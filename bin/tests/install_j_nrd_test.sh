#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALLER="${REPO_ROOT}/bin/install_j.sh"
TEST_ROOT="$(mktemp -d)"
TEST_COUNT=0

# Remove only the disposable directory created by this test run.
cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

# Stop the suite immediately; some bash builds ignore errexit inside
# subshells, so assertion failures must exit explicitly.
fail() {
  echo "not ok: $*" >&2
  exit 1
}

# Require two scalar values to be identical.
assert_eq() {
  local expected="$1" actual="$2" message="$3"
  [[ "$actual" == "$expected" ]] || fail "${message}: expected '${expected}', got '${actual}'"
}

# Require a directory to exist.
assert_dir() {
  [[ -d "$1" ]] || fail "$2: expected directory '$1'"
}

# Require an exact count of lines containing a fixed string in a file.
assert_count() {
  local expected="$1" needle="$2" file="$3" actual
  actual="$(grep -cF -- "$needle" "$file" || true)"
  assert_eq "$expected" "$actual" "$4"
}

# Run one test; any assertion failure exits the suite from fail().
run_test() {
  local name="$1" test_function="$2"
  printf 'test: %s ... ' "$name"
  "$test_function"
  TEST_COUNT=$((TEST_COUNT + 1))
  echo 'ok'
}

# Load only the installer functions exercised by this suite.
load_installer_functions() {
  # shellcheck source=/dev/null
  source <(sed -n '/^remove_profile_section()/,/^}/p' "$INSTALLER")
}

# Source the managed nrd section exactly as the installer writes it.
load_embedded_nrd() {
  # shellcheck source=/dev/null
  source <(awk '
    $0 == "# >>> nrd >>>" { emit = 1; next }
    $0 == "# <<< nrd <<<" { emit = 0 }
    emit
  ' "$INSTALLER")
}

# Write the managed nrd section to a file for other shells (zsh) to source.
write_embedded_nrd() {
  awk '
    $0 == "# >>> nrd >>>" { emit = 1; next }
    $0 == "# <<< nrd <<<" { emit = 0 }
    emit
  ' "$INSTALLER" > "$TEST_ROOT/nrd_block.sh"
}

# Print the single child directory of $1, failing when none or several exist.
sole_child_dir() {
  local base="$1" found="" entry
  for entry in "$base"/*; do
    [[ -d "$entry" ]] || continue
    [[ -z "$found" ]] || fail "$base: multiple child directories created"
    found="$entry"
  done
  [[ -n "$found" ]] || fail "$base: no child directory was created"
  printf '%s' "$found"
}

test_empty_directory_scan_succeeds() {
  local base="$TEST_ROOT/empty"
  mkdir -p "$base"
  load_embedded_nrd
  (cd "$base" && nrd >/dev/null) || fail 'nrd failed'
  sole_child_dir "$base" >/dev/null
}

test_directory_with_only_files_succeeds() {
  local base="$TEST_ROOT/files-only"
  mkdir -p "$base"
  : > "$base/ordinary.txt"
  load_embedded_nrd
  (cd "$base" && nrd >/dev/null) || fail 'nrd failed'
  sole_child_dir "$base" >/dev/null
}

test_existing_color_children_still_scanned() {
  local base="$TEST_ROOT/prefixed" entry new=""
  mkdir -p "$base/red-one-two"
  load_embedded_nrd
  (cd "$base" && nrd >/dev/null) || fail 'nrd failed'
  for entry in "$base"/*; do
    [[ -d "$entry" ]] || continue
    [[ "$(basename "$entry")" == red-one-two ]] && continue
    [[ -z "$new" ]] || fail 'multiple new child directories created'
    new="$entry"
  done
  [[ -n "$new" ]] || fail 'no new child directory was created'
  # The scan must avoid the used 'red' prefix while the pool allows it.
  [[ "$(basename "$new")" != red-* ]] || fail 'picked the already-used color'
}

test_explicit_name_is_unchanged() {
  local base="$TEST_ROOT/explicit"
  mkdir -p "$base"
  load_embedded_nrd
  (cd "$base" && nrd -n given-name >/dev/null)
  assert_dir "$base/given-name" 'explicit name'
}

test_parent_path_with_spaces_succeeds() {
  local base="$TEST_ROOT/with space"
  mkdir -p "$base"
  load_embedded_nrd
  (cd "$base" && nrd >/dev/null) || fail 'nrd failed'
  sole_child_dir "$base" >/dev/null
}

test_caller_options_unchanged_after_run() {
  local base="$TEST_ROOT/options" before after
  mkdir -p "$base"
  load_embedded_nrd
  before="$-"
  (cd "$base" && nrd >/dev/null) || fail 'nrd failed'
  after="$-"
  assert_eq "$before" "$after" 'caller option state'
}

test_old_version_marker_upgrades_once_and_idempotent() {
  local profile="$TEST_ROOT/zshrc" installer_logic
  printf '%s\n' \
    'before' \
    '# >>> nrd >>>' \
    '# nrd version 2' \
    'nrd() { echo old; }' \
    '# <<< nrd <<<' \
    'after' > "$profile"
  # Referenced by the extracted installer sections evaluated below.
  # shellcheck disable=SC2034
  PROFILE="$profile"
  # shellcheck disable=SC2034
  FORCE_REINSTALL=false
  load_installer_functions
  # Marker guard: drops a managed block that lacks the current version marker.
  installer_logic="$(awk '
    $0 == "MARKER=\"# >>> nrd >>>\"" { emit = 1 }
    emit && $0 == "fi" { print; exit }
    emit
  ' "$INSTALLER")"
  eval "$installer_logic" > /dev/null || fail 'installer logic failed'
  assert_count 0 '# >>> nrd >>>' "$profile" 'old managed block was not removed'
  # Re-emit block: writes the current managed section after the guard.
  installer_logic="$(awk '
    $0 == "if grep -qF \"$MARKER\" \"$PROFILE\" 2>/dev/null; then" { emit = 1 }
    emit && $0 == "fi" { print; exit }
    emit
  ' "$INSTALLER")"
  eval "$installer_logic" > /dev/null || fail 'installer logic failed'
  assert_count 1 '# >>> nrd >>>' "$profile" 're-emitted managed block count'
  grep -Fqx '# nrd version 3' "$profile" || fail 'version 3 marker missing after upgrade'
  ! grep -Fq '# nrd version 2' "$profile" || fail 'version 2 content remained'
  grep -Fqx before "$profile" || fail 'content before the managed block was lost'
  grep -Fqx after "$profile" || fail 'content after the managed block was lost'
  # A rerun must be idempotent: no duplicate managed sections.
  eval "$installer_logic" > /dev/null || fail 'installer logic failed'
  assert_count 1 '# >>> nrd >>>' "$profile" 'rerun duplicated the managed block'
  bash -n "$profile" || fail 'generated profile has bash syntax errors'
}

test_generated_name_has_nonempty_components() {
  local base="$TEST_ROOT/components" child name
  mkdir -p "$base"
  load_embedded_nrd
  (cd "$base" && nrd >/dev/null) || fail 'nrd failed'
  child="$(sole_child_dir "$base")"
  name="$(basename "$child")"
  # color-adjective-noun: every component nonempty in both target shells.
  [[ "$name" =~ ^[a-z]+-[a-z]+-[a-z]+$ ]] || fail "generated name '$name' has an empty component"
}

# Print the nrd color palette parsed from the extracted embedded block.
nrd_palette() {
  awk '/^  local colors=\($/{ emit = 1; next } emit && /^  \)$/{ exit } emit { print }' \
    "$TEST_ROOT/nrd_block.sh" | tr ' ' '\n' | sed '/^$/d'
}

test_exhausted_palette_warns_and_uses_that_color() {
  # Seed one child directory per palette color so every draw collides; the
  # retry loop must warn with its final color and the created directory must
  # actually lead with it (a name draw re-picking a color would disagree).
  local base="$TEST_ROOT/exhausted" color warned name new="" entry
  mkdir -p "$base"
  write_embedded_nrd
  for color in $(nrd_palette); do mkdir -p "$base/$color-seed-x"; done
  local stderr_file="$TEST_ROOT/nrd-stderr.txt"
  (cd "$base" && nrd >/dev/null 2>"$stderr_file") || fail 'nrd failed'
  warned="$(sed -n "s/.*using '\\([a-z]*\\)' anyway.*/\\1/p" "$stderr_file")"
  [[ -n "$warned" ]] || fail 'expected a palette-exhaustion warning'
  for entry in "$base"/*; do
    [[ -d "$entry" ]] || continue
    case "$(basename "$entry")" in *-seed-x) continue ;; esac
    [[ -z "$new" ]] || fail 'multiple new child directories created'
    new="$(basename "$entry")"
  done
  [[ -n "$new" ]] || fail 'no new child directory was created'
  [[ "$new" == "$warned-"* ]] || fail "created '$new' does not lead with the warned color '$warned'"
}

test_two_sequential_calls_pick_different_names() {
  # Both calls must run in ONE shell: a draw made inside a command
  # substitution replays the inherited frozen seed across calls (probe:
  # three substitutions yield one value), which is what an interactive
  # session sees. The indices are therefore computed in the function's own
  # scope, and this test fails if any draw migrates back into a substitution.
  local base="$TEST_ROOT/sequential" results first second
  mkdir -p "$base"
  load_embedded_nrd
  results="$(cd "$base" && { nrd && nrd; })" || fail 'sequential nrd failed'
  first="$(printf '%s\n' "$results" | sed -n '1s|.*/||p')"
  second="$(printf '%s\n' "$results" | sed -n '2s|.*/||p')"
  assert_dir "$base/$first" 'first directory'
  # nrd cd's into the new directory, so the second call nests inside the first.
  assert_dir "$base/$first/$second" 'second directory'
  [[ -n "$second" ]] || fail 'second nrd produced no directory'
  [[ "$first" != "$second" ]] || fail "sequential calls replayed the draw '$first'"
}

run_test 'bash: empty directory scan succeeds' test_empty_directory_scan_succeeds
run_test 'bash: directory with only files succeeds' test_directory_with_only_files_succeeds
run_test 'bash: existing color-prefixed children scanned' test_existing_color_children_still_scanned
run_test 'bash: explicit name unchanged' test_explicit_name_is_unchanged
run_test 'bash: parent path with spaces succeeds' test_parent_path_with_spaces_succeeds
run_test 'bash: caller options unchanged' test_caller_options_unchanged_after_run
run_test 'bash: generated name has nonempty components' test_generated_name_has_nonempty_components
run_test 'bash: exhausted palette warns and uses that color' test_exhausted_palette_warns_and_uses_that_color
run_test 'bash: two sequential calls pick different names' test_two_sequential_calls_pick_different_names
run_test 'installer: version 2 block upgrades once, rerun idempotent' test_old_version_marker_upgrades_once_and_idempotent

if command -v zsh >/dev/null 2>&1; then
  test_zsh_empty_directory_scan_succeeds() {
    local base="$TEST_ROOT/zsh-empty"
    mkdir -p "$base"
    write_embedded_nrd
    zsh -f -e -c "source '$TEST_ROOT/nrd_block.sh'; cd '$base'; nrd >/dev/null" || fail 'zsh nrd failed'
    sole_child_dir "$base" >/dev/null
  }

  test_zsh_caller_options_restored() {
    local base="$TEST_ROOT/zsh-options"
    mkdir -p "$base"
    write_embedded_nrd
    # nomatch must be on again after nrd returns; LOCAL_OPTIONS guarantees it.
    zsh -f -e -c "
      setopt nomatch
      source '$TEST_ROOT/nrd_block.sh'
      cd '$base'
      nrd >/dev/null
      [[ -o nomatch ]] || exit 70
    " || fail 'caller nomatch state not restored after nrd'
  }

  test_zsh_explicit_name_is_unchanged() {
    local base="$TEST_ROOT/zsh-explicit"
    mkdir -p "$base"
    write_embedded_nrd
    zsh -f -e -c "source '$TEST_ROOT/nrd_block.sh'; cd '$base'; nrd -n zsh-given >/dev/null" || fail 'zsh nrd failed'
    assert_dir "$base/zsh-given" 'zsh explicit name'
  }

  test_zsh_generated_name_has_nonempty_components() {
    local base="$TEST_ROOT/zsh-components" child name
    mkdir -p "$base"
    write_embedded_nrd
    # 1-based zsh subscripts must not empty the random name components.
    zsh -f -e -c "source '$TEST_ROOT/nrd_block.sh'; cd '$base'; nrd >/dev/null" || fail 'zsh nrd failed'
    child="$(sole_child_dir "$base")"
    name="$(basename "$child")"
    [[ "$name" =~ ^[a-z]+-[a-z]+-[a-z]+$ ]] || fail "generated name '$name' has an empty component"
  }

  test_zsh_sequential_calls_pick_different_names() {
    # The actual defect shape: draws inside command substitutions advance
    # only a copy of zsh's random state, so the parent replays the seeded
    # sequence on the next call and the same name collides until retries
    # exhaust. A fixed RANDOM seed makes that replay deterministic: pre-fix
    # both calls produce one identical name; post-fix the in-function draws
    # advance the state and the names differ. Both calls run in one zsh and
    # nrd's cd nests the second directory under the first.
    local base="$TEST_ROOT/zsh-sequential" results first second
    mkdir -p "$base"
    write_embedded_nrd
    results="$(
      zsh -f -e -c "
        cd '$base' || exit 70
        RANDOM=42
        source '$TEST_ROOT/nrd_block.sh'
        nrd && nrd
      "
    )" || fail 'zsh sequential nrd failed'
    first="$(printf '%s\n' "$results" | sed -n '1s|.*/||p')"
    second="$(printf '%s\n' "$results" | sed -n '2s|.*/||p')"
    assert_dir "$base/$first" 'zsh first directory'
    assert_dir "$base/$first/$second" 'zsh second directory'
    [[ -n "$second" ]] || fail 'second zsh nrd produced no directory'
    [[ "$first" != "$second" ]] || fail "zsh sequential calls replayed the draw '$first'"
  }

  run_test 'zsh: empty directory scan succeeds' test_zsh_empty_directory_scan_succeeds
  run_test 'zsh: caller option state restored' test_zsh_caller_options_restored
  run_test 'zsh: explicit name unchanged' test_zsh_explicit_name_is_unchanged
  run_test 'zsh: generated name has nonempty components' test_zsh_generated_name_has_nonempty_components
  run_test 'zsh: sequential calls pick different names' test_zsh_sequential_calls_pick_different_names
else
  echo 'skip: zsh is unavailable; nrd zsh cases were not run' >&2
fi

printf 'passed: %d tests\n' "$TEST_COUNT"
