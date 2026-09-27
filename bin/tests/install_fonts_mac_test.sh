#!/usr/bin/env bash
#
# install_fonts_mac_test.sh
# Test suite for thejjw/bin/install_fonts_mac.sh
#
# 2026 @thejjw
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALLER="${REPO_ROOT}/bin/install_fonts_mac.sh"
CATALOG="${REPO_ROOT}/bin/font_catalog.sh"
TEST_ROOT="$(mktemp -d -t install_fonts_mac_test.XXXXXX)"
TEST_COUNT=0

# Clean up test suite root directory upon exit
cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

# Stop the suite with an assertion failure message
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

# Require two values to be identical
assert_eq() {
  local expected="$1"
  local actual="$2"
  local message="${3:-values not equal}"
  if [[ "$expected" != "$actual" ]]; then
    fail "${message}: expected '${expected}', got '${actual}'"
  fi
}

# Assert that a pattern matches within a given file
assert_contains() {
  local pattern="$1"
  local file="$2"
  local message="${3:-file does not contain pattern}"
  if ! grep -Fq -- "$pattern" "$file"; then
    fail "${message}: pattern '${pattern}' not found in '${file}'"
  fi
}

# Assert that a pattern does NOT match within a given file
assert_not_contains() {
  local pattern="$1"
  local file="$2"
  local message="${3:-file contains forbidden pattern}"
  if grep -Fq -- "$pattern" "$file"; then
    fail "${message}: forbidden pattern '${pattern}' found in '${file}'"
  fi
}

# Run one isolated test case
run_test() {
  local desc="$1"
  local fn="$2"
  printf 'running: %s... ' "$desc"
  "$fn"
  TEST_COUNT=$((TEST_COUNT + 1))
  printf 'OK\n'
}

# Create a clean isolated workspace for each test case
new_case() {
  local case_dir="${TEST_ROOT}/case_${TEST_COUNT}"
  rm -rf "$case_dir"
  mkdir -p "$case_dir/bin" "$case_dir/fonts" "$case_dir/work"
  printf '%s\n' "$case_dir"
}

# Helper to create a zip file using python3
create_mock_zip() {
  local zip_path="$1"
  shift
  python3 -c "
import sys, zipfile
zip_path = sys.argv[1]
entries = sys.argv[2:]
with zipfile.ZipFile(zip_path, 'w') as z:
    for e in entries:
        parts = e.split('=', 1)
        name = parts[0]
        content = parts[1] if len(parts) > 1 else 'mock_content'
        z.writestr(name, content)
" "$zip_path" "$@"
}

# Test 1: Full 33-pack catalog integrity and schema validation via shell contract
test_catalog_integrity() {
  local case_dir
  case_dir="$(new_case)"
  local err="${case_dir}/err.txt"

  bash -c '
    set -eu
    PACK_COUNT=0
    declare -a NAMES=()
    declare -a PROBES=()

    add_pack() {
      if [ "$#" -ne 9 ]; then
        echo "ERROR: add_pack called with $# arguments (expected 9) for pack \"${1:-}\"" >&2
        exit 1
      fi
      local name="$1" url="$2" bytes="$3" fonts="$4" kind="$5" include="$6" probe="$7" ext="$8" note="$9"
      PACK_COUNT=$((PACK_COUNT + 1))
      NAMES+=("$name")
      PROBES+=("$probe")

      if [ -z "$name" ]; then echo "Empty name" >&2; exit 1; fi
      if ! [[ "$url" =~ ^https:// ]]; then echo "URL must start with https://: $url" >&2; exit 1; fi
      if ! [[ "$bytes" =~ ^[0-9]+$ ]] || [ "$bytes" -le 0 ]; then echo "Invalid bytes: $bytes" >&2; exit 1; fi
      if ! [[ "$fonts" =~ ^[0-9]+$ ]] || [ "$fonts" -le 0 ]; then echo "Invalid fonts: $fonts" >&2; exit 1; fi
      if ! [[ "$kind" =~ ^(Zip|7z|File)$ ]]; then echo "Invalid kind: $kind" >&2; exit 1; fi
      if ! [[ "$ext" =~ ^(0|1)$ ]]; then echo "Invalid extended: $ext" >&2; exit 1; fi
      if [ -z "$probe" ]; then echo "Empty probe" >&2; exit 1; fi
      if [ -z "$note" ]; then echo "Empty note" >&2; exit 1; fi

      if [ "$kind" = "File" ]; then
        if [ -n "$include" ]; then echo "File kind must have empty include" >&2; exit 1; fi
      else
        if [ -z "$include" ]; then echo "Archive kind must have non-empty include" >&2; exit 1; fi
      fi
    }

    # shellcheck source=font_catalog.sh
    source "$1"
    load_font_catalog

    if [ "$PACK_COUNT" -ne 33 ]; then
      echo "Expected 33 packs, got $PACK_COUNT" >&2
      exit 1
    fi

    unique_names=$(printf "%s\n" "${NAMES[@]}" | sort -u | wc -l | tr -d " ")
    if [ "$unique_names" -ne 33 ]; then
      echo "Duplicate pack names detected" >&2
      exit 1
    fi

    unique_probes=$(printf "%s\n" "${PROBES[@]}" | sort -u | wc -l | tr -d " ")
    if [ "$unique_probes" -ne 33 ]; then
      echo "Duplicate probe filenames detected" >&2
      exit 1
    fi
  ' bash "$CATALOG" > /dev/null 2> "$err" || fail "Catalog integrity failed: $(cat "$err")"
}

# Test 2: Verify all 33 catalog regex patterns are valid in BSD grep -Ei once (?i) is stripped
test_regex_normalization_bsd_grep() {
  local case_dir
  case_dir="$(new_case)"
  local err="${case_dir}/err.txt"

  bash -c '
    set -eu
    add_pack() {
      local name="$1" kind="$5" include="$6"
      [ "$kind" = "File" ] && return 0
      local norm="${include#(\?i)}"
      if ! echo "dummy_line" | grep -Ei "$norm" >/dev/null 2>&1; then
        local st=$?
        if [ "$st" -ge 2 ]; then
          echo "Regex syntax error on normalized pattern for $name: $include -> $norm" >&2
          exit 1
        fi
      fi
    }
    # shellcheck source=font_catalog.sh
    source "$1"
    load_font_catalog
  ' bash "$CATALOG" > /dev/null 2> "$err" || fail "Regex normalization failed: $(cat "$err")"
}

# Test 3: --list runs cleanly without extractors or 7z tool on PATH
test_list_without_7z() {
  local case_dir
  case_dir="$(new_case)"
  local out="${case_dir}/out.txt"

  # Run under sanitized PATH containing only standard system binaries (no 7z)
  env -i PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" --list > "$out"

  assert_contains '30 pack(s)' "$out" 'Standard list count'
  assert_contains 'IntelOneMono' "$out"
  assert_contains 'SarasaGothicK' "$out"
  assert_contains 'SarasaMonoK' "$out"
  assert_not_contains 'SourceHanSans' "$out" 'Extended packs excluded by default'
}

# Test 4: --list --extended displays all 33 packs
test_list_extended() {
  local case_dir
  case_dir="$(new_case)"
  local out="${case_dir}/out.txt"

  env -i PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" --list --extended > "$out"

  assert_contains '33 pack(s)' "$out" 'Extended list count'
  assert_contains 'SourceHanSans' "$out"
  assert_contains 'SourceHanSerif' "$out"
  assert_contains 'SourceHanMono' "$out"
}

# Test 5: Preflight hard failure when 7z is missing and 7z pack is selected
test_preflight_fails_without_7z() {
  local case_dir
  case_dir="$(new_case)"
  local out="${case_dir}/out.txt"
  local err="${case_dir}/err.txt"

  # Run under sanitized PATH lacking 7z/7za
  set +e
  env -i PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name SarasaMonoK > "$out" 2> "$err"
  local status="$?"
  set -e

  assert_eq 1 "$status" 'Preflight exit status without 7z'
  assert_contains 'brew install sevenzip' "$err" 'Actionable Homebrew message'
  assert_eq 0 "$(ls -A "${case_dir}/fonts" | wc -l | tr -d ' ')" 'Target directory untouched'
}

# Test 5b: 7zz binary (from brew install sevenzip) is accepted by preflight and extracts correctly
test_7zz_preflight_and_extraction() {
  local case_dir
  case_dir="$(new_case)"

  # Mock 7zz script that responds to '7zz l -ba -slt ...' and '7zz e -y -o... ...'
  cat <<'EOF' > "${case_dir}/bin/7zz"
#!/usr/bin/env bash
if [ "$1" = "l" ]; then
  cat <<'LIST_EOF'
Path = SarasaMonoK-Regular.ttf
Size = 12345

Path = SarasaMonoK-Bold.ttf
Size = 12345

Path = __MACOSX/._SarasaMonoK-Regular.ttf
Size = 100
LIST_EOF
  exit 0
elif [ "$1" = "e" ]; then
  outdir=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -o*)
        outdir="${1#-o}"
        shift
        ;;
      *)
        shift
        ;;
    esac
  done
  echo "sarasa_regular_data" > "$outdir/SarasaMonoK-Regular.ttf"
  echo "sarasa_bold_data" > "$outdir/SarasaMonoK-Bold.ttf"
  exit 0
fi
EOF
  chmod +x "${case_dir}/bin/7zz"

  # Mock curl to output a dummy archive
  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
echo "dummy_7z_payload" > "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  local out="${case_dir}/out.txt"
  local err="${case_dir}/err.txt"

  set +e
  PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name SarasaMonoK > "$out" 2> "$err"
  local status="$?"
  set -e

  assert_eq 0 "$status" '7zz should allow preflight and install to succeed'
  assert_eq 0 "$(cat "$err" | wc -l | tr -d ' ')" 'No stderr errors when 7zz is present'
  [ -f "${case_dir}/fonts/SarasaMonoK-Regular.ttf" ] || fail 'SarasaMonoK-Regular.ttf installed via 7zz'
  [ -f "${case_dir}/fonts/SarasaMonoK-Bold.ttf" ] || fail 'SarasaMonoK-Bold.ttf installed via 7zz'
  assert_eq "sarasa_regular_data" "$(cat "${case_dir}/fonts/SarasaMonoK-Regular.ttf")"
}

# Test 5c: Unwritable target directory fails immediately before any download
test_unwritable_target_directory_fails_early() {
  local case_dir
  case_dir="$(new_case)"
  local unwritable_dir="${case_dir}/ro_fonts"
  mkdir -p "$unwritable_dir"
  chmod 555 "$unwritable_dir"

  local err="${case_dir}/err.txt"
  set +e
  INSTALL_FONTS_TARGET_DIR="$unwritable_dir" \
    "$INSTALLER" -y --name Jetendard > /dev/null 2> "$err"
  local status="$?"
  set -e

  chmod 755 "$unwritable_dir"
  assert_eq 1 "$status" 'Unwritable target should exit 1'
  assert_contains 'Target directory is not writable' "$err"
}

# Test 6: Selective extraction, flattening, and AppleDouble rejection
test_selective_zip_extraction_and_appledouble_rejection() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/Jetendard-TTF.zip"

  # Create mock zip bundling valid ttf, web fonts, and AppleDouble metadata
  create_mock_zip "$mock_zip" \
    "ttf/Jetendard-Regular.ttf=regular_font_data" \
    "ttf/Jetendard-Bold.ttf=bold_font_data" \
    "web/Jetendard.woff2=web_font" \
    "__MACOSX/._Jetendard-Regular.ttf=mac_resource_fork" \
    "ttf/._Jetendard-Bold.ttf=mac_resource_fork2"

  # Mock curl to return our mock zip
  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    out="$2"
    shift 2
  else
    shift
  fi
done
cp "$MOCK_ZIP" "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  local out="${case_dir}/out.txt"
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > "$out"

  # Assert only the 2 valid font files were installed
  [ -f "${case_dir}/fonts/Jetendard-Regular.ttf" ] || fail 'Jetendard-Regular.ttf was not installed'
  [ -f "${case_dir}/fonts/Jetendard-Bold.ttf" ] || fail 'Jetendard-Bold.ttf was not installed'
  [ ! -f "${case_dir}/fonts/Jetendard.woff2" ] || fail 'woff2 should not be installed'
  [ ! -f "${case_dir}/fonts/._Jetendard-Regular.ttf" ] || fail 'AppleDouble ._* should be rejected'
  [ ! -d "${case_dir}/fonts/__MACOSX" ] || fail '__MACOSX folder should be rejected'
  assert_eq "regular_font_data" "$(cat "${case_dir}/fonts/Jetendard-Regular.ttf")" 'Probe content match'
}

# Test 7: Pre-commit hard validation gate fails immediately on zero matches
test_precommit_hard_validation_zero_matches() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/Jetendard-TTF.zip"

  # Create zip where directory changed to 'static/' so 'ttf/' regex matches 0 entries
  create_mock_zip "$mock_zip" \
    "static/Jetendard-Regular.ttf=font_data"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$MOCK_ZIP" "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  local out="${case_dir}/out.txt"
  local err="${case_dir}/err.txt"

  set +e
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > "$out" 2> "$err"
  local status="$?"
  set -e

  assert_eq 1 "$status" 'Zero match should exit 1'
  assert_contains 'No matching font entries found in archive' "$err" 'Hard validation message'
  assert_not_contains 'retry 1/' "$out" 'Deterministic layout drift should not retry'
  assert_eq 0 "$(ls -A "${case_dir}/fonts" | wc -l | tr -d ' ')" 'Target directory untouched'
}

# Test 8: Pre-commit hard validation gate fails immediately on missing probe
test_precommit_hard_validation_missing_probe() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/Jetendard-TTF.zip"

  # Create zip matching ttf/ regex, but probe Jetendard-Regular.ttf is missing
  create_mock_zip "$mock_zip" \
    "ttf/Jetendard-Bold.ttf=bold_font_data"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$MOCK_ZIP" "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  local err="${case_dir}/err.txt"
  set +e
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > /dev/null 2> "$err"
  local status="$?"
  set -e

  assert_eq 1 "$status" 'Missing probe should exit 1'
  assert_contains 'Staged probe file' "$err" 'Probe validation error'
  assert_eq 0 "$(ls -A "${case_dir}/fonts" | wc -l | tr -d ' ')" 'Target directory untouched'
}

# Test 9: --force with failing validation gate does NOT delete pre-existing probe
test_force_with_validation_failure_preserves_probe() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/Jetendard-TTF.zip"

  # Pre-create probe in target directory
  echo "preexisting_probe" > "${case_dir}/fonts/Jetendard-Regular.ttf"

  # Create zip with zero matches
  create_mock_zip "$mock_zip" "other/font.ttf=data"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$MOCK_ZIP" "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  set +e
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --force --name Jetendard > /dev/null 2>&1
  local status="$?"
  set -e

  assert_eq 1 "$status" 'Validation failure exits 1'
  [ -f "${case_dir}/fonts/Jetendard-Regular.ttf" ] || fail 'Existing probe should NOT be deleted on validation failure'
  assert_eq "preexisting_probe" "$(cat "${case_dir}/fonts/Jetendard-Regular.ttf")" 'Probe content preserved'
}

# Test 10: Soft warning on font count mismatch allows successful commit
test_soft_warning_count_difference() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/Jetendard-TTF.zip"

  # Jetendard catalog estimates 16 fonts; provide only 2 (with valid probe)
  create_mock_zip "$mock_zip" \
    "ttf/Jetendard-Regular.ttf=regular_data" \
    "ttf/Jetendard-Bold.ttf=bold_data"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$MOCK_ZIP" "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  local out="${case_dir}/out.txt"
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > "$out"

  assert_contains 'notice: extracted 2 file(s), catalog estimated ~16' "$out" 'Soft warning emitted'
  assert_contains 'installed 2 font file(s)' "$out" 'Successfully committed'
  [ -f "${case_dir}/fonts/Jetendard-Regular.ttf" ] || fail 'Probe installed'
  [ -f "${case_dir}/fonts/Jetendard-Bold.ttf" ] || fail 'Bold installed'
}

# Test 11: Transient download retry purges corrupt archive before next attempt
test_transient_retry_and_archive_purge() {
  local case_dir
  case_dir="$(new_case)"
  local valid_zip="${case_dir}/work/valid.zip"
  create_mock_zip "$valid_zip" "ttf/Jetendard-Regular.ttf=valid_data"

  # State counter for mock curl
  echo "0" > "${case_dir}/work/curl_attempts"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
attempt_file="$STATE_DIR/curl_attempts"
count=$(cat "$attempt_file")
count=$((count + 1))
echo "$count" > "$attempt_file"

while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done

if [ "$count" -eq 1 ]; then
  # Attempt 1: write corrupt truncated zip
  printf 'PK\x03\x04corrupted_payload' > "$out"
else
  # Attempt 2: write valid zip
  cp "$VALID_ZIP" "$out"
fi
EOF
  chmod +x "${case_dir}/bin/curl"

  local out="${case_dir}/out.txt"
  STATE_DIR="${case_dir}/work" \
    VALID_ZIP="$valid_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > "$out"

  assert_contains 'retry 1/2' "$out" 'Retry triggered on archive corruption'
  assert_contains 'installed 1 font file(s)' "$out" 'Success on attempt 2'
  [ -f "${case_dir}/fonts/Jetendard-Regular.ttf" ] || fail 'Probe installed after retry'
}

# Test 12: Process-isolated temporary file tracking and safe cleanup
test_process_isolated_temp_cleanup() {
  local case_dir
  case_dir="$(new_case)"

  # Pre-create an unrelated concurrent temporary file in target directory
  local foreign_temp="${case_dir}/fonts/.foreign_font.tmp.123456"
  echo "concurrent_installer_temp" > "$foreign_temp"

  local mock_zip="${case_dir}/work/mock.zip"
  create_mock_zip "$mock_zip" "ttf/Jetendard-Regular.ttf=regular_data"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$MOCK_ZIP" "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > /dev/null

  # Assert the foreign temp file was NOT deleted by install_fonts_mac cleanup
  [ -f "$foreign_temp" ] || fail 'Cleanup deleted unrelated temp file from concurrent installer'
  assert_eq "concurrent_installer_temp" "$(cat "$foreign_temp")" 'Foreign temp intact'
}

# Test 13: Probe idempotency skips download vs --force re-downloads
test_probe_idempotency_and_force() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/mock.zip"
  create_mock_zip "$mock_zip" "ttf/Jetendard-Regular.ttf=new_data"

  echo "0" > "${case_dir}/work/curl_called"
  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
echo "1" > "$STATE_DIR/curl_called"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$MOCK_ZIP" "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  # Pre-populate target with probe
  echo "old_data" > "${case_dir}/fonts/Jetendard-Regular.ttf"

  # Run without --force: should skip download
  local out="${case_dir}/out.txt"
  local err="${case_dir}/err.txt"
  set +e
  STATE_DIR="${case_dir}/work" \
    MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > "$out" 2> "$err"
  local skip_status="$?"
  set -e

  assert_eq 0 "$skip_status" 'Idempotent skip should exit 0'
  assert_eq 0 "$(cat "$err" | wc -l | tr -d ' ')" 'Idempotent skip should produce zero stderr output'
  assert_contains 'already installed (Jetendard-Regular.ttf); skipping download' "$out"
  assert_eq "0" "$(cat "${case_dir}/work/curl_called")" 'curl should not be called'
  assert_eq "old_data" "$(cat "${case_dir}/fonts/Jetendard-Regular.ttf")" 'Probe content unchanged'

  # Run with --force: should download and overwrite
  set +e
  STATE_DIR="${case_dir}/work" \
    MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --force --name Jetendard > "$out" 2> "$err"
  local force_status="$?"
  set -e

  assert_eq 0 "$force_status" 'Force install should exit 0'
  assert_eq 0 "$(cat "$err" | wc -l | tr -d ' ')" 'Force install should produce zero stderr output'
  assert_contains 'installed 1 font file(s)' "$out" 'Forced install succeeded'
  assert_eq "1" "$(cat "${case_dir}/work/curl_called")" 'curl was called on force'
  assert_eq "new_data" "$(cat "${case_dir}/fonts/Jetendard-Regular.ttf")" 'Probe content overwritten'
}

# Test 14: Confirmation prompt aborts with exit code 130 on 'n'
test_confirmation_prompt_abort() {
  local case_dir
  case_dir="$(new_case)"

  set +e
  printf 'n\n' | env -i PATH="/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" --name Jetendard > "${case_dir}/out.txt"
  local status="$?"
  set -e

  assert_eq 130 "$status" 'Aborting prompt should exit 130'
  assert_contains 'Aborting. Nothing was downloaded or installed.' "${case_dir}/out.txt"
  assert_eq 0 "$(ls -A "${case_dir}/fonts" | wc -l | tr -d ' ')" 'Target directory untouched'
}

# Test 15: Best-effort loop continues across pack failure and exits 1 with summary
test_best_effort_loop_and_failure_summary() {
  local case_dir
  case_dir="$(new_case)"
  local jet_zip="${case_dir}/work/jet.zip"
  create_mock_zip "$jet_zip" "ttf/Jetendard-Regular.ttf=jet_data"

  # Mock curl fails on IntelOneMono, succeeds on Jetendard
  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
url=""
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else url="$1"; shift; fi
done
if [[ "$url" =~ intel-one-mono ]]; then
  exit 22 # HTTP 404
else
  cp "$JET_ZIP" "$out"
fi
EOF
  chmod +x "${case_dir}/bin/curl"

  local out="${case_dir}/out.txt"
  set +e
  JET_ZIP="$jet_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name 'IntelOneMono,Jetendard' --retries 0 > "$out" 2>&1
  local status="$?"
  set -e

  assert_eq 1 "$status" 'Failure of one pack causes overall exit 1'
  assert_contains 'installed 1 font file(s)' "$out" 'Jetendard still installed'
  [ -f "${case_dir}/fonts/Jetendard-Regular.ttf" ] || fail 'Jetendard should be installed'
  assert_contains 'Failed packs:' "$out" 'Failure summary printed'
  assert_contains 'IntelOneMono' "$out" 'IntelOneMono in failed summary'
}

# Test 16: Interrupted pack recovery (missing probe retried on next run)
test_interrupted_pack_recovery() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/mock.zip"
  create_mock_zip "$mock_zip" \
    "ttf/Jetendard-Regular.ttf=recovered_data" \
    "ttf/Jetendard-Bold.ttf=recovered_bold"

  # Simulate partial previous install: non-probe file present, probe absent
  echo "partial_bold" > "${case_dir}/fonts/Jetendard-Bold.ttf"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$MOCK_ZIP" "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  local out="${case_dir}/out.txt"
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > "$out"

  assert_contains 'installed 2 font file(s)' "$out" 'Incomplete pack was re-downloaded and completed'
  [ -f "${case_dir}/fonts/Jetendard-Regular.ttf" ] || fail 'Probe installed after recovery'
  assert_eq "recovered_data" "$(cat "${case_dir}/fonts/Jetendard-Regular.ttf")"
  assert_eq "recovered_bold" "$(cat "${case_dir}/fonts/Jetendard-Bold.ttf")"
}

# Test 17: Commit failure regression (atomic commit failure halts pack, probe absent, exits 1)
test_commit_failure_regression() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/mock.zip"
  create_mock_zip "$mock_zip" \
    "ttf/Jetendard-Regular.ttf=regular_data" \
    "ttf/Jetendard-Bold.ttf=bold_data"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$MOCK_ZIP" "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  # Mock mv to simulate a filesystem commit failure when targeting destination
  cat <<'EOF' > "${case_dir}/bin/mv"
#!/usr/bin/env bash
for arg in "$@"; do
  if [[ "$arg" == *"/fonts/"* ]]; then
    echo "simulated mv failure: disk write error" >&2
    exit 1
  fi
done
exec /bin/mv "$@"
EOF
  chmod +x "${case_dir}/bin/mv"

  local out="${case_dir}/out.txt"
  local err="${case_dir}/err.txt"

  set +e
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > "$out" 2> "$err"
  local status="$?"
  set -e

  assert_eq 1 "$status" 'Commit failure should exit 1'
  assert_contains 'Atomic commit failed during installation' "$err" 'Commit error logged'
  assert_contains 'Failed packs:' "$out" 'Failure summary printed'
  assert_contains 'Jetendard' "$out" 'Jetendard listed in failed packs'
  [ ! -f "${case_dir}/fonts/Jetendard-Regular.ttf" ] || fail 'Probe MUST be absent when commit fails'
  assert_contains '0 installed' "$out" 'Installed count must remain 0 on commit failure'
}

# Test 18: Comma-separated name filter and literal substring metacharacter handling
test_comma_separated_and_literal_name_filter() {
  local case_dir
  case_dir="$(new_case)"
  local out="${case_dir}/out.txt"

  # Comma-separated matching
  "$INSTALLER" --list --name "Pretendard, FiraCode" > "$out"
  assert_contains '2 pack(s)' "$out" 'Matches both Pretendard and FiraCode'
  assert_contains 'Pretendard' "$out"
  assert_contains 'FiraCode' "$out"
  assert_not_contains 'IntelOneMono' "$out"

  # Literal metacharacter handling (must not fail regex syntax error)
  "$INSTALLER" --list --name "Pretendard[" > "$out"
  assert_contains 'No matching font packs to install.' "$out"
}

# Test 19: Bracketed filenames in Zip entries extract properly
test_bracketed_filename_extraction() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/mock.zip"

  create_mock_zip "$mock_zip" \
    "fonts/variable/JetBrainsMono[wght].ttf=variable_data" \
    "fonts/variable/JetBrainsMono-Italic[wght].ttf=italic_data"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$MOCK_ZIP" "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  local out="${case_dir}/out.txt"
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name JetBrainsMono > "$out"

  assert_contains 'installed 2 font file(s)' "$out" 'Bracketed files extracted and installed'
  [ -f "${case_dir}/fonts/JetBrainsMono[wght].ttf" ] || fail 'JetBrainsMono[wght].ttf was not installed'
  [ -f "${case_dir}/fonts/JetBrainsMono-Italic[wght].ttf" ] || fail 'JetBrainsMono-Italic[wght].ttf was not installed'
  assert_eq "variable_data" "$(cat "${case_dir}/fonts/JetBrainsMono[wght].ttf")"
}

# Test 20: Mode-000 extracted font permissions are normalized to 0644
test_mode_000_permissions_normalization() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/mock.zip"

  # Create zip with an entry having external_attr mode 0000
  python3 -c "
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], 'w') as z:
    zi = zipfile.ZipInfo('OpenDyslexic-Regular.otf')
    zi.create_system = 3
    zi.external_attr = 0o100000 << 16
    z.writestr(zi, 'opendyslexic_data')
" "$mock_zip"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$MOCK_ZIP" "$out"
EOF
  chmod +x "${case_dir}/bin/curl"

  local out="${case_dir}/out.txt"
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name OpenDyslexic > "$out"

  assert_contains 'installed 1 font file(s)' "$out" 'Mode-000 file installed'
  local target_file="${case_dir}/fonts/OpenDyslexic-Regular.otf"
  [ -f "$target_file" ] || fail 'OpenDyslexic-Regular.otf was not installed'
  [ -r "$target_file" ] || fail 'Installed file must be readable'
  assert_eq "644" "$(stat -f '%Lp' "$target_file")" 'Installed file permissions must be normalized to 0644'
  assert_eq "opendyslexic_data" "$(cat "$target_file")"
}

# Run all test cases in sequence
run_test 'Catalog integrity (33 packs, unique names/probes, schema)' test_catalog_integrity
run_test 'Regex normalization compatibility with BSD grep -Ei' test_regex_normalization_bsd_grep
run_test '--list execution without 7z extractor' test_list_without_7z
run_test '--list --extended displays all 33 packs' test_list_extended
run_test 'Preflight hard failure when 7z missing on selected pack' test_preflight_fails_without_7z
run_test 'Selective zip extraction, flattening, and AppleDouble rejection' test_selective_zip_extraction_and_appledouble_rejection
run_test 'Pre-commit hard validation fails immediately on zero matches' test_precommit_hard_validation_zero_matches
run_test 'Pre-commit hard validation fails immediately on missing probe' test_precommit_hard_validation_missing_probe
run_test '--force with validation failure preserves pre-existing probe' test_force_with_validation_failure_preserves_probe
run_test 'Soft warning on font count mismatch allows commit' test_soft_warning_count_difference
run_test 'Transient download retry purges corrupt archive' test_transient_retry_and_archive_purge
run_test 'Process-isolated temp tracking cleans only own files' test_process_isolated_temp_cleanup
run_test 'Probe idempotency skips download vs --force re-downloads' test_probe_idempotency_and_force
run_test 'Confirmation prompt aborts with exit code 130 on n' test_confirmation_prompt_abort
run_test 'Best-effort loop continues across failure and exits 1 with summary' test_best_effort_loop_and_failure_summary
run_test 'Interrupted pack recovery (missing probe retried on next run)' test_interrupted_pack_recovery
run_test '7zz (from brew install sevenzip) is accepted and extracts cleanly' test_7zz_preflight_and_extraction
run_test 'Unwritable target directory fails immediately' test_unwritable_target_directory_fails_early
run_test 'Commit failure halts pack, probe absent, reports failure' test_commit_failure_regression
run_test 'Comma-separated and literal metacharacter name filtering' test_comma_separated_and_literal_name_filter
run_test 'Bracketed filenames in Zip entries extract properly' test_bracketed_filename_extraction
run_test 'Mode-000 extracted font permissions are normalized to 0644' test_mode_000_permissions_normalization

printf '\npassed: %d tests\n' "$TEST_COUNT"
