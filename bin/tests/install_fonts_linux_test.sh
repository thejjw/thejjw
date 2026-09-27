#!/usr/bin/env bash
#
# install_fonts_linux_test.sh
# Test suite for thejjw/bin/install_fonts_linux.sh
#
# 2026 @thejjw
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALLER="${REPO_ROOT}/bin/install_fonts_linux.sh"
CATALOG="${REPO_ROOT}/bin/font_catalog.sh"
TEST_ROOT="$(mktemp -d -t install_fonts_linux_test.XXXXXX)"
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

# Run a test function with isolated test logging
run_test() {
  local name="$1"
  local fn="$2"
  TEST_COUNT=$((TEST_COUNT + 1))
  printf 'running: %s... ' "$name"
  "$fn"
  printf 'OK\n'
}

# Assert two strings are equal
assert_eq() {
  local expected="$1"
  local actual="$2"
  local msg="${3:-Values do not match}"
  if [ "$expected" != "$actual" ]; then
    fail "$msg (expected '$expected', got '$actual')"
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

# Creates a new isolated case directory inside TEST_ROOT
new_case() {
  local dir
  dir="$(mktemp -d "${TEST_ROOT}/case.XXXXXX")"
  mkdir -p "${dir}/bin" "${dir}/fonts" "${dir}/work"
  echo "$dir"
}

# Helper to create a zip file using python3
create_mock_zip() {
  local zip_path="$1"
  shift
  python3 -c "
import zipfile, sys

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

# Test 1: Sourced catalog smoke load and count
test_catalog_smoke_load() {
  local case_dir
  case_dir="$(new_case)"
  local out="${case_dir}/out.txt"

  INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" --list > "$out"

  assert_contains '30 pack(s)' "$out" 'Standard list count'
  assert_contains 'IntelOneMono' "$out"

  INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" --list --extended > "$out"

  assert_contains '33 pack(s)' "$out" 'Extended list count'
  assert_contains 'SourceHanSans' "$out"
}

# Test 2: Default target directory resolves to $HOME/.local/share/fonts when XDG_DATA_HOME is unset
test_default_target_dir_resolution() {
  local case_dir
  case_dir="$(new_case)"
  local mock_home="${case_dir}/fake_home"
  mkdir -p "$mock_home"
  local out="${case_dir}/out.txt"

  # Run without INSTALL_FONTS_TARGET_DIR and with XDG_DATA_HOME explicitly unset
  (
    unset INSTALL_FONTS_TARGET_DIR
    unset XDG_DATA_HOME
    export HOME="$mock_home"
    "$INSTALLER" --list > "$out"
  )

  assert_contains "Target: ${mock_home}/.local/share/fonts" "$out" 'Default target path matches XDG standard'
}

# Test 3: Target directory resolves to $XDG_DATA_HOME/fonts when XDG_DATA_HOME is exported
test_xdg_data_home_override_resolution() {
  local case_dir
  case_dir="$(new_case)"
  local custom_xdg="${case_dir}/custom_data"
  mkdir -p "$custom_xdg"
  local out="${case_dir}/out.txt"

  (
    unset INSTALL_FONTS_TARGET_DIR
    export XDG_DATA_HOME="$custom_xdg"
    "$INSTALLER" --list > "$out"
  )

  assert_contains "Target: ${custom_xdg}/fonts" "$out" 'Target directory honors XDG_DATA_HOME override'
}

# Test 4: Missing 7z extractor emits Linux package manager hints
test_preflight_7z_linux_hints() {
  local case_dir
  case_dir="$(new_case)"
  local out="${case_dir}/out.txt"
  local err="${case_dir}/err.txt"

  set +e
  env -i PATH="/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name SarasaMonoK > "$out" 2> "$err"
  local status="$?"
  set -e

  assert_eq "1" "$status" 'Exited with 1 on missing 7z dependency'
  assert_contains "apt install p7zip-full, dnf install p7zip p7zip-plugins, or pacman -S p7zip" "$err" 'Linux package manager hint shown'
}

# Test 5: Successful installation invokes fc-cache on target directory
test_fc_cache_invocation_on_success() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/Jetendard-TTF.zip"

  create_mock_zip "$mock_zip" \
    "ttf/Jetendard-Regular.ttf=regular_font_data" \
    "ttf/Jetendard-Bold.ttf=bold_font_data"

  # Mock curl to return the mock zip
  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    cp "$MOCK_ZIP" "$2"
    exit 0
  fi
  shift
done
exit 1
EOF
  chmod +x "${case_dir}/bin/curl"

  # Mock fc-cache to log its arguments
  local fc_log="${case_dir}/work/fc_cache.log"
  cat <<EOF > "${case_dir}/bin/fc-cache"
#!/usr/bin/env bash
echo "\$@" >> "$fc_log"
exit 0
EOF
  chmod +x "${case_dir}/bin/fc-cache"

  local out="${case_dir}/out.txt"
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > "$out"

  assert_contains 'Updating Fontconfig cache (fc-cache -f)...' "$out" 'fc-cache progress message emitted'
  [ -f "$fc_log" ] || fail 'fc-cache was not executed'
  assert_contains "-f ${case_dir}/fonts" "$fc_log" 'fc-cache called with -f and target directory'
}

# Test 6: Absence of fc-cache emits informational note without failing installation
test_missing_fc_cache_graceful_note() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/Jetendard-TTF.zip"

  create_mock_zip "$mock_zip" \
    "ttf/Jetendard-Regular.ttf=regular_font_data"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    cp "$MOCK_ZIP" "$2"
    exit 0
  fi
  shift
done
exit 1
EOF
  chmod +x "${case_dir}/bin/curl"

  # Ensure fc-cache is NOT on PATH
  local out="${case_dir}/out.txt"
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > "$out"

  assert_contains 'Note: fc-cache not found on PATH. Installed fonts will be recognized once Fontconfig is updated.' "$out" 'Informational note emitted'
  assert_contains 'installed 1 font file(s)' "$out" 'Font still installed cleanly'
  [ -f "${case_dir}/fonts/Jetendard-Regular.ttf" ] || fail 'Probe installed'
}

# Test 7: Selective extraction, pre-commit validation, and atomic commit
test_selective_zip_and_atomic_commit() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/Jetendard-TTF.zip"

  create_mock_zip "$mock_zip" \
    "ttf/Jetendard-Regular.ttf=regular_font_data" \
    "ttf/Jetendard-Bold.ttf=bold_font_data" \
    "web/Jetendard.woff2=web_font" \
    "__MACOSX/._Jetendard-Regular.ttf=appledouble_junk"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    cp "$MOCK_ZIP" "$2"
    exit 0
  fi
  shift
done
exit 1
EOF
  chmod +x "${case_dir}/bin/curl"

  local out="${case_dir}/out.txt"
  MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > "$out"

  [ -f "${case_dir}/fonts/Jetendard-Regular.ttf" ] || fail 'Jetendard-Regular.ttf was not installed'
  [ -f "${case_dir}/fonts/Jetendard-Bold.ttf" ] || fail 'Jetendard-Bold.ttf was not installed'
  [ ! -f "${case_dir}/fonts/Jetendard.woff2" ] || fail 'woff2 should be excluded'
  [ ! -f "${case_dir}/fonts/._Jetendard-Regular.ttf" ] || fail 'AppleDouble metadata should be rejected'
}

# Test 8: Pre-commit hard validation failure on missing probe prevents commit
test_precommit_missing_probe() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/Jetendard-TTF.zip"

  create_mock_zip "$mock_zip" \
    "ttf/Jetendard-Bold.ttf=bold_font_data"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    cp "$MOCK_ZIP" "$2"
    exit 0
  fi
  shift
done
exit 1
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

  assert_eq "1" "$status" 'Installer returned exit code 1'
  assert_contains "Staged probe file 'Jetendard-Regular.ttf' is missing or 0 bytes" "$err"
  [ ! -f "${case_dir}/fonts/Jetendard-Bold.ttf" ] || fail 'Bold font must not be committed'
}

# Test 9: Probe idempotency skips download vs --force re-downloads
test_probe_idempotency_and_force() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/mock.zip"
  create_mock_zip "$mock_zip" "ttf/Jetendard-Regular.ttf=new_data"

  echo "0" > "${case_dir}/work/curl_called"
  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
cnt=$(cat "$STATE_DIR/curl_called")
echo $((cnt + 1)) > "$STATE_DIR/curl_called"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    cp "$MOCK_ZIP" "$2"
    exit 0
  fi
  shift
done
exit 1
EOF
  chmod +x "${case_dir}/bin/curl"

  # Pre-install probe
  echo "existing" > "${case_dir}/fonts/Jetendard-Regular.ttf"

  local out="${case_dir}/out.txt"
  local err="${case_dir}/err.txt"
  STATE_DIR="${case_dir}/work" \
    MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --name Jetendard > "$out" 2> "$err"

  assert_contains 'skipped: already installed' "$out" 'Skipped message shown'
  assert_eq "0" "$(cat "${case_dir}/work/curl_called")" 'curl not called when probe exists'
  assert_eq "existing" "$(cat "${case_dir}/fonts/Jetendard-Regular.ttf")" 'Pre-existing probe unchanged'

  # Now run with --force
  STATE_DIR="${case_dir}/work" \
    MOCK_ZIP="$mock_zip" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    INSTALL_FONTS_TARGET_DIR="${case_dir}/fonts" \
    "$INSTALLER" -y --force --name Jetendard > "$out" 2> "$err"

  assert_eq "1" "$(cat "${case_dir}/work/curl_called")" 'curl called with --force'
  assert_eq "new_data" "$(cat "${case_dir}/fonts/Jetendard-Regular.ttf")" 'Probe updated with new data'
}

# Test 10: Mode-000 extracted font permissions are normalized to 0644
test_mode_000_permissions_normalization() {
  local case_dir
  case_dir="$(new_case)"
  local mock_zip="${case_dir}/work/mock.zip"

  python3 -c "
import zipfile, sys

zip_path = sys.argv[1]
with zipfile.ZipFile(zip_path, 'w') as z:
    zi = zipfile.ZipInfo('OpenDyslexic-Regular.otf')
    zi.external_attr = 0o000 << 16
    z.writestr(zi, 'opendyslexic_data')
" "$mock_zip"

  cat <<'EOF' > "${case_dir}/bin/curl"
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    cp "$MOCK_ZIP" "$2"
    exit 0
  fi
  shift
done
exit 1
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
  assert_eq "opendyslexic_data" "$(cat "$target_file")"
}

# Run all test cases in sequence
run_test 'Catalog smoke load (--list and --list --extended)' test_catalog_smoke_load
run_test 'Default target directory resolution (~/.local/share/fonts)' test_default_target_dir_resolution
run_test 'Target directory resolution with XDG_DATA_HOME override' test_xdg_data_home_override_resolution
run_test 'Missing 7z preflight emits Linux package manager hints' test_preflight_7z_linux_hints
run_test 'Successful installation invokes fc-cache on target directory' test_fc_cache_invocation_on_success
run_test 'Absence of fc-cache emits informational note without failure' test_missing_fc_cache_graceful_note
run_test 'Selective zip extraction and atomic commit' test_selective_zip_and_atomic_commit
run_test 'Pre-commit hard validation failure on missing probe prevents commit' test_precommit_missing_probe
run_test 'Probe idempotency skips download vs --force re-downloads' test_probe_idempotency_and_force
run_test 'Mode-000 extracted font permissions are normalized' test_mode_000_permissions_normalization

printf '\npassed: %d tests\n' "$TEST_COUNT"
