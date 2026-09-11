#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONVERTER="${REPO_ROOT}/bin/convert_av1_ab-av1.sh"
TEST_ROOT="$(mktemp -d)"
TEST_COUNT=0

# Clean up temporary test directory upon exit.
cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

# Stop the suite with an assertion failure message.
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

# Require two values to be identical.
assert_eq() {
  local expected="$1"
  local actual="$2"
  local message="${3:-values not equal}"
  if [[ "$expected" != "$actual" ]]; then
    fail "${message}: expected '${expected}', got '${actual}'"
  fi
}

# Assert that a pattern matches within a given file.
assert_contains() {
  local pattern="$1"
  local file="$2"
  local message="${3:-file does not contain pattern}"
  if ! grep -Fq -- "$pattern" "$file"; then
    fail "${message}: pattern '${pattern}' not found in '${file}'"
  fi
}

# Assert that a pattern does NOT match within a given file.
assert_not_contains() {
  local pattern="$1"
  local file="$2"
  local message="${3:-file contains forbidden pattern}"
  if grep -Fq -- "$pattern" "$file"; then
    fail "${message}: forbidden pattern '${pattern}' found in '${file}'"
  fi
}

# Run one isolated test case.
run_test() {
  local desc="$1"
  local fn="$2"
  printf 'running: %s... ' "$desc"
  "$fn"
  TEST_COUNT=$((TEST_COUNT + 1))
  printf 'OK\n'
}

# Create a clean isolated workspace for each test case.
new_case() {
  local case_dir="${TEST_ROOT}/case_${TEST_COUNT}"
  rm -rf "$case_dir"
  mkdir -p "$case_dir/bin" "$case_dir/work"
  printf '%s\n' "$case_dir"
}

# Test 1: CRF failure on the first encode skips remux and updates STAT_CRF_FAILED.
test_crf_failure_skips_remux() {
  local case_dir
  case_dir="$(new_case)"
  local bin_dir="${case_dir}/bin"
  local work_dir="${case_dir}/work"

  # Create a dummy video file
  echo "dummy video" > "${work_dir}/sample.mp4"

  # Mock ab-av1: outputs "Error: Failed to find a suitable crf" and exits 1
  cat > "${bin_dir}/ab-av1" <<'EOF'
#!/usr/bin/env bash
echo "encoding sample 1/12 crf 37.5"
echo "Error: Failed to find a suitable crf"
exit 1
EOF
  chmod +x "${bin_dir}/ab-av1"

  # Mock ffmpeg: logs if called (should not be called for remux)
  cat > "${bin_dir}/ffmpeg" <<EOF
#!/usr/bin/env bash
echo "ffmpeg called" >> "${case_dir}/ffmpeg.log"
exit 1
EOF
  chmod +x "${bin_dir}/ffmpeg"

  # Run converter inside work_dir with PATH pointing to mock binaries
  (
    cd "$work_dir"
    PATH="${bin_dir}:${PATH}" bash "$CONVERTER"
  )

  # Verify log assertions
  local logfile
  logfile="$(find "$work_dir" -maxdepth 1 -name "convert_av1_ab-av1_*.log" | head -n 1)"
  assert_contains "CRF search exhausted" "$logfile" "should log CRF exhaustion warning"
  assert_contains "Skipping remux repair" "$logfile" "should skip remux repair"
  assert_not_contains "Attempting MKV remux repair" "$logfile" "should not attempt remux"
  assert_contains "CRF failed: 1" "$logfile" "should count 1 in CRF failed stat"
  assert_contains "Direct OK: 0" "$logfile" "Direct OK should be 0"
  assert_contains "Remux OK: 0" "$logfile" "Remux OK should be 0"
  assert_contains "Other failed: 0" "$logfile" "Other failed should be 0"

  # ffmpeg should not have been called
  if [[ -f "${case_dir}/ffmpeg.log" ]]; then
    fail "ffmpeg was unexpectedly invoked when CRF failure occurred"
  fi
}

# Test 2: Non-CRF failure triggers remux repair, and retry success increments STAT_REMUX_SUCCESS.
test_non_crf_failure_triggers_remux_success() {
  local case_dir
  case_dir="$(new_case)"
  local bin_dir="${case_dir}/bin"
  local work_dir="${case_dir}/work"

  echo "dummy video" > "${work_dir}/corrupt.mp4"

  # Mock ab-av1: fails on .mp4 with general container error, succeeds on .mkv
  cat > "${bin_dir}/ab-av1" <<EOF
#!/usr/bin/env bash
for arg in "\$@"; do
  if [[ "\$arg" == *.mp4 ]]; then
    echo "moov atom not found: generic container error"
    exit 1
  fi
  if [[ "\$arg" == *.mkv ]]; then
    # Create the expected output file
    dir="\$(dirname "\$arg")"
    base="\$(basename "\$arg")"
    fname="\${base%.*}"
    echo "encoded av1" > "\${dir}/\${fname}.av1.mkv"
    echo "verification ok"
    exit 0
  fi
done
exit 1
EOF
  chmod +x "${bin_dir}/ab-av1"

  # Mock ffmpeg: creates dummy remux temp file
  cat > "${bin_dir}/ffmpeg" <<'EOF'
#!/usr/bin/env bash
out="${!#}"
echo "remuxed mkv stream" > "$out"
exit 0
EOF
  chmod +x "${bin_dir}/ffmpeg"

  (
    cd "$work_dir"
    PATH="${bin_dir}:${PATH}" bash "$CONVERTER"
  )

  local logfile
  logfile="$(find "$work_dir" -maxdepth 1 -name "convert_av1_ab-av1_*.log" | head -n 1)"
  assert_contains "Attempting MKV remux repair" "$logfile" "should attempt remux repair on non-CRF error"
  assert_contains "Remux successful" "$logfile" "remux should succeed"
  assert_contains "Remux OK: 1" "$logfile" "should count 1 in Remux OK stat"
  assert_contains "CRF failed: 0" "$logfile" "CRF failed should be 0"
  assert_contains "Other failed: 0" "$logfile" "Other failed should be 0"
}

# Test 3: Non-CRF failure remuxes, but retry fails due to CRF search exhaustion.
test_remux_retry_crf_failure_classified_as_crf_failed() {
  local case_dir
  case_dir="$(new_case)"
  local bin_dir="${case_dir}/bin"
  local work_dir="${case_dir}/work"

  echo "dummy video" > "${work_dir}/badheader.mp4"

  # Mock ab-av1: fails on .mp4 with container error, fails on .mkv retry with CRF exhaustion
  cat > "${bin_dir}/ab-av1" <<EOF
#!/usr/bin/env bash
for arg in "\$@"; do
  if [[ "\$arg" == *.mp4 ]]; then
    echo "Invalid data found when processing input"
    exit 1
  fi
  if [[ "\$arg" == *.mkv ]]; then
    echo "Error: Failed to find a suitable crf"
    exit 1
  fi
done
exit 1
EOF
  chmod +x "${bin_dir}/ab-av1"

  # Mock ffmpeg: creates dummy remux temp file
  cat > "${bin_dir}/ffmpeg" <<'EOF'
#!/usr/bin/env bash
out="${!#}"
echo "remuxed mkv stream" > "$out"
exit 0
EOF
  chmod +x "${bin_dir}/ffmpeg"

  (
    cd "$work_dir"
    PATH="${bin_dir}:${PATH}" bash "$CONVERTER"
  )

  local logfile
  logfile="$(find "$work_dir" -maxdepth 1 -name "convert_av1_ab-av1_*.log" | head -n 1)"
  assert_contains "Attempting MKV remux repair" "$logfile" "should attempt remux for container error"
  assert_contains "constraints for remuxed" "$logfile" "should detect CRF exhaustion on retry"
  assert_contains "CRF failed: 1" "$logfile" "should classify retry CRF failure as CRF failed"
  assert_contains "Remux OK: 0" "$logfile" "Remux OK should be 0"
  assert_contains "Other failed: 0" "$logfile" "Other failed should be 0"
}

# Test 4: Running statistics are printed when processing multiple files.
test_running_statistics_printed() {
  local case_dir
  case_dir="$(new_case)"
  local bin_dir="${case_dir}/bin"
  local work_dir="${case_dir}/work"

  # Create two video files
  echo "vid1" > "${work_dir}/vid1.mp4"
  echo "vid2" > "${work_dir}/vid2.mp4"

  # Mock ab-av1: succeeds on vid1, fails with CRF on vid2
  cat > "${bin_dir}/ab-av1" <<EOF
#!/usr/bin/env bash
for arg in "\$@"; do
  if [[ "\$arg" == *vid1.mp4 ]]; then
    echo "av1 content" > "${work_dir}/vid1.av1.mp4"
    exit 0
  fi
  if [[ "\$arg" == *vid2.mp4 ]]; then
    echo "Error: Failed to find a suitable crf"
    exit 1
  fi
done
exit 1
EOF
  chmod +x "${bin_dir}/ab-av1"

  (
    cd "$work_dir"
    PATH="${bin_dir}:${PATH}" bash "$CONVERTER"
  )

  local logfile
  logfile="$(find "$work_dir" -maxdepth 1 -name "convert_av1_ab-av1_*.log" | head -n 1)"
  assert_contains "Running stats: 1 processed" "$logfile" "should print running stats line for subsequent file"
  assert_contains "Summary: 2 files | Direct OK: 1 | Remux OK: 0 | CRF failed: 1 | Other failed: 0" "$logfile" "final summary must reflect both outcomes"
}

run_test 'CRF failure skips remux and increments STAT_CRF_FAILED' test_crf_failure_skips_remux
run_test 'Non-CRF failure triggers remux and counts remux success' test_non_crf_failure_triggers_remux_success
run_test 'Remux retry CRF failure is classified as CRF failed' test_remux_retry_crf_failure_classified_as_crf_failed
run_test 'Running statistics are printed across multiple files' test_running_statistics_printed

printf 'passed: %d tests\n' "$TEST_COUNT"
