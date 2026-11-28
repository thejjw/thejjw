#!/usr/bin/env bash
# The stub commands below are invoked indirectly, through the installer under
# test, so shellcheck cannot see the call sites.
# shellcheck disable=SC2329
# Verify the libjxl CLI tools installer embedded in bin/install_j.sh.
# Targets a POSIX host: bash, coreutils and mktemp are required.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALLER="${REPO_ROOT}/bin/install_j.sh"
TEST_ROOT="$(mktemp -d)"
TEST_COUNT=0

export TEST_ROOT

# Remove only the disposable directory created by this test run.
cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

# Stop the suite with a concise assertion failure.
fail() { echo "FAIL: $*" >&2; exit 1; }

# Require a file to contain a literal string.
assert_contains() {
  local file="$1" pattern="$2" message="$3"
  grep -Fq -- "$pattern" "$file" || { cat "$file" >&2; fail "$message"; }
}

# Require a file not to contain a literal string.
assert_absent() {
  local file="$1" pattern="$2" message="$3"
  ! grep -Fq -- "$pattern" "$file" || { cat "$file" >&2; fail "$message"; }
}

# ---------------------------------------------------------------------------
# Stub commands
#
# Every command the installer shells out to is stubbed as a shell function:
# a function outranks both a shell builtin and a PATH executable, so the
# suite behaves the same on a Linux host, a macOS host, and this harness.
# ---------------------------------------------------------------------------

# Report the platform the installer sees.
uname() {
  case "${1:-}" in
    -s) echo "${FAKE_OS:-Linux}" ;;
    -m) echo "${FAKE_ARCH:-x86_64}" ;;
    *) echo "${FAKE_OS:-Linux}" ;;
  esac
}

# Model the installer's presence checks: the commands listed in
# ABSENT_COMMANDS are hidden, everything else resolves normally.
command() {
  if [[ "${1:-}" == "-v" ]]; then
    case " ${ABSENT_COMMANDS:-} " in
      *" ${2} "*) return 1 ;;
    esac
  fi
  builtin command "$@"
}

# Extract the fake release archive into the disposable tree.
tar() {
  [[ "${TAR_FAIL:-0}" == 0 ]] || return 1
  local dest="" b
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -C) dest="$2"; shift ;;
    esac
    shift
  done
  mkdir -p "$dest/tools"
  for b in cjxl djxl jxlinfo; do
    if [[ "${MISSING_TOOL:-}" == "$b" ]]; then continue; fi
    printf '#!/bin/bash\necho "%s --help"\nexit %s\n' "$b" "${EXEC_RC:-0}" > "$dest/tools/$b"
    chmod +x "$dest/tools/$b"
  done
  return 0
}

# Download the fake release archive.
curl() {
  printf 'curl %s\n' "$*" >> "$TEST_ROOT/curl.log"
  [[ "${CURL_FAIL:-0}" == 0 ]] || { echo 'connection failed' >&2; return 22; }
  local out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) out="$2"; shift ;;
    esac
    shift
  done
  if [[ -n "$out" ]]; then echo 'fake-archive' > "$out"; fi
  return 0
}

# Download the fake release archive with wget.
wget() {
  printf 'wget %s\n' "$*" >> "$TEST_ROOT/wget.log"
  [[ "${WGET_FAIL:-0}" == 0 ]] || { echo 'connection failed' >&2; return 8; }
  local out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -O) out="$2"; shift ;;
    esac
    shift
  done
  if [[ -n "$out" ]]; then echo 'fake-archive' > "$out"; fi
  return 0
}

# Decompress the fake release archive; the fake archive is already plain text.
lzip() {
  local arg
  for arg in "$@"; do
    case "$arg" in
      -*) ;;
      *) cat "$arg" ;;
    esac
  done
  return 0
}

# Run the wrapped command with the caller's privileges.
sudo() { "$@"; }

# Copy a file into the install target directory.
install() {
  local src="" dest="" arg
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -m) shift ;;
      -*) ;;
      *) if [[ -z "$src" ]]; then src="$1"; else dest="$1"; fi ;;
    esac
    shift
  done
  [[ -n "$src" && -n "$dest" ]] || return 2
  mkdir -p "$dest"
  cp "$src" "$dest/"
  chmod 0755 "$dest/$(basename "$src")"
}

# Install a package; the requested helper binaries appear afterwards.
apt-get() {
  printf 'apt-get %s\n' "$*" >> "$TEST_ROOT/apt.log"
  [[ "${APT_FAIL:-0}" == 0 ]] || return 100
  local arg
  for arg in "$@"; do
    case "$arg" in
      lzip)
        lzip() {
          local a
          for a in "$@"; do case "$a" in -*) ;; *) cat "$a" ;; esac; done
          return 0
        }
        ;;
      curl)
        curl() {
          printf 'curl %s\n' "$*" >> "$TEST_ROOT/curl.log"
          local out=""
          while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2"; shift ;; esac; shift; done
          if [[ -n "$out" ]]; then echo 'fake-archive' > "$out"; fi
          return 0
        }
        ;;
    esac
  done
  return 0
}

# Install a Homebrew formula.
brew() {
  printf 'brew %s\n' "$*" >> "$TEST_ROOT/brew.log"
  return 0
}

# Reset the disposable state between cases. The host's own cjxl is hidden by
# default so the presence of the tools is a property of the case, not of the
# machine the suite runs on.
reset_case() {
  : > "$TEST_ROOT/curl.log"
  : > "$TEST_ROOT/wget.log"
  : > "$TEST_ROOT/apt.log"
  : > "$TEST_ROOT/brew.log"
  rm -rf "$TEST_ROOT/install"
  mkdir -p "$TEST_ROOT/install"
  unset -f cjxl
  unset CURL_FAIL WGET_FAIL TAR_FAIL EXEC_RC MISSING_TOOL APT_FAIL FAKE_OS FAKE_ARCH
  export FAKE_OS=Linux FAKE_ARCH=x86_64 ABSENT_COMMANDS="cjxl"
}

# Extract the libjxl runtime block from the installer.
extract_runtime_block() {
  awk '
    $0 == "# >>> libjxl runtime >>>" { emit = 1; next }
    $0 == "# <<< libjxl runtime <<<" { emit = 0 }
    emit
  ' "$INSTALLER" > "$TEST_ROOT/libjxl_runtime.sh"
  [[ -s "$TEST_ROOT/libjxl_runtime.sh" ]] || fail 'libjxl runtime block not found in the installer'
}

# Load the installer functions with the install target inside the test tree.
load_installer_functions() {
  # shellcheck source=/dev/null
  source <(sed "s|/usr/local/bin|${TEST_ROOT}/install|g" "$TEST_ROOT/libjxl_runtime.sh")
}

extract_runtime_block
load_installer_functions

# Run one test in an isolated subshell.
run_test() {
  local name="$1" test_function="$2"
  printf 'test: %s ... ' "$name"
  (set -euo pipefail; "$test_function")
  TEST_COUNT=$((TEST_COUNT + 1))
  echo 'ok'
}

# Verify an installed tool is present in the disposable target dir.
assert_installed() {
  local tool="$1"
  [[ -x "$TEST_ROOT/install/$tool" ]] || fail "$tool was not installed"
}

# Verify the installer skips the download when the tools are already present.
test_skip_when_present() {
  reset_case
  export ABSENT_COMMANDS=""
  cjxl() { return 0; }

  local out="$TEST_ROOT/out" status=0
  install_libjxl_static_tools > "$out" 2>&1 || status=$?
  [[ "$status" -eq 0 ]] || { cat "$out" >&2; fail 'expected success when cjxl is present'; }
  assert_contains "$out" 'already present' 'skip message missing'
  [[ ! -s "$TEST_ROOT/curl.log" ]] || fail 'downloaded although cjxl was already present'
}

# Verify --force reinstalls every tool from the static release.
test_force_installs_tools() {
  reset_case

  local out="$TEST_ROOT/out" status=0
  install_libjxl_static_tools --force > "$out" 2>&1 || status=$?
  [[ "$status" -eq 0 ]] || { cat "$out" >&2; fail 'forced install failed'; }
  for tool in cjxl djxl jxlinfo; do assert_installed "$tool"; done
  assert_contains "$out" 'static tools installed' 'success message missing'
  assert_contains "$TEST_ROOT/curl.log" 'jxl-linux-x86_64-static.tar.lz' 'wrong asset URL'
}

# Verify a failed download falls back to the apt package instead of aborting.
test_download_failure_falls_back() {
  reset_case
  export CURL_FAIL=1

  local out="$TEST_ROOT/out" status=0
  install_libjxl_static_tools --force > "$out" 2>&1 || status=$?
  [[ "$status" -ne 0 ]] || fail 'a failed download must not report success'

  install_libjxl_tools > "$out" 2>&1 || true
  assert_contains "$TEST_ROOT/apt.log" 'libjxl-tools' 'apt fallback was not requested'
}

# Verify a failed extraction falls back to the apt package.
test_extraction_failure_falls_back() {
  reset_case
  export TAR_FAIL=1

  local out="$TEST_ROOT/out" status=0
  install_libjxl_static_tools --force > "$out" 2>&1 || status=$?
  [[ "$status" -ne 0 ]] || fail 'a failed extraction must not report success'

  install_libjxl_tools > "$out" 2>&1 || true
  assert_contains "$TEST_ROOT/apt.log" 'libjxl-tools' 'apt fallback was not requested'
}

# Verify the exec check removes the binaries it cannot run.
test_exec_failure_cleans_up() {
  reset_case
  export EXEC_RC=126

  local out="$TEST_ROOT/out" status=0
  install_libjxl_static_tools --force > "$out" 2>&1 || status=$?
  [[ "$status" -ne 0 ]] || fail 'an unusable binary must not report success'
  assert_contains "$out" 'failed to run' 'exec failure message missing'
  [[ ! -e "$TEST_ROOT/install/cjxl" ]] || fail 'cjxl was not removed after the exec check failed'

  install_libjxl_tools > "$out" 2>&1 || true
  assert_contains "$TEST_ROOT/apt.log" 'libjxl-tools' 'apt fallback was not requested'
}

# Verify a tarball without every tool is rejected.
test_missing_tool_rejected() {
  reset_case
  export MISSING_TOOL=djxl

  local out="$TEST_ROOT/out" status=0
  install_libjxl_static_tools --force > "$out" 2>&1 || status=$?
  [[ "$status" -ne 0 ]] || fail 'a missing tool must not report success'
  assert_contains "$out" 'not found in tarball' 'missing tool message missing'
}

# Verify macOS uses Homebrew and never touches the Linux static tarball.
test_darwin_uses_brew() {
  reset_case
  export FAKE_OS=Darwin

  local out="$TEST_ROOT/out" status=0
  install_libjxl_tools > "$out" 2>&1 || status=$?
  [[ ! -s "$TEST_ROOT/curl.log" ]] || fail 'downloaded the static tarball on macOS'
  [[ ! -e "$TEST_ROOT/install/cjxl" ]] || fail 'installed a Linux binary on macOS'
  assert_contains "$TEST_ROOT/brew.log" 'install jpeg-xl' 'Homebrew path was not used'
}

# Verify arm64 Linux uses the aarch64 static release.
test_aarch64_asset() {
  reset_case
  export FAKE_ARCH=aarch64

  install_libjxl_static_tools --force > "$TEST_ROOT/out" 2>&1 || fail 'aarch64 install failed'
  assert_contains "$TEST_ROOT/curl.log" 'jxl-linux-aarch64-static.tar.lz' 'wrong asset for aarch64'
}

# Verify the macOS "arm64" spelling never matches the aarch64 static asset.
test_arm64_spelling_rejected() {
  reset_case
  export FAKE_ARCH=arm64

  local out="$TEST_ROOT/out" status=0
  install_libjxl_static_tools --force > "$out" 2>&1 || status=$?
  [[ "$status" -ne 0 ]] || fail 'arm64 must not match the aarch64 static asset'
  [[ ! -s "$TEST_ROOT/curl.log" ]] || fail 'downloaded a static tarball for arm64'
}

# Verify a machine without curl and lzip gets them provisioned first.
test_provisions_curl_and_lzip() {
  reset_case
  unset -f curl lzip wget
  export ABSENT_COMMANDS="curl lzip wget cjxl"

  local out="$TEST_ROOT/out" status=0
  install_libjxl_static_tools --force > "$out" 2>&1 || status=$?
  [[ "$status" -eq 0 ]] || { cat "$out" >&2; fail 'fresh machine install failed'; }
  assert_contains "$TEST_ROOT/apt.log" 'lzip' 'lzip was not provisioned'
  assert_contains "$TEST_ROOT/apt.log" 'curl' 'curl was not provisioned'
  assert_absent "$TEST_ROOT/apt.log" 'libjxl-tools' 'a fresh machine must not fall back to the apt package'
  # Only the stubs record downloads, so this proves the suite stayed offline.
  assert_contains "$TEST_ROOT/curl.log" 'jxl-linux-x86_64-static.tar.lz' 'the download did not go through the stub'
  assert_absent "$TEST_ROOT/wget.log" 'wget' 'the suite must not download with wget'
  for tool in cjxl djxl jxlinfo; do assert_installed "$tool"; done
}

# Verify an unsupported architecture falls back to the apt package.
test_unsupported_arch_falls_back() {
  reset_case
  export FAKE_ARCH=riscv64

  local out="$TEST_ROOT/out" status=0
  install_libjxl_static_tools --force > "$out" 2>&1 || status=$?
  [[ "$status" -ne 0 ]] || fail 'an unsupported architecture must not report success'
  [[ ! -s "$TEST_ROOT/curl.log" ]] || fail 'downloaded a static tarball for an unsupported architecture'

  install_libjxl_tools > "$out" 2>&1 || true
  assert_contains "$TEST_ROOT/apt.log" 'libjxl-tools' 'apt fallback was not requested'
}

# Verify the dispatcher reports where cjxl resolves to.
test_dispatcher_reports_path() {
  reset_case
  export ABSENT_COMMANDS=""
  cjxl() { return 0; }

  install_libjxl_tools > "$TEST_ROOT/out" 2>&1 || fail 'dispatcher failed'
  assert_contains "$TEST_ROOT/out" 'cjxl resolves to' 'resolved path not reported'
}

# Verify the profile installer emits both functions and upgrades a stale block.
test_profile_installer() {
  local profile="$TEST_ROOT/profile" section

  # Emit the unpatched functions so the profile text matches a real install.
  # shellcheck source=/dev/null
  source "$TEST_ROOT/libjxl_runtime.sh"
  # shellcheck source=/dev/null
  source <(sed -n '/^remove_profile_section()/,/^}/p' "$INSTALLER")

  printf '%s\n' \
    before \
    '# >>> libjxl >>>' \
    '# libjxl tools version 0' \
    old-body \
    '# <<< libjxl <<<' \
    after > "$profile"
  export PROFILE="$profile"
  # Referenced by the extracted installer section evaluated below.
  # shellcheck disable=SC2034
  FORCE_REINSTALL=false

  section="$(awk '
    $0 == "# >>> libjxl profile installer >>>" { emit = 1; next }
    $0 == "# <<< libjxl profile installer <<<" { emit = 0 }
    emit
  ' "$INSTALLER")"
  eval "$section" > "$TEST_ROOT/out"

  assert_contains "$profile" '# libjxl tools version 1' 'version 1 marker missing'
  assert_absent "$profile" '# libjxl tools version 0' 'stale version marker remained'
  assert_contains "$profile" 'before' 'content before the block was lost'
  assert_contains "$profile" 'after' 'content after the block was lost'
  assert_contains "$profile" 'install_libjxl_static_tools' 'static installer was not emitted'
  assert_contains "$profile" 'install_libjxl_tools' 'dispatcher was not emitted'
  bash -n "$profile" || fail 'generated profile is not valid bash'
  if command -v zsh >/dev/null 2>&1; then
    zsh -f -n "$profile" || fail 'generated profile is not valid zsh'
  else
    echo 'skip: zsh is unavailable; generated zsh syntax was not checked' >&2
  fi

  # A second run must not duplicate the block.
  eval "$section" > "$TEST_ROOT/out2"
  [[ "$(grep -c '^# >>> libjxl >>>$' "$profile")" -eq 1 ]] || fail 'profile block was duplicated'
}

run_test 'existing tools are skipped' test_skip_when_present
run_test 'forced install writes every tool' test_force_installs_tools
run_test 'download failure falls back to apt' test_download_failure_falls_back
run_test 'extraction failure falls back to apt' test_extraction_failure_falls_back
run_test 'unusable binaries are removed' test_exec_failure_cleans_up
run_test 'an incomplete tarball is rejected' test_missing_tool_rejected
run_test 'macOS installs through Homebrew' test_darwin_uses_brew
run_test 'arm64 uses the aarch64 asset' test_aarch64_asset
run_test 'the arm64 spelling is not aarch64' test_arm64_spelling_rejected
run_test 'curl and lzip are provisioned' test_provisions_curl_and_lzip
run_test 'unsupported architecture falls back' test_unsupported_arch_falls_back
run_test 'the dispatcher reports the tool path' test_dispatcher_reports_path
run_test 'the profile installer emits both functions' test_profile_installer

printf 'passed: %d tests\n' "$TEST_COUNT"
