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

# Stop the suite with a concise assertion failure.
fail() {
  echo "not ok: $*" >&2
  return 1
}

# Require two scalar values to be identical.
assert_eq() {
  local expected="$1" actual="$2" message="$3"
  [[ "$actual" == "$expected" ]] || fail "${message}: expected '${expected}', got '${actual}'"
}

# Require a file or directory to have one exact numeric mode.
assert_mode() {
  local expected="$1" path="$2" actual
  actual="$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null)"
  assert_eq "$expected" "$actual" "mode for $path"
}

# Run one test in an isolated subshell.
run_test() {
  local name="$1" test_function="$2"
  printf 'test: %s ... ' "$name"
  (set -euo pipefail; "$test_function")
  TEST_COUNT=$((TEST_COUNT + 1))
  echo 'ok'
}

# Load only the installer functions exercised by this suite.
load_installer_functions() {
  # shellcheck source=/dev/null
  source <(sed -n '/^remove_profile_section()/,/^}/p' "$INSTALLER")
  # shellcheck source=/dev/null
  source <(awk '
    $0 == "# >>> jjw-aikeys runtime >>>" { emit = 1; next }
    $0 == "# <<< jjw-aikeys runtime <<<" { emit = 0 }
    emit
  ' "$INSTALLER")
}

# Clear every environment variable managed by the vault.
clear_managed_environment() {
  unset DEEPSEEK_API_KEY ZAI_API_KEY MINIMAX_API_KEY KIMI_CODE_PLAN_API_KEY
  unset QWEN_TOKEN_PLAN_API_KEY BAILIAN_TOKEN_PLAN_API_KEY
  unset GEMINI_API_KEY NVIDIA_API_KEY OPENROUTER_API_KEY
}

# Create one disposable HOME/XDG setup and reset fake command state.
new_case() {
  local name="$1"
  CASE_ROOT="$(mktemp -d "${TEST_ROOT}/${name}.XXXXXX")"
  export HOME="${CASE_ROOT}/home"
  export XDG_CONFIG_HOME="${CASE_ROOT}/config"
  export FAKE_AGE_LOG="${CASE_ROOT}/age.log"
  export PROMPT_LOG="${CASE_ROOT}/prompts.log"
  mkdir -p "$HOME"
  : > "$FAKE_AGE_LOG"
  : > "$PROMPT_LOG"
  unset FAKE_AGE_FAIL_DECRYPT FAKE_AGE_FAIL_ENCRYPT
  unset PROMPT_DEEPSEEK PROMPT_ZAI PROMPT_MINIMAX PROMPT_KIMI
  unset PROMPT_QWEN PROMPT_GEMINI PROMPT_NVIDIA PROMPT_OPENROUTER
  clear_managed_environment
}

load_installer_functions

# Emulate age while retaining plaintext only inside the disposable test tree.
age() {
  case "${1:-}" in
    --decrypt)
      printf '%s\n' decrypt >> "$FAKE_AGE_LOG"
      [[ "${FAKE_AGE_FAIL_DECRYPT:-0}" != 1 ]] || return 1
      command cat -- "$2"
      ;;
    --passphrase)
      printf '%s\n' encrypt >> "$FAKE_AGE_LOG"
      [[ "${FAKE_AGE_FAIL_ENCRYPT:-0}" != 1 ]] || return 1
      command cat
      ;;
    *)
      echo "fake age: unsupported arguments: $*" >&2
      return 2
      ;;
  esac
}

# Replace interactive reads with deterministic values and record exact prompts.
_jjw_read_hidden() {
  local prompt="$1"
  printf '%s\n' "$prompt" >> "$PROMPT_LOG"
  case "$prompt" in
    *DEEPSEEK_API_KEY*) printf '%s' "${PROMPT_DEEPSEEK:-}" ;;
    *ZAI_API_KEY*) printf '%s' "${PROMPT_ZAI:-}" ;;
    *MINIMAX_API_KEY*) printf '%s' "${PROMPT_MINIMAX:-}" ;;
    *KIMI_CODE_PLAN_API_KEY*) printf '%s' "${PROMPT_KIMI:-}" ;;
    *QWEN_TOKEN_PLAN_API_KEY*) printf '%s' "${PROMPT_QWEN:-}" ;;
    *GEMINI_API_KEY*) printf '%s' "${PROMPT_GEMINI:-}" ;;
    *NVIDIA_API_KEY*) printf '%s' "${PROMPT_NVIDIA:-}" ;;
    *OPENROUTER_API_KEY*) printf '%s' "${PROMPT_OPENROUTER:-}" ;;
    *) fail "unexpected prompt: $prompt" ;;
  esac
}

# Return the active disposable vault path.
vault_path() {
  _jjw_aikeys_path
}

# Install one fake encrypted payload with production permissions.
write_vault() {
  local payload="$1" file
  file="$(vault_path)"
  mkdir -p "${file%/*}"
  chmod 700 "${file%/*}"
  printf '%s\n' "$payload" > "$file"
  chmod 600 "$file"
}

# Require one operation to fail without allowing errexit to stop the assertion.
assert_fails() {
  if "$@" > "${CASE_ROOT}/failed-command.stdout" 2> "${CASE_ROOT}/failed-command.stderr"; then
    fail "command unexpectedly succeeded: $*"
  fi
}

# Verify the public commands and their existing argument handling.
test_public_interface() {
  local expected
  new_case interface
  assert_eq 'Usage: cloakj [--force]' "$(cloakj --help)" 'cloakj help'
  assert_eq 'Usage: uncloakj' "$(uncloakj --help)" 'uncloakj help'

  if cloakj --unknown > "${CASE_ROOT}/stdout" 2> "${CASE_ROOT}/stderr"; then
    fail 'cloakj accepted an unknown option'
  fi
  expected=$'cloakj: unknown argument: --unknown\nUsage: cloakj [--force]'
  assert_eq "$expected" "$(command cat "${CASE_ROOT}/stderr")" 'cloakj argument error'

  if uncloakj --unknown > "${CASE_ROOT}/stdout" 2> "${CASE_ROOT}/stderr"; then
    fail 'uncloakj accepted an unknown option'
  fi
  expected=$'uncloakj: unknown argument: --unknown\nUsage: uncloakj'
  assert_eq "$expected" "$(command cat "${CASE_ROOT}/stderr")" 'uncloakj argument error'

  export PROMPT_DEEPSEEK=created-by-uncloak
  uncloakj > "${CASE_ROOT}/stdout" 2> "${CASE_ROOT}/stderr"
  assert_eq 'uncloakj: no encrypted API-key vault found; starting cloakj' \
    "$(command cat "${CASE_ROOT}/stderr")" 'missing-vault delegation'
  [[ -f "$(vault_path)" ]] || fail 'uncloakj did not create a missing vault'
  assert_eq created-by-uncloak "$DEEPSEEK_API_KEY" 'uncloakj-created export'
}

# Verify the centralized schema and allowlist.
test_metadata() {
  local expected name runtime count
  new_case metadata
  expected=$'DEEPSEEK_API_KEY||\nZAI_API_KEY||\nMINIMAX_API_KEY||\nKIMI_CODE_PLAN_API_KEY||\nQWEN_TOKEN_PLAN_API_KEY|BAILIAN_TOKEN_PLAN_API_KEY|Qwen and Bailian aliases\nGEMINI_API_KEY||\nNVIDIA_API_KEY||\nOPENROUTER_API_KEY||'
  assert_eq 'JJW-AIKEYS-V1' "$(_jjw_aikeys_header)" 'vault header'
  assert_eq "$expected" "$(_jjw_aikeys_spec)" 'key specification'

  for name in DEEPSEEK_API_KEY ZAI_API_KEY MINIMAX_API_KEY KIMI_CODE_PLAN_API_KEY \
    QWEN_TOKEN_PLAN_API_KEY BAILIAN_TOKEN_PLAN_API_KEY GEMINI_API_KEY \
    NVIDIA_API_KEY OPENROUTER_API_KEY; do
    _jjw_aikeys_name_allowed "$name" || fail "allowlisted name rejected: $name"
  done
  assert_fails _jjw_aikeys_name_allowed NOT_ALLOWED

  runtime="$(awk '
    $0 == "# >>> jjw-aikeys runtime >>>" { emit = 1; next }
    $0 == "# <<< jjw-aikeys runtime <<<" { emit = 0 }
    emit
  ' "$INSTALLER")"
  for name in DEEPSEEK_API_KEY ZAI_API_KEY MINIMAX_API_KEY KIMI_CODE_PLAN_API_KEY \
    QWEN_TOKEN_PLAN_API_KEY BAILIAN_TOKEN_PLAN_API_KEY GEMINI_API_KEY \
    NVIDIA_API_KEY OPENROUTER_API_KEY; do
    count="$(grep -oF "$name" <<< "$runtime" | wc -l | tr -d ' ')"
    assert_eq 1 "$count" "$name should be declared only in the vault specification"
  done
}

# Verify initial creation, canonical order, permissions, prompts, and exports.
test_initial_creation() {
  local file expected expected_prompts output
  new_case initial
  export PROMPT_DEEPSEEK='deep=alpha' PROMPT_ZAI='zai-alpha'
  export PROMPT_MINIMAX='minimax-alpha' PROMPT_KIMI='kimi-alpha'
  export PROMPT_QWEN='qwen=alpha' PROMPT_GEMINI='gemini-alpha'
  export PROMPT_NVIDIA='nvidia-alpha' PROMPT_OPENROUTER='openrouter-alpha'

  cloakj > "${CASE_ROOT}/stdout"
  file="$(vault_path)"
  expected=$'JJW-AIKEYS-V1\nDEEPSEEK_API_KEY=deep=alpha\nZAI_API_KEY=zai-alpha\nMINIMAX_API_KEY=minimax-alpha\nKIMI_CODE_PLAN_API_KEY=kimi-alpha\nQWEN_TOKEN_PLAN_API_KEY=qwen=alpha\nBAILIAN_TOKEN_PLAN_API_KEY=qwen=alpha\nGEMINI_API_KEY=gemini-alpha\nNVIDIA_API_KEY=nvidia-alpha\nOPENROUTER_API_KEY=openrouter-alpha'
  assert_eq "$expected" "$(command cat "$file")" 'canonical payload'
  assert_mode 700 "${file%/*}"
  assert_mode 600 "$file"
  [[ ! -e "${XDG_CONFIG_HOME}/jjw/s" ]] || fail 'plaintext directory was created'
  assert_eq 'deep=alpha' "$DEEPSEEK_API_KEY" 'DeepSeek export'
  assert_eq 'qwen=alpha' "$QWEN_TOKEN_PLAN_API_KEY" 'Qwen export'
  assert_eq "$QWEN_TOKEN_PLAN_API_KEY" "$BAILIAN_TOKEN_PLAN_API_KEY" 'Qwen alias export'
  assert_eq 1 "$(grep -c '^encrypt$' "$FAKE_AGE_LOG")" 'initial encryption count'

  expected_prompts="${CASE_ROOT}/expected-prompts"
  printf '%s\n' \
    'Enter DEEPSEEK_API_KEY (blank skips): ' \
    'Enter ZAI_API_KEY (blank skips): ' \
    'Enter MINIMAX_API_KEY (blank skips): ' \
    'Enter KIMI_CODE_PLAN_API_KEY (blank skips): ' \
    'Enter QWEN_TOKEN_PLAN_API_KEY (blank skips): ' \
    'Enter GEMINI_API_KEY (blank skips): ' \
    'Enter NVIDIA_API_KEY (blank skips): ' \
    'Enter OPENROUTER_API_KEY (blank skips): ' > "$expected_prompts"
  cmp -s "$expected_prompts" "$PROMPT_LOG" || fail 'initial prompts changed'
  output="$(command cat "${CASE_ROOT}/stdout")"
  assert_eq "cloakj: stored and loaded 9 API key(s) in $file" "$output" 'creation status'
}

# Verify existing V1 files, missing-only prompts, and unchanged updates.
test_missing_only_update() {
  local file expected_prompts
  new_case missing
  write_vault $'JJW-AIKEYS-V1\nDEEPSEEK_API_KEY=old-deep\nQWEN_TOKEN_PLAN_API_KEY=old-qwen\nBAILIAN_TOKEN_PLAN_API_KEY=old-qwen'
  file="$(vault_path)"
  export PROMPT_ZAI='new-zai'

  cloakj > "${CASE_ROOT}/stdout"
  assert_eq 'old-deep' "$DEEPSEEK_API_KEY" 'existing key preservation'
  assert_eq 'new-zai' "$ZAI_API_KEY" 'missing key addition'
  assert_eq 'old-qwen' "$BAILIAN_TOKEN_PLAN_API_KEY" 'existing alias preservation'
  expected_prompts="${CASE_ROOT}/expected-prompts"
  printf '%s\n' \
    'Enter ZAI_API_KEY (blank skips): ' \
    'Enter MINIMAX_API_KEY (blank skips): ' \
    'Enter KIMI_CODE_PLAN_API_KEY (blank skips): ' \
    'Enter GEMINI_API_KEY (blank skips): ' \
    'Enter NVIDIA_API_KEY (blank skips): ' \
    'Enter OPENROUTER_API_KEY (blank skips): ' > "$expected_prompts"
  cmp -s "$expected_prompts" "$PROMPT_LOG" || fail 'missing-only prompts changed'

  : > "$FAKE_AGE_LOG"
  : > "$PROMPT_LOG"
  cloakj > "${CASE_ROOT}/stdout"
  if grep -q '^encrypt$' "$FAKE_AGE_LOG"; then
    fail 'unchanged vault was re-encrypted'
  fi
  assert_eq 'cloakj: vault unchanged; loaded existing keys into the current shell session' \
    "$(command cat "${CASE_ROOT}/stdout")" 'unchanged status'
  grep -Fqx 'DEEPSEEK_API_KEY=old-deep' "$file" || fail 'existing value was lost'
}

# Verify forced replacement and passphrase-rotation encryption behavior.
test_forced_update() {
  local file before expected_prompts
  new_case force
  write_vault $'JJW-AIKEYS-V1\nDEEPSEEK_API_KEY=old-deep\nZAI_API_KEY=old-zai\nMINIMAX_API_KEY=old-minimax\nKIMI_CODE_PLAN_API_KEY=old-kimi\nQWEN_TOKEN_PLAN_API_KEY=old-qwen\nBAILIAN_TOKEN_PLAN_API_KEY=old-qwen\nGEMINI_API_KEY=old-gemini\nNVIDIA_API_KEY=old-nvidia\nOPENROUTER_API_KEY=old-openrouter'
  file="$(vault_path)"
  export PROMPT_DEEPSEEK='new-deep'
  cloakj --force > "${CASE_ROOT}/stdout"
  grep -Fqx 'DEEPSEEK_API_KEY=new-deep' "$file" || fail 'forced replacement was not stored'
  grep -Fqx 'ZAI_API_KEY=old-zai' "$file" || fail 'blank force prompt did not preserve value'
  assert_eq 8 "$(wc -l < "$PROMPT_LOG" | tr -d ' ')" 'forced prompt count'
  expected_prompts="${CASE_ROOT}/expected-force-prompts"
  printf '%s\n' \
    'Enter DEEPSEEK_API_KEY (blank keeps stored value): ' \
    'Enter ZAI_API_KEY (blank keeps stored value): ' \
    'Enter MINIMAX_API_KEY (blank keeps stored value): ' \
    'Enter KIMI_CODE_PLAN_API_KEY (blank keeps stored value): ' \
    'Enter QWEN_TOKEN_PLAN_API_KEY (blank keeps stored value): ' \
    'Enter GEMINI_API_KEY (blank keeps stored value): ' \
    'Enter NVIDIA_API_KEY (blank keeps stored value): ' \
    'Enter OPENROUTER_API_KEY (blank keeps stored value): ' > "$expected_prompts"
  cmp -s "$expected_prompts" "$PROMPT_LOG" || fail 'forced prompts changed'

  unset PROMPT_DEEPSEEK
  : > "$FAKE_AGE_LOG"
  : > "$PROMPT_LOG"
  before="$(command cat "$file")"
  cloakj --force > "${CASE_ROOT}/stdout"
  assert_eq 1 "$(grep -c '^encrypt$' "$FAKE_AGE_LOG")" 'passphrase rotation encryption count'
  assert_eq "$before" "$(command cat "$file")" 'blank forced update payload'
}

# Require an invalid payload to fail before changing any environment value.
assert_invalid_payload() {
  local payload="$1" expected_error="$2"
  write_vault "$payload"
  export DEEPSEEK_API_KEY=sentinel-deep ZAI_API_KEY=sentinel-zai
  if uncloakj > "${CASE_ROOT}/stdout" 2> "${CASE_ROOT}/stderr"; then
    fail 'invalid payload was accepted'
  fi
  assert_eq "$expected_error" "$(command cat "${CASE_ROOT}/stderr")" 'validation error'
  assert_eq sentinel-deep "$DEEPSEEK_API_KEY" 'partial DeepSeek export'
  assert_eq sentinel-zai "$ZAI_API_KEY" 'partial Z.AI export'
}

# Verify complete payload validation and alias invariants.
test_payload_validation() {
  new_case validation
  assert_invalid_payload $'JJW-AIKEYS-V1\nDEEPSEEK_API_KEY=changed\nNOT_ALLOWED=bad' \
    'cloakj: unsupported vault entry: NOT_ALLOWED'
  assert_invalid_payload $'JJW-AIKEYS-V1\nDEEPSEEK_API_KEY=one\nDEEPSEEK_API_KEY=two' \
    'cloakj: duplicate vault entry: DEEPSEEK_API_KEY'
  assert_invalid_payload $'JJW-AIKEYS-V1\nQWEN_TOKEN_PLAN_API_KEY=qwen' \
    'cloakj: Qwen and Bailian aliases must both be present'
  assert_invalid_payload $'JJW-AIKEYS-V1\nQWEN_TOKEN_PLAN_API_KEY=one\nBAILIAN_TOKEN_PLAN_API_KEY=two' \
    'cloakj: Qwen and Bailian aliases do not match'
  assert_invalid_payload $'WRONG\nDEEPSEEK_API_KEY=value' \
    'cloakj: unsupported or malformed vault payload'
  assert_invalid_payload $'JJW-AIKEYS-V1\nDEEPSEEK_API_KEY=' \
    'cloakj: empty vault entry: DEEPSEEK_API_KEY'
}

# Verify permission and symlink rejection.
test_path_security() {
  local file
  new_case paths
  write_vault $'JJW-AIKEYS-V1\nDEEPSEEK_API_KEY=value'
  file="$(vault_path)"
  chmod 644 "$file"
  assert_fails uncloakj

  chmod 600 "$file"
  chmod 755 "${file%/*}"
  assert_fails uncloakj

  chmod 700 "${file%/*}"
  rm -f -- "$file"
  printf '%s\n' target > "${CASE_ROOT}/target"
  ln -s "${CASE_ROOT}/target" "$file"
  assert_fails uncloakj
}

# Verify failed encryption leaves the existing vault byte-for-byte intact.
test_atomic_failure() {
  local file
  new_case atomic
  write_vault $'JJW-AIKEYS-V1\nDEEPSEEK_API_KEY=old-deep'
  file="$(vault_path)"
  cp "$file" "${CASE_ROOT}/before"
  export PROMPT_DEEPSEEK='new-deep' FAKE_AGE_FAIL_ENCRYPT=1
  if cloakj --force > "${CASE_ROOT}/stdout" 2> "${CASE_ROOT}/stderr"; then
    fail 'failed encryption was reported as successful'
  fi
  cmp -s "${CASE_ROOT}/before" "$file" || fail 'failed encryption changed the vault'
  if find "${file%/*}" -maxdepth 1 -name '.aikeys.age.*' -print -quit | grep -q .; then
    fail 'failed encryption left a temporary ciphertext file'
  fi
}

# Verify unlock success and failure preserve all-or-nothing exports.
test_unlock_behavior() {
  new_case unlock
  write_vault $'JJW-AIKEYS-V1\nDEEPSEEK_API_KEY=stored-deep\nZAI_API_KEY=stored-zai'
  export DEEPSEEK_API_KEY=old-deep ZAI_API_KEY=old-zai
  uncloakj > "${CASE_ROOT}/stdout"
  assert_eq stored-deep "$DEEPSEEK_API_KEY" 'unlock overwrite'
  assert_eq stored-zai "$ZAI_API_KEY" 'unlock second export'
  assert_eq 'uncloakj: loaded 2 API key(s) into the current shell session' \
    "$(command cat "${CASE_ROOT}/stdout")" 'unlock status'

  export DEEPSEEK_API_KEY=sentinel ZAI_API_KEY=sentinel
  export FAKE_AGE_FAIL_DECRYPT=1
  assert_fails uncloakj
  assert_eq sentinel "$DEEPSEEK_API_KEY" 'failed decrypt DeepSeek preservation'
  assert_eq sentinel "$ZAI_API_KEY" 'failed decrypt Z.AI preservation'
}

# Verify environment, vault, and legacy plaintext precedence.
test_secret_precedence() {
  local file legacy value
  new_case precedence
  write_vault $'JJW-AIKEYS-V1\nDEEPSEEK_API_KEY=vault-deep\nZAI_API_KEY=vault-zai'
  file="$(vault_path)"
  export FAKE_AGE_FAIL_DECRYPT=1
  _jjw_prepare_secret existing
  [[ ! -s "$FAKE_AGE_LOG" ]] || fail 'existing environment triggered vault decryption'

  unset FAKE_AGE_FAIL_DECRYPT ZAI_API_KEY
  _jjw_prepare_secret '' > "${CASE_ROOT}/stdout"
  assert_eq vault-zai "$ZAI_API_KEY" 'launcher-triggered unlock'
  value="$(_jjw_secret z session-zai)"
  assert_eq session-zai "$value" 'environment precedence'

  rm -f -- "$file"
  legacy="${XDG_CONFIG_HOME}/jjw/s"
  mkdir -p "$legacy"
  chmod 700 "$legacy"
  printf '%s\n' legacy-zai > "${legacy}/z"
  chmod 600 "${legacy}/z"
  value="$(_jjw_secret z '')"
  assert_eq legacy-zai "$value" 'legacy fallback'

  write_vault $'JJW-AIKEYS-V1\nDEEPSEEK_API_KEY=only-deepseek'
  assert_fails _jjw_secret z ''
}

# Verify v2 block replacement and generated Bash/zsh syntax.
test_profile_upgrade() {
  local profile installer_section
  new_case profile
  profile="${CASE_ROOT}/profile"
  printf '%s\n' \
    before \
    '# >>> jjw-secrets >>>' \
    '# jjw-secrets version 2' \
    old-body \
    '# <<< jjw-secrets <<<' \
    after > "$profile"
  export PROFILE="$profile"
  # Referenced by the extracted installer section evaluated below.
  # shellcheck disable=SC2034
  FORCE_REINSTALL=false
  installer_section="$(awk '
    $0 == "# >>> jjw-secrets profile installer >>>" { emit = 1; next }
    $0 == "# <<< jjw-secrets profile installer <<<" { emit = 0 }
    emit
  ' "$INSTALLER")"
  eval "$installer_section" > "${CASE_ROOT}/stdout"

  grep -Fqx '# jjw-secrets version 3' "$profile" || fail 'version 3 marker missing'
  ! grep -Fq '# jjw-secrets version 2' "$profile" || fail 'version 2 block remained'
  grep -Fqx before "$profile" || fail 'content before upgraded block was lost'
  grep -Fqx after "$profile" || fail 'content after upgraded block was lost'
  grep -Fq '_jjw_aikeys_spec ()' "$profile" || fail 'metadata helper was not emitted'
  bash -n "$profile"
  if command -v zsh >/dev/null 2>&1; then
    zsh -f -n "$profile"
  else
    echo 'skip: zsh is unavailable; generated zsh syntax was not checked' >&2
  fi
}

run_test 'public command behavior is stable' test_public_interface
run_test 'metadata is centralized' test_metadata
run_test 'initial creation is canonical' test_initial_creation
run_test 'missing-only updates are preserved' test_missing_only_update
run_test 'forced updates rotate encryption' test_forced_update
run_test 'payload validation is all-or-nothing' test_payload_validation
run_test 'permissions and symlinks are rejected' test_path_security
run_test 'failed encryption is atomic' test_atomic_failure
run_test 'unlock behavior is stable' test_unlock_behavior
run_test 'secret precedence is stable' test_secret_precedence
run_test 'version 2 profiles upgrade to version 3' test_profile_upgrade

printf 'passed: %d tests\n' "$TEST_COUNT"
