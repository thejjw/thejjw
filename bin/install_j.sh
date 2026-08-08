#!/bin/bash
# ---------------------------------------------------------------------------
# One-shot environment bootstrap
# Installs packages, nvm/node, and embeds functions into ~/.bashrc.
# ---------------------------------------------------------------------------
# 2026.4-2026.7 @thejjw

set -e

FORCE_REINSTALL=false
INSTALL_GHOSTTY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE_REINSTALL=true
      shift
      ;;
    --ghostty)
      INSTALL_GHOSTTY=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--force] [--ghostty]"
      exit 0
      ;;
    *)
      echo "install_j.sh: unknown argument: $1" >&2
      echo "Usage: $0 [--force] [--ghostty]" >&2
      exit 1
      ;;
  esac
done

PACKAGES="age tmux build-essential git cmatrix fonts-noto-cjk curl wget ripgrep jq parallel zstd xz-utils lzip webp btop bubblewrap socat fd-find fzf"
NVM_VERSION="v0.40.6"
NVM_INSTALL_URL="https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh"
UV_INSTALL_URL="https://astral.sh/uv/install.sh"

remove_profile_section() {
  local profile_file="$1" start_marker="$2" end_marker="$3"
  local tmp_file

  [[ -f "$profile_file" ]] || return 0

  tmp_file="$(mktemp)"
  awk -v start="$start_marker" -v end="$end_marker" '
    $0 == start { skip = 1; next }
    skip {
      if ($0 == end) {
        skip = 0
      }
      next
    }
    { print }
  ' "$profile_file" > "$tmp_file"
  mv "$tmp_file" "$profile_file"
}

# Print the encrypted API-key vault path for the active user.
_jjw_aikeys_path() {
  printf '%s/jjw/aikeys.age' "${XDG_CONFIG_HOME:-${HOME}/.config}"
}

# Return a file mode using GNU stat on Linux or BSD stat on macOS.
_jjw_file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

# Return success only for an API-key name supported by the vault format.
_jjw_aikeys_name_allowed() {
  case "$1" in
    DEEPSEEK_API_KEY|ZAI_API_KEY|MINIMAX_API_KEY|KIMI_API_KEY|\
    QWEN_TOKEN_PLAN_API_KEY|BAILIAN_TOKEN_PLAN_API_KEY|GEMINI_API_KEY|\
    NVIDIA_API_KEY|OPENROUTER_API_KEY) return 0 ;;
    *) return 1 ;;
  esac
}

# Validate a decrypted vault payload completely before any values are exported.
_jjw_aikeys_validate() {
  local payload="$1" line name value seen='|' first=true count=0
  local qwen_value='' bailian_value=''

  while IFS= read -r line || [[ -n "$line" ]]; do
    if $first; then
      first=false
      if [[ "$line" != "JJW-AIKEYS-V1" ]]; then
        echo "cloakj: unsupported or malformed vault payload" >&2
        return 1
      fi
      continue
    fi

    if [[ "$line" != *=* || "$line" == *$'\r'* ]]; then
      echo "cloakj: malformed vault entry" >&2
      return 1
    fi
    name="${line%%=*}"
    value="${line#*=}"
    if ! _jjw_aikeys_name_allowed "$name"; then
      echo "cloakj: unsupported vault entry: $name" >&2
      return 1
    fi
    if [[ -z "$value" ]]; then
      echo "cloakj: empty vault entry: $name" >&2
      return 1
    fi
    case "$seen" in
      *"|${name}|"*)
        echo "cloakj: duplicate vault entry: $name" >&2
        return 1
        ;;
    esac
    seen="${seen}${name}|"
    count=$((count + 1))
    [[ "$name" == "QWEN_TOKEN_PLAN_API_KEY" ]] && qwen_value="$value"
    [[ "$name" == "BAILIAN_TOKEN_PLAN_API_KEY" ]] && bailian_value="$value"
  done <<< "$payload"

  if $first || (( count == 0 )); then
    echo "cloakj: vault contains no API keys" >&2
    return 1
  fi
  if [[ -n "$qwen_value" || -n "$bailian_value" ]]; then
    if [[ -z "$qwen_value" || -z "$bailian_value" ]]; then
      echo "cloakj: Qwen and Bailian aliases must both be present" >&2
      return 1
    fi
    if [[ "$qwen_value" != "$bailian_value" ]]; then
      echo "cloakj: Qwen and Bailian aliases do not match" >&2
      return 1
    fi
  fi
}

# Print one named value from an already validated vault payload.
_jjw_aikeys_value() {
  local payload="$1" wanted="$2" line name
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == *=* ]] || continue
    name="${line%%=*}"
    if [[ "$name" == "$wanted" ]]; then
      printf '%s' "${line#*=}"
      return 0
    fi
  done <<< "$payload"
  return 1
}

# Export every entry from an already validated payload into the current shell.
_jjw_aikeys_export() {
  local payload="$1" line name value count=0
  _jjw_aikeys_validate "$payload" || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == *=* ]] || continue
    name="${line%%=*}"
    value="${line#*=}"
    if ! export "$name=$value"; then
      echo "cloakj: cannot export vault entry: $name" >&2
      return 1
    fi
    count=$((count + 1))
  done <<< "$payload"
  JJW_AIKEYS_LOADED_COUNT="$count"
}

# Read one API key without echoing it; compatible with Bash and zsh.
_jjw_read_hidden() {
  local prompt="$1" value
  if [[ ! -r /dev/tty ]]; then
    echo "cloakj: an interactive terminal is required" >&2
    return 1
  fi
  if [[ -n "${ZSH_VERSION:-}" ]]; then
    IFS= read -r -s "value?${prompt}" < /dev/tty || return 1
  else
    IFS= read -r -s -p "$prompt" value < /dev/tty || return 1
  fi
  printf '\n' > /dev/tty
  printf '%s' "$value"
}

# Prompt for a missing or replaceable key and print the selected value.
_jjw_cloak_value() {
  local name="$1" current="$2" force="$3" entered
  if [[ -n "$current" ]] && ! $force; then
    printf '%s' "$current"
    return 0
  fi
  if [[ -n "$current" ]]; then
    entered="$(_jjw_read_hidden "Enter $name (blank keeps stored value): ")" || return 1
    printf '%s' "${entered:-$current}"
  else
    entered="$(_jjw_read_hidden "Enter $name (blank skips): ")" || return 1
    printf '%s' "$entered"
  fi
}

# Reject unsafe vault paths and enforce owner-only permissions.
_jjw_aikeys_check_path() {
  local file="$1" dir mode
  dir="${file%/*}"
  if [[ -L "$dir" || ! -d "$dir" ]]; then
    echo "cloakj: vault directory must be a regular directory: $dir" >&2
    return 1
  fi
  mode="$(_jjw_file_mode "$dir")" || {
    echo "cloakj: cannot inspect vault directory permissions: $dir" >&2
    return 1
  }
  if [[ "$mode" != "700" ]]; then
    echo "cloakj: insecure permissions on $dir (expected 700, found $mode)" >&2
    return 1
  fi
  if [[ -L "$file" || ! -f "$file" ]]; then
    echo "cloakj: vault must be a regular file: $file" >&2
    return 1
  fi
  mode="$(_jjw_file_mode "$file")" || {
    echo "cloakj: cannot inspect vault permissions: $file" >&2
    return 1
  }
  if [[ "$mode" != "600" ]]; then
    echo "cloakj: insecure permissions on $file (expected 600, found $mode)" >&2
    return 1
  fi
}

# Decrypt aikeys.age and load every stored key into the current shell session.
uncloakj() {
  local file payload had_xtrace=false count
  if (( $# > 1 )); then
    echo "Usage: uncloakj" >&2
    return 1
  fi
  case "${1:-}" in
    '') ;;
    -h|--help)
      echo "Usage: uncloakj"
      return 0
      ;;
    *)
      echo "uncloakj: unknown argument: $1" >&2
      echo "Usage: uncloakj" >&2
      return 1
      ;;
  esac

  file="$(_jjw_aikeys_path)"
  if [[ ! -e "$file" && ! -L "$file" ]]; then
    echo "uncloakj: no encrypted API-key vault found; starting cloakj" >&2
    cloakj
    return $?
  fi
  command -v age >/dev/null 2>&1 || {
    echo "uncloakj: age is required (install with 'apt install age' or 'brew install age')" >&2
    return 1
  }
  _jjw_aikeys_check_path "$file" || return 1

  case "$-" in *x*) had_xtrace=true; set +x ;; esac
  if ! payload="$(age --decrypt "$file")"; then
    unset payload
    $had_xtrace && set -x
    echo "uncloakj: vault decryption failed" >&2
    return 1
  fi
  if ! _jjw_aikeys_validate "$payload"; then
    unset payload
    $had_xtrace && set -x
    return 1
  fi
  if ! _jjw_aikeys_export "$payload"; then
    unset payload JJW_AIKEYS_LOADED_COUNT
    $had_xtrace && set -x
    return 1
  fi
  count="${JJW_AIKEYS_LOADED_COUNT:-0}"
  unset payload JJW_AIKEYS_LOADED_COUNT
  $had_xtrace && set -x
  echo "uncloakj: loaded $count API key(s) into the current shell session"
}

# Create or update the passphrase-encrypted API-key vault.
cloakj() {
  local force=false file dir old_payload='' payload tmp='' had_xtrace=false
  local deepseek zai minimax kimi qwen gemini nvidia openrouter count
  if (( $# > 1 )); then
    echo "Usage: cloakj [--force]" >&2
    return 1
  fi
  case "${1:-}" in
    '') ;;
    --force) force=true ;;
    -h|--help)
      echo "Usage: cloakj [--force]"
      return 0
      ;;
    *)
      echo "cloakj: unknown argument: $1" >&2
      echo "Usage: cloakj [--force]" >&2
      return 1
      ;;
  esac

  command -v age >/dev/null 2>&1 || {
    echo "cloakj: age is required (install with 'apt install age' or 'brew install age')" >&2
    return 1
  }
  file="$(_jjw_aikeys_path)"
  dir="${file%/*}"
  if [[ -L "$dir" ]]; then
    echo "cloakj: refusing symlinked vault directory: $dir" >&2
    return 1
  fi
  if [[ ! -d "$dir" ]]; then
    (umask 077; mkdir -p "$dir") || return 1
    chmod 700 "$dir" || return 1
  else
    local dir_mode
    dir_mode="$(_jjw_file_mode "$dir")" || return 1
    if [[ "$dir_mode" != "700" ]]; then
      chmod 700 "$dir" || {
        echo "cloakj: cannot secure vault directory permissions: $dir" >&2
        return 1
      }
    fi
  fi
  if [[ -e "$file" || -L "$file" ]]; then
    _jjw_aikeys_check_path "$file" || return 1
  fi

  case "$-" in *x*) had_xtrace=true; set +x ;; esac
  if [[ -f "$file" ]]; then
    if ! old_payload="$(age --decrypt "$file")"; then
      unset old_payload
      $had_xtrace && set -x
      echo "cloakj: existing vault decryption failed" >&2
      return 1
    fi
    if ! _jjw_aikeys_validate "$old_payload"; then
      unset old_payload
      $had_xtrace && set -x
      return 1
    fi
  fi

  deepseek="$(_jjw_aikeys_value "$old_payload" DEEPSEEK_API_KEY 2>/dev/null || true)"
  zai="$(_jjw_aikeys_value "$old_payload" ZAI_API_KEY 2>/dev/null || true)"
  minimax="$(_jjw_aikeys_value "$old_payload" MINIMAX_API_KEY 2>/dev/null || true)"
  kimi="$(_jjw_aikeys_value "$old_payload" KIMI_API_KEY 2>/dev/null || true)"
  qwen="$(_jjw_aikeys_value "$old_payload" QWEN_TOKEN_PLAN_API_KEY 2>/dev/null || true)"
  [[ -n "$qwen" ]] || qwen="$(_jjw_aikeys_value "$old_payload" BAILIAN_TOKEN_PLAN_API_KEY 2>/dev/null || true)"
  gemini="$(_jjw_aikeys_value "$old_payload" GEMINI_API_KEY 2>/dev/null || true)"
  nvidia="$(_jjw_aikeys_value "$old_payload" NVIDIA_API_KEY 2>/dev/null || true)"
  openrouter="$(_jjw_aikeys_value "$old_payload" OPENROUTER_API_KEY 2>/dev/null || true)"

  deepseek="$(_jjw_cloak_value DEEPSEEK_API_KEY "$deepseek" "$force")" || {
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter tmp
    $had_xtrace && set -x
    return 1
  }
  zai="$(_jjw_cloak_value ZAI_API_KEY "$zai" "$force")" || {
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter tmp
    $had_xtrace && set -x
    return 1
  }
  minimax="$(_jjw_cloak_value MINIMAX_API_KEY "$minimax" "$force")" || {
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter tmp
    $had_xtrace && set -x
    return 1
  }
  kimi="$(_jjw_cloak_value KIMI_API_KEY "$kimi" "$force")" || {
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter tmp
    $had_xtrace && set -x
    return 1
  }
  qwen="$(_jjw_cloak_value QWEN_TOKEN_PLAN_API_KEY "$qwen" "$force")" || {
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter tmp
    $had_xtrace && set -x
    return 1
  }
  gemini="$(_jjw_cloak_value GEMINI_API_KEY "$gemini" "$force")" || {
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter tmp
    $had_xtrace && set -x
    return 1
  }
  nvidia="$(_jjw_cloak_value NVIDIA_API_KEY "$nvidia" "$force")" || {
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter tmp
    $had_xtrace && set -x
    return 1
  }
  openrouter="$(_jjw_cloak_value OPENROUTER_API_KEY "$openrouter" "$force")" || {
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter tmp
    $had_xtrace && set -x
    return 1
  }

  payload='JJW-AIKEYS-V1'
  count=0
  [[ -n "$deepseek" ]] && { payload="${payload}"$'\n'"DEEPSEEK_API_KEY=${deepseek}"; count=$((count + 1)); }
  [[ -n "$zai" ]] && { payload="${payload}"$'\n'"ZAI_API_KEY=${zai}"; count=$((count + 1)); }
  [[ -n "$minimax" ]] && { payload="${payload}"$'\n'"MINIMAX_API_KEY=${minimax}"; count=$((count + 1)); }
  [[ -n "$kimi" ]] && { payload="${payload}"$'\n'"KIMI_API_KEY=${kimi}"; count=$((count + 1)); }
  if [[ -n "$qwen" ]]; then
    payload="${payload}"$'\n'"QWEN_TOKEN_PLAN_API_KEY=${qwen}"$'\n'"BAILIAN_TOKEN_PLAN_API_KEY=${qwen}"
    count=$((count + 2))
  fi
  [[ -n "$gemini" ]] && { payload="${payload}"$'\n'"GEMINI_API_KEY=${gemini}"; count=$((count + 1)); }
  [[ -n "$nvidia" ]] && { payload="${payload}"$'\n'"NVIDIA_API_KEY=${nvidia}"; count=$((count + 1)); }
  [[ -n "$openrouter" ]] && { payload="${payload}"$'\n'"OPENROUTER_API_KEY=${openrouter}"; count=$((count + 1)); }
  if (( count == 0 )); then
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter
    $had_xtrace && set -x
    echo "cloakj: no API keys were provided" >&2
    return 1
  fi
  if ! _jjw_aikeys_validate "$payload"; then
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter
    $had_xtrace && set -x
    return 1
  fi

  if [[ -f "$file" && "$payload" == "$old_payload" ]] && ! $force; then
    if ! _jjw_aikeys_export "$payload"; then
      unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter JJW_AIKEYS_LOADED_COUNT
      $had_xtrace && set -x
      return 1
    fi
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter JJW_AIKEYS_LOADED_COUNT
    $had_xtrace && set -x
    echo "cloakj: vault unchanged; loaded existing keys into the current shell session"
    return 0
  fi

  tmp="$(umask 077; mktemp "${dir}/.aikeys.age.XXXXXX")" || {
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter tmp
    $had_xtrace && set -x
    return 1
  }
  if ! (
    trap 'rm -f "$tmp"; exit 1' HUP INT TERM
    printf '%s\n' "$payload" | age --passphrase > "$tmp"
  ); then
    rm -f "$tmp"
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter
    $had_xtrace && set -x
    echo "cloakj: vault encryption failed; existing vault was not changed" >&2
    return 1
  fi
  if ! chmod 600 "$tmp" || ! mv "$tmp" "$file"; then
    rm -f "$tmp"
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter
    $had_xtrace && set -x
    echo "cloakj: failed to replace vault; existing vault was not changed" >&2
    return 1
  fi
  if ! _jjw_aikeys_export "$payload"; then
    unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter JJW_AIKEYS_LOADED_COUNT
    $had_xtrace && set -x
    echo "cloakj: vault stored, but one or more keys could not be loaded into this shell" >&2
    return 1
  fi
  unset old_payload payload deepseek zai minimax kimi qwen gemini nvidia openrouter JJW_AIKEYS_LOADED_COUNT
  $had_xtrace && set -x
  echo "cloakj: stored and loaded $count API key(s) in $file"
}

# Unlock the encrypted vault in the parent shell when a required value is absent.
_jjw_prepare_secret() {
  local current="$1" vault
  [[ -n "$current" ]] && return 0
  vault="$(_jjw_aikeys_path)"
  if [[ -e "$vault" || -L "$vault" ]]; then
    uncloakj
  fi
}

# Resolve a session value first, then the legacy plaintext store when no vault exists.
_jjw_secret() {
  local name="$1" current="$2" vault dir file dir_mode mode value
  if [[ -n "$current" ]]; then
    printf '%s' "$current"
    return 0
  fi
  vault="$(_jjw_aikeys_path)"
  if [[ -e "$vault" || -L "$vault" ]]; then
    echo "secret: required key is missing from encrypted vault; run cloakj" >&2
    return 1
  fi

  dir="${XDG_CONFIG_HOME:-${HOME}/.config}/jjw/s"
  file="${dir}/${name}"
  dir_mode="$(_jjw_file_mode "$dir")" || {
    echo "secret: cannot inspect directory permissions: $dir" >&2
    return 1
  }
  if [[ "$dir_mode" != "700" ]]; then
    echo "secret: insecure permissions on $dir (expected 700, found $dir_mode)" >&2
    return 1
  fi
  if [[ ! -f "$file" || -L "$file" ]]; then
    echo "secret: missing regular file: $file" >&2
    return 1
  fi
  mode="$(_jjw_file_mode "$file")" || {
    echo "secret: cannot inspect permissions: $file" >&2
    return 1
  }
  if [[ "$mode" != "600" ]]; then
    echo "secret: insecure permissions on $file (expected 600, found $mode)" >&2
    return 1
  fi
  IFS= read -r value < "$file" || true
  if [[ -z "$value" ]]; then
    echo "secret: empty credential file: $file" >&2
    return 1
  fi
  printf '%s' "$value"
}

# Install libjxl CLI tools (cjxl/djxl/jxlinfo) from the official statically
# linked x86_64 release tarball. The published binaries are fully static (no
# dynamic loader, no glibc version dependency), so they run on any amd64 Linux
# without distro detection. Falls back to the libjxl-tools apt package on
# non-amd64 systems or if download/extraction/exec fails.
install_libjxl_static_tools() {
  local arch tmp_dir archive tools url b rc
  local -a want=(cjxl djxl jxlinfo)

  echo "libjxl: checking for official static release tools..."

  if command -v cjxl &>/dev/null && ! $FORCE_REINSTALL; then
    echo "libjxl: cjxl already present at $(command -v cjxl) -- skipping (use --force to reinstall)"
    return 0
  fi
  if command -v cjxl &>/dev/null && $FORCE_REINSTALL; then
    echo "libjxl: --force set; reinstalling from latest release over existing $(command -v cjxl)"
  fi

  # The static tarball is x86_64/amd64 only; anything else uses the apt package.
  arch="$(dpkg --print-architecture 2>/dev/null || uname -m)"
  if [[ "$arch" != "amd64" ]]; then
    echo "libjxl: architecture '$arch' has no static tarball; using libjxl-tools apt package"
    PACKAGES="libjxl-tools $PACKAGES"
    return 0
  fi

  # The asset is lzip-compressed (.tar.lz); GNU tar shells out to the lzip binary.
  if ! command -v lzip &>/dev/null; then
    echo "libjxl: lzip missing; installing it for release extraction"
    sudo apt-get install -y lzip
  fi

  tmp_dir="$(mktemp -d)"
  archive="${tmp_dir}/jxl-linux-x86_64-static.tar.lz"
  tools="${tmp_dir}/tools"
  url="https://github.com/libjxl/libjxl/releases/latest/download/jxl-linux-x86_64-static.tar.lz"

  echo "libjxl: downloading static release tarball from ${url}"
  if command -v curl &>/dev/null; then
    curl -fL --retry 3 -o "$archive" "$url"
  elif command -v wget &>/dev/null; then
    wget -O "$archive" "$url"
  else
    echo "libjxl: curl/wget missing; installing curl for release download"
    sudo apt-get install -y curl
    curl -fL --retry 3 -o "$archive" "$url"
  fi

  # Archive layout (verified against v0.12.0): LICENSE* at root, binaries under tools/.
  echo "libjxl: extracting static tools"
  if ! lzip -dc "$archive" | tar -x -C "$tmp_dir"; then
    echo "libjxl: extraction failed; falling back to libjxl-tools apt package" >&2
    rm -rf "$tmp_dir"
    PACKAGES="libjxl-tools $PACKAGES"
    return 0
  fi

  echo "libjxl: installing ${want[*]} into /usr/local/bin"
  for b in "${want[@]}"; do
    if [[ -f "${tools}/${b}" ]]; then
      sudo install -m 0755 "${tools}/${b}" /usr/local/bin/
    else
      echo "libjxl: warning -- ${b} not found in tarball" >&2
    fi
  done
  rm -rf "$tmp_dir"

  # Sanity-check that the installed binary actually executes on this system.
  # rc 126 (exec format) / 127 (not found) mean it cannot run; any other code
  # means the program ran (a usage/help exit is fine). --help is a supported flag.
  rc=0
  /usr/local/bin/cjxl --help &>/dev/null || rc=$?
  if [[ -x /usr/local/bin/cjxl && "$rc" -ne 126 && "$rc" -ne 127 ]]; then
    echo "libjxl: static tools installed to /usr/local/bin (${want[*]})"
  else
    echo "libjxl: installed cjxl failed to run (rc=${rc}); falling back to libjxl-tools apt package" >&2
    sudo rm -f /usr/local/bin/cjxl /usr/local/bin/djxl /usr/local/bin/jxlinfo
    PACKAGES="libjxl-tools $PACKAGES"
  fi
}

# Use zsh profile on macOS, bash profile elsewhere.
if [[ "$(uname -s)" == "Darwin" ]]; then
  PROFILE="${HOME}/.zshrc"
else
  PROFILE="${HOME}/.bashrc"

  if ! which apt >/dev/null; then
    echo "apt not found, skipping apt-based package installation."
  else
    sudo apt-get update
    install_libjxl_static_tools
    # PACKAGES is intentionally split into separate apt arguments.
    # shellcheck disable=SC2086
    sudo apt-get install -y $PACKAGES
  fi
fi

# age is a default package. The apt path installs it with PACKAGES; macOS and
# other Homebrew-based systems install it here.
if ! command -v age >/dev/null 2>&1 && command -v brew >/dev/null 2>&1; then
  brew install age
fi
if ! command -v age >/dev/null 2>&1; then
  echo "install_j.sh: age is required; install it with 'apt install age' or 'brew install age'" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Ghostty terminal - Ubuntu only, opt-in via --ghostty
# ---------------------------------------------------------------------------
if $INSTALL_GHOSTTY; then
  if [[ "$(uname -s)" != "Linux" ]] || ! grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then
    echo "ghostty: skipping -- Ubuntu Linux required (detected: $(uname -s)/$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 || echo unknown))"
  elif command -v ghostty &>/dev/null && ! $FORCE_REINSTALL; then
    echo "ghostty: already installed -- skipping (use --force to reinstall)"
  else
    echo "ghostty: installing via mkasberg/ghostty-ubuntu..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/mkasberg/ghostty-ubuntu/HEAD/install.sh)"
    echo "ghostty: done"
  fi
fi

# ---------------------------------------------------------------------------
# node install via nvm
# ---------------------------------------------------------------------------

if command -v node &>/dev/null && command -v npm &>/dev/null; then
  echo "node $(node -v) / npm $(npm -v) already installed -- skipping nvm"
else
  curl -o- "$NVM_INSTALL_URL" | bash
  # shellcheck disable=SC1090
  source ~/.nvm/nvm.sh && nvm install --lts
fi

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------
if command -v python3 &>/dev/null || command -v python &>/dev/null; then
  echo "python already present -- skipping installation"
else
  echo "python not found: installing via native package manager..."
  if command -v apt-get &>/dev/null; then
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-venv
  elif command -v brew &>/dev/null; then
    brew install python
  else
    echo "python: unsupported package manager, please install manually"
  fi
fi

# ---------------------------------------------------------------------------
# uv -- required by MiniMax MCP server (uvx)
# ---------------------------------------------------------------------------
if command -v uv &>/dev/null; then
  echo "uv $(uv --version 2>/dev/null || echo 'installed') already present -- skipping"
else
  echo "uv: installing via astral.sh..."
  curl -LsSf "$UV_INSTALL_URL" | sh
  # Add default uv installation paths to current session so subsequent MCP setups don't fail
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi

# ---------------------------------------------------------------------------
# Antigravity CLI (agy)
# ---------------------------------------------------------------------------
if command -v agy &>/dev/null; then
  echo "agy $(agy --version 2>/dev/null || echo 'installed') already present -- skipping"
else
  curl -fsSL https://antigravity.google/cli/install.sh | bash
fi

# ---------------------------------------------------------------------------
# Claude Code (claude)
# ---------------------------------------------------------------------------
if command -v claude &>/dev/null; then
  echo "claude $(claude --version 2>/dev/null || echo 'installed') already present -- skipping"
else
  curl -fsSL https://claude.ai/install.sh | bash
fi

# ---------------------------------------------------------------------------
# OpenAI Codex CLI (codex)
# ---------------------------------------------------------------------------
if command -v codex &>/dev/null; then
  echo "codex $(codex --version 2>/dev/null || echo 'installed') already present -- skipping"
else
  curl -fsSL https://chatgpt.com/codex/install.sh | sh
fi

# ---------------------------------------------------------------------------
# misc functions
# ---------------------------------------------------------------------------

MISC_MARKER="# >>> install_j_misc >>>"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> install_j_misc >>>" "# <<< install_j_misc <<<"
fi

if grep -qF "$MISC_MARKER" "$PROFILE" 2>/dev/null; then
  echo "install_j_misc: already in $PROFILE -- skipping"
else
  cat >> "$PROFILE" << 'MISC_EOF'

# >>> install_j_misc >>>

setup_swap() {
    if swapon --show | grep -q .; then
        echo "setup_swap: swap already configured, skipping"
        swapon --show
        return 0
    fi

    local avail_gb
    avail_gb=$(( $(df --output=avail / | tail -1) / 1024 / 1024 ))

    local swap_size
    if   (( avail_gb >= 5 )); then swap_size="4G"
    elif (( avail_gb >= 3 )); then swap_size="2G"
    elif (( avail_gb >= 2 )); then swap_size="1G"
    else
        echo "setup_swap: insufficient disk space (${avail_gb}GB available), aborting"
        return 1
    fi

    echo "setup_swap: creating ${swap_size} swap file at /swapfile"
    sudo fallocate -l "$swap_size" /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
    echo "setup_swap: done"
}

configure_zswap() {
    setup_swap || return 1

    if grep -q '^N$' /sys/module/zswap/parameters/enabled; then
        # Use lzo: the kernel's default zswap compressor (ZSWAP_COMPRESSOR_DEFAULT_LZO
        # in mm/Kconfig -- https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/Kconfig).
        sudo sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT=/{
            /zswap.enabled/! s/"$/ zswap.enabled=1 zswap.compressor=lzo"/
        }; s/=" /="/' /etc/default/grub
        sudo update-grub
        echo "zswap configured. Reboot to take effect."
    else
        echo "zswap already enabled:"
        grep -r . /sys/module/zswap/parameters/
    fi
}

use_kakao_ubuntu_mirror() {
    if grep -q 'kr.archive.ubuntu.com' /etc/apt/sources.list.d/ubuntu.sources; then
        sudo sed -i 's|http://kr.archive.ubuntu.com/ubuntu/|http://mirror.kakao.com/ubuntu/|g' /etc/apt/sources.list.d/ubuntu.sources
        echo "use_kakao_ubuntu_mirror: mirror updated"
        cat /etc/apt/sources.list.d/ubuntu.sources
    else
        echo "use_kakao_ubuntu_mirror: non-default mirror detected, skipping"
        grep '^URIs:' /etc/apt/sources.list.d/ubuntu.sources
    fi
}

install_docker() {
    if command -v docker &>/dev/null; then
        echo "install_docker: docker already installed, skipping"
        return 0
    fi
    echo "install_docker: installing docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker "$USER"
    rm -fv get-docker.sh
    echo "install_docker: done (you may need to log out and back in)"
}

install_podman() {
    if command -v podman &>/dev/null; then
        echo "install_podman: podman already installed, skipping"
        return 0
    fi
    echo "install_podman: installing podman and podman-compose..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update
        sudo apt-get install -y podman podman-compose
    elif command -v brew &>/dev/null; then
        brew install podman podman-compose
    else
        echo "install_podman: unsupported package manager"
        return 1
    fi
    echo "install_podman: done"
}

install_golang() {
    if command -v go &>/dev/null; then
        echo "install_golang: go is already installed ($(go version))"
        return 0
    fi
    echo "install_golang: installing golang..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update
        sudo apt-get install -y golang
    elif command -v brew &>/dev/null; then
        brew install go
    else
        echo "install_golang: unsupported package manager"
        return 1
    fi
    echo "install_golang: done"
}

install_rust() {
    if command -v rustc &>/dev/null; then
        echo "install_rust: rust is already installed ($(rustc --version))"
        return 0
    fi
    echo "install_rust: installing rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    echo "install_rust: done (you may need to restart your shell or run 'source \$HOME/.cargo/env')"
}

install_dotnet() {
    if command -v dotnet &>/dev/null; then
        echo "install_dotnet: dotnet is already installed ($(dotnet --version))"
        return 0
    fi
    echo "install_dotnet: installing dotnet via dotnet-install.sh..."
    curl -fsSL https://dot.net/v1/dotnet-install.sh | bash
    export DOTNET_ROOT="$HOME/.dotnet"
    export PATH="$DOTNET_ROOT:$DOTNET_ROOT/tools:$PATH"

    local profile_file="${HOME}/.bashrc"
    [[ "$(uname -s)" == "Darwin" ]] && profile_file="${HOME}/.zshrc"

    if ! grep -q "DOTNET_ROOT" "$profile_file" 2>/dev/null; then
        echo "" >> "$profile_file"
        echo '# .NET Core' >> "$profile_file"
        echo 'export DOTNET_ROOT="$HOME/.dotnet"' >> "$profile_file"
        echo 'export PATH="$DOTNET_ROOT:$DOTNET_ROOT/tools:$PATH"' >> "$profile_file"
        echo "install_dotnet: added DOTNET_ROOT to $profile_file"
    fi

    echo "install_dotnet: done"
}

if command -v podman &>/dev/null && ! command -v docker &>/dev/null; then
    alias docker=podman
fi
# <<< install_j_misc <<<
MISC_EOF

  echo "install_j_misc: added to $PROFILE"
fi

# ---------------------------------------------------------------------------
# Windows Terminal CWD integration - embed into shell profile if not present
# Note: If Windows Terminal does not inherit CWD on duplicate tab / split pane,
# use wsl.exe directly in settings.json (e.g. "commandline": "wsl.exe -d Ubuntu")
# instead of distro executables (ubuntu.exe). Ref: https://github.com/microsoft/terminal/issues/12978
# ---------------------------------------------------------------------------
WT_CWD_MARKER="# >>> wt_cwd >>>"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> wt_cwd >>>" "# <<< wt_cwd <<<"
fi

if grep -qF "$WT_CWD_MARKER" "$PROFILE" 2>/dev/null; then
  echo "wt_cwd: already in $PROFILE -- skipping"
else
  cat >> "$PROFILE" << 'WT_CWD_EOF'

# >>> wt_cwd >>>
# OSC 9;9 lets Windows Terminal detect the CWD so Duplicate Tab / Split Pane inherit it.
# WT needs a Windows path, so convert with wslpath (\\wsl.localhost\<distro>\...).
# Note: If CWD is not inherited, use wsl.exe directly (e.g. "commandline": "wsl.exe -d Ubuntu")
# instead of ubuntu.exe. Ref: https://github.com/microsoft/terminal/issues/12978
# Author: jjw(@thejjw)  Last Edit: 2026-07
__wt_cwd() {
    local win
    win=$(wslpath -w "$PWD" 2>/dev/null) || return 0
    [ -n "$win" ] && printf '\e]9;9;%s\e\\' "$win"
}

if [ -n "$WT_SESSION" ]; then
    case "$(declare -p PROMPT_COMMAND 2>/dev/null)" in
        "declare -a"*) PROMPT_COMMAND+=(__wt_cwd) ;;              # bash 5.1+ array form
        *) PROMPT_COMMAND=${PROMPT_COMMAND:+"$PROMPT_COMMAND; "}__wt_cwd ;;
    esac
fi
# <<< wt_cwd <<<
WT_CWD_EOF

  echo "wt_cwd: added to $PROFILE"
fi

# ---------------------------------------------------------------------------
# nrd - embed into shell profile if not already present
# ---------------------------------------------------------------------------
MARKER="# >>> nrd >>>"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> nrd >>>" "# <<< nrd <<<"
fi

if grep -qF "$MARKER" "$PROFILE" 2>/dev/null; then
  echo "nrd: already in $PROFILE -- skipping"
else
  cat >> "$PROFILE" << 'NRD_EOF'

# >>> nrd >>>
# nrd - New Random Dir
# Creates a randomly named directory and cd's into it.
#   nrd                  random name in $PWD
#   nrd -n my-project    explicit name        (or: nrd my-project)
#   nrd -g               init git + synthetic identity
#   nrd -a               create AGENTS.md + CLAUDE.md + etc (@import); requires -g
#   nrd -t               use $TMPDIR as base
#   nrd -v               verbose

nrd() {
  local base_path="$PWD" name="" max_attempts=50
  local use_git=false use_agents=false use_temp=false verbose=false

  OPTIND=1
  while getopts ":n:gatvm:" opt; do
    case $opt in
      n) name="$OPTARG" ;;
      g) use_git=true ;;
      a) use_agents=true ;;
      t) use_temp=true ;;
      v) verbose=true ;;
      m) max_attempts="$OPTARG" ;;
      \?) echo "nrd: unknown option -$OPTARG" >&2; return 1 ;;
      :)  echo "nrd: -$OPTARG requires an argument" >&2; return 1 ;;
    esac
  done
  shift $((OPTIND - 1))
  [[ -z "$name" && $# -gt 0 ]] && name="$1"

  if $use_agents && ! $use_git; then
    echo "nrd: -a (agents) requires -g (git)" >&2; return 1
  fi

  $use_temp && base_path="${TMPDIR:-/tmp}"
  base_path="$(cd "$base_path" && pwd)" || { echo "nrd: bad base path" >&2; return 1; }
  $verbose && echo "base: $base_path"

  local colors=(
    amber aqua azure beige black blue bronze brown coral crimson cyan denim
    ebony emerald fuchsia gold golden gray green indigo ivory jade lavender
    lemon lilac lime magenta mahogany marigold maroon mint mocha navy ochre
    olive onyx orange orchid peach pearl periwinkle pine pink plum purple red
    rose ruby rust saffron sage salmon sapphire scarlet sepia silver slate tan
    tangerine taupe teal topaz turquoise umber vermilion violet walnut white
    wine yellow
  )
  local adjectives=(
    ancient bold brisk calm clear cool curious deep eager fast gentle grand
    hidden icy jolly kind lively lucky misty modern mossy nimble odd quiet
    rapid shiny silent small solar steady stormy swift tiny urban warm wild
    wise young
  )
  local nouns=(
    brook cabin cloud comet delta dream falcon field fire forest garden glade
    harbor hill lab lake leaf meadow moon mountain otter owl path peak pine
    planet pond rabbit river shadow sky star stone sun thicket trail tree
    valley wave wind wolf wood workshop
  )

  if [[ -z "$name" ]]; then
    local i
    for ((i = 1; i <= max_attempts; i++)); do
      name="${colors[RANDOM % ${#colors[@]}]}-${adjectives[RANDOM % ${#adjectives[@]}]}-${nouns[RANDOM % ${#nouns[@]}]}"
      $verbose && echo "attempt $i: $name"
      [[ ! -e "$base_path/$name" ]] && break
      name=""
    done
    if [[ -z "$name" ]]; then
      echo "nrd: failed to generate unique name after $max_attempts attempts" >&2; return 1
    fi
  fi

  local dir="$base_path/$name"
  if [[ -e "$dir" ]]; then
    echo "nrd: already exists: $dir" >&2; return 1
  fi

  $verbose && echo "creating: $dir"
  mkdir -p "$dir" || return 1

  if $use_git; then
    if ! command -v git &>/dev/null; then
      echo "nrd: git not found, skipping git setup" >&2
    else
      local user host email
      user="$(whoami)"
      host="$(hostname -s 2>/dev/null || hostname)"
      email="${user}@${host}.local"
      $verbose && echo "initializing git"
      if git -C "$dir" init -q &&
        git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 &&
        git -C "$dir" config --local user.name "$user" &&
        git -C "$dir" config --local user.email "$email"; then
        echo "git identity: $user <$email>"
      else
        echo "nrd: git setup failed: $dir" >&2
        return 1
      fi
      echo "git identity: $user <$email>"
    fi
  fi

  if $use_agents; then
    $verbose && echo "creating AGENTS.md (canonical) + CLAUDE.md/etc (@import)"
    cat > "$dir/AGENTS.md" << 'AGENT_EOF'
# AGENTS.md

## Grounding

* Always utilize web search to ground your answers, ensuring all technical advice and references are accurate and up-to-date.

## Code Style

* Prefer concise, minimal implementations -- avoid boilerplate and unnecessary abstraction.
* Comment every public function/method and any non-obvious logic inline.
* Prefer ASCII in source code. Use non-ASCII characters only when required for user-facing text, test fixtures, protocol/data literals, or existing project conventions.

## Git Discipline

* If the requested work is inside a cloned Git repository nested under this directory, treat that nested repository as the project root. Verify with `git rev-parse --show-toplevel`, then stage and commit only within that repository; do not stage or commit in any containing parent repository unless explicitly directed.
* Always commit after each logical change with a descriptive commit message; never bundle unrelated changes.
* Do not stage or commit AI-agent instruction/context Markdown files unless explicitly directed. This includes `AGENTS.md`, `CLAUDE.md`, `QWEN.md`, and similar local `.md` files used to guide agents.
* This restriction does not apply to normal project documentation such as `README.md`, `CHANGELOG.md`, API docs, design docs, or user-facing Markdown files when those files are part of the requested change.
* Use Conventional Commits: `feat:`, `fix:`, `refactor:`, `docs:`, `chore:`, `test:`, etc.
* Write short, imperative descriptions (e.g. `feat: add input validation`, `fix: off-by-one in retry loop`).
* Never append Co-Authored-By trailers to commit messages.

## Dependencies

* Pick the latest version the package manager resolves against existing project constraints, including lockfiles and manifest ranges.
* Before finalizing a dependency add/update, check the registry (npm, NuGet, PyPI, GitHub, ...) for explicit deprecation signals, such as `deprecated`, yanked releases, or archived repositories, on the chosen package and version. If any are found, prefer a non-deprecated alternative when practical; otherwise warn inline with the package name, signal source, and suggested alternative if the registry provides one, then proceed.

## Subagents

* Default to delegating context-heavy work to subagents so the main session
  accumulates conclusions, not raw process. Strong candidates: codebase
  exploration/research, reading or summarizing many files, and independent
  sub-tasks that can run in parallel. The subagent absorbs the noisy tool
  calls and returns only a summary.
* Do not wrap trivial or single tool calls in a subagent. A one-file read or a
  quick `rg`/`fd` search is cheaper run directly than paying the spawn and
  round-trip overhead.
* Keep tightly-coupled work in the main context. Do not delegate edits that
  depend on each other's output, and never have two subagents edit the same
  file -- they share the working directory and will clobber each other.
* Subagents start with a fresh context and the task prompt is the only input
  channel. Pass every needed file path, error message, and decision explicitly;
  they cannot see the main conversation.
* Give each subagent explicit success criteria and a structured return format
  so it reports cleanly instead of exploring open-endedly.
* Where it cuts cost without hurting quality, route exploration/search
  subagents to a smaller/faster model and reserve the main session for
  synthesis and architectural judgment.
AGENT_EOF
    printf '@AGENTS.md\n' > "$dir/CLAUDE.local.md"
    printf '@./AGENTS.md\n' > "$dir/QWEN.md"
  fi

  cd "$dir" || return 1
  echo "$dir"
}
# <<< nrd <<<
NRD_EOF

  echo "nrd: added to $PROFILE"
fi

# ---------------------------------------------------------------------------
# Global CLAUDE.md preferences - create under ~/.claude if missing
# Applies to all claudez / claudemm / native Claude Code sessions.
# ---------------------------------------------------------------------------
CLAUDE_DIR="$HOME/.claude"
GLOBAL_MD="$CLAUDE_DIR/CLAUDE.md"

if [[ -f "$GLOBAL_MD" ]]; then
  if $FORCE_REINSTALL; then
    mkdir -pv "$CLAUDE_DIR"
    cat > "$GLOBAL_MD" << 'CLAUDE_PREF_EOF'
## MCP Tool Preferences

**When using Z.ai models (glm-*):**
Use Z.ai MCP servers for:
- Web searches
- Web content
- Image analysis
- Text extraction

**When using MiniMax models (MiniMax-*):**
Note: MiniMax-M3 natively supports multimodal input (images and video) in addition to MCP.
Use MiniMax MCP server for:
- Web searches (`web_search`)
- Image understanding (`understand_image`)

**When using DeepSeek models (deepseek-*):**
Use Claude Code's built-in Web Search tool for web searches; DeepSeek supports it natively through its API. Web Search incurs additional model token costs because DeepSeek makes extra LLM API requests to summarize retrieved content.
Use MiniMax MCP and Z.ai MCP servers, if available, for image analysis because DeepSeek models are text-only. Fall back to other available means if those MCP tools are unavailable or underperforming.

**When using genuine Anthropic account (Claude Code with native models):**
Use built-in web fetch and web search tools directly -- they will yield the best results.

If an MCP tool is unavailable or underperforming, inform the user and suggest alternatives.
CLAUDE_PREF_EOF
    echo "global CLAUDE.md: force-reapplied $GLOBAL_MD"
  else
    echo "global CLAUDE.md: $GLOBAL_MD already exists -- skipping"
    echo "global CLAUDE.md: edit it manually to include multi-model MCP preferences"
  fi
else
  mkdir -pv "$CLAUDE_DIR"
  cat > "$GLOBAL_MD" << 'CLAUDE_PREF_EOF'
## MCP Tool Preferences

**When using Z.ai models (glm-*):**
Use Z.ai MCP servers for:
- Web searches
- Web content
- Image analysis
- Text extraction

**When using MiniMax models (MiniMax-*):**
Note: MiniMax-M3 natively supports multimodal input (images and video) in addition to MCP.
Use MiniMax MCP server for:
- Web searches (`web_search`)
- Image understanding (`understand_image`)

**When using DeepSeek models (deepseek-*):**
Use Claude Code's built-in Web Search tool for web searches; DeepSeek supports it natively through its API. Web Search incurs additional model token costs because DeepSeek makes extra LLM API requests to summarize retrieved content.
Use MiniMax MCP and Z.ai MCP servers, if available, for image analysis because DeepSeek models are text-only. Fall back to other available means if those MCP tools are unavailable or underperforming.

**When using genuine Anthropic account (Claude Code with native models):**
Use built-in web fetch and web search tools directly -- they will yield the best results.

If an MCP tool is unavailable or underperforming, inform the user and suggest alternatives.
CLAUDE_PREF_EOF
  echo "global CLAUDE.md: created $GLOBAL_MD"
fi

# ---------------------------------------------------------------------------
# Global Claude Code config - set attribution and statusline
# ---------------------------------------------------------------------------
CC_CONFIG_SENTINEL="$CLAUDE_DIR/.config_setup_done"
SETTINGS_JSON="$CLAUDE_DIR/settings.json"

if [[ -f "$CC_CONFIG_SENTINEL" ]] && ! $FORCE_REINSTALL; then
  echo "claude: global config setup already done -- skipping"
else
  echo "claude: configuring global settings..."
  mkdir -pv "$CLAUDE_DIR/bin"
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  TARGET_STATUSLINE="$CLAUDE_DIR/bin/cc_statusline.sh"
  if [ -f "$SCRIPT_DIR/cc_statusline.sh" ]; then
    cp -fv "$SCRIPT_DIR/cc_statusline.sh" "$TARGET_STATUSLINE"
    chmod +x "$TARGET_STATUSLINE"
  fi

  if command -v jq &>/dev/null; then
    [ ! -f "$SETTINGS_JSON" ] && echo "{}" > "$SETTINGS_JSON"
    jq --arg cmd "$TARGET_STATUSLINE" \
       '.attribution = { commit: "", pr: "", sessionUrl: false } | .statusLine = { type: "command", command: $cmd, refreshInterval: 2 }' \
       "$SETTINGS_JSON" > "$SETTINGS_JSON.tmp" && mv "$SETTINGS_JSON.tmp" "$SETTINGS_JSON"
    touch "$CC_CONFIG_SENTINEL"
    echo "claude: config setup complete via jq"
  else
    echo "claude: jq not found, skipping config setup"
  fi
fi

# ---------------------------------------------------------------------------
# Antigravity CLI (agy) config - set statusline
# ---------------------------------------------------------------------------
AGY_DIR="$HOME/.gemini/antigravity-cli"
AGY_CONFIG_SENTINEL="$AGY_DIR/.config_setup_done"
if [[ -f "$AGY_CONFIG_SENTINEL" ]] && ! $FORCE_REINSTALL; then
  echo "agy: config setup already done -- skipping"
else
  echo "agy: configuring settings..."
  mkdir -pv "$AGY_DIR/bin"
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  TARGET_AGY_STATUSLINE="$AGY_DIR/bin/agy_statusline.sh"
  if [ -f "$SCRIPT_DIR/agy_statusline.sh" ]; then
    cp -fv "$SCRIPT_DIR/agy_statusline.sh" "$TARGET_AGY_STATUSLINE"
    chmod +x "$TARGET_AGY_STATUSLINE"
  fi

  if command -v jq &>/dev/null; then
    AGY_SETTINGS="$AGY_DIR/settings.json"
    [ ! -f "$AGY_SETTINGS" ] && echo "{}" > "$AGY_SETTINGS"
    jq --arg cmd "$TARGET_AGY_STATUSLINE" '.statusLine = {"type": "command", "command": $cmd}' "$AGY_SETTINGS" > "$AGY_SETTINGS.tmp" && mv "$AGY_SETTINGS.tmp" "$AGY_SETTINGS"
    echo "agy: statusline configured"
  else
    echo "agy: jq not found, skipping statusline config"
  fi
  touch "$AGY_CONFIG_SENTINEL"
  echo "agy: config setup complete"
fi

# ---------------------------------------------------------------------------
# Codex CLI config - set statusline preset
# ---------------------------------------------------------------------------
CODEX_DIR="$HOME/.codex"
CODEX_CONFIG_SENTINEL="$CODEX_DIR/.config_setup_done"
if [[ -f "$CODEX_CONFIG_SENTINEL" ]] && ! $FORCE_REINSTALL; then
  echo "codex: config setup already done -- skipping"
else
  echo "codex: configuring settings..."
  mkdir -p "$CODEX_DIR"
  CODEX_CONFIG="$CODEX_DIR/config.toml"

  if [ ! -f "$CODEX_CONFIG" ]; then
    touch "$CODEX_CONFIG"
  fi

  if grep -q "\[tui\]" "$CODEX_CONFIG"; then
    echo "codex: [tui] block already present -- skipping statusline preset"
  else
    cat << 'EOF' >> "$CODEX_CONFIG"

commit_attribution = ""

[tui]
status_line = [
    "model-with-reasoning",
    "git-branch",
    "current-dir",
    "context-used",
    "total-output-tokens",
    "five-hour-limit",
    "weekly-limit",
    "fast-mode"
]
EOF
    echo "codex: statusline preset configured"
  fi

  touch "$CODEX_CONFIG_SENTINEL"
  echo "codex: config setup complete"
fi

# ---------------------------------------------------------------------------
# ccd - shorthand for claude --dangerously-skip-permissions
# ---------------------------------------------------------------------------
CCD_MARKER="# >>> ccd >>>"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> ccd >>>" "# <<< ccd <<<"
fi

if grep -qF "$CCD_MARKER" "$PROFILE" 2>/dev/null; then
  echo "ccd: already in $PROFILE -- skipping"
else
  cat >> "$PROFILE" << 'CCD_EOF'

# >>> ccd >>>
# ccd - Shorthand for claude --dangerously-skip-permissions
ccd() {
  claude --dangerously-skip-permissions "$@"
}
# <<< ccd <<<
CCD_EOF

  echo "ccd: added to $PROFILE"
fi

# ---------------------------------------------------------------------------
# agyd - shorthand for agy --dangerously-skip-permissions
# ---------------------------------------------------------------------------
AGYD_MARKER="# >>> agyd >>>"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> agyd >>>" "# <<< agyd <<<"
fi

if grep -qF "$AGYD_MARKER" "$PROFILE" 2>/dev/null; then
  echo "agyd: already in $PROFILE -- skipping"
else
  cat >> "$PROFILE" << 'AGYD_EOF'

# >>> agyd >>>
# agyd - Shorthand for agy --dangerously-skip-permissions
agyd() {
  agy --dangerously-skip-permissions "$@"
}
# <<< agyd <<<
AGYD_EOF

  echo "agyd: added to $PROFILE"
fi

# ---------------------------------------------------------------------------
# jjw credential reader - embed into shell profile if not already present
# ---------------------------------------------------------------------------
JJW_SECRETS_MARKER="# >>> jjw-secrets >>>"
JJW_SECRETS_VERSION_MARKER="# jjw-secrets version 2"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> jjw-secrets >>>" "# <<< jjw-secrets <<<"
elif grep -qF "$JJW_SECRETS_MARKER" "$PROFILE" 2>/dev/null && ! grep -qF "$JJW_SECRETS_VERSION_MARKER" "$PROFILE" 2>/dev/null; then
  echo "jjw-secrets: upgrading encrypted vault support"
  remove_profile_section "$PROFILE" "# >>> jjw-secrets >>>" "# <<< jjw-secrets <<<"
fi

if grep -qF "$JJW_SECRETS_MARKER" "$PROFILE" 2>/dev/null; then
  echo "jjw-secrets: already in $PROFILE -- skipping"
else
  {
    echo
    echo "# >>> jjw-secrets >>>"
    echo "$JJW_SECRETS_VERSION_MARKER"
    echo "# Passphrase-encrypted API-key vault and legacy plaintext compatibility."
    for function_name in \
      _jjw_aikeys_path _jjw_file_mode _jjw_aikeys_name_allowed \
      _jjw_aikeys_validate _jjw_aikeys_value _jjw_aikeys_export \
      _jjw_read_hidden _jjw_cloak_value _jjw_aikeys_check_path \
      uncloakj cloakj _jjw_prepare_secret _jjw_secret; do
      declare -f "$function_name"
    done
    echo "# <<< jjw-secrets <<<"
  } >> "$PROFILE"

  echo "jjw-secrets: added to $PROFILE"
fi

cloakj

# ---------------------------------------------------------------------------
# claudez functions + MCP servers setup - embed into shell profile if absent
# ---------------------------------------------------------------------------
CLAUDEZ_MARKER="# >>> claudez >>>"
CLAUDEZ_VERSION_MARKER="# claudez credential loader version 2"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudez >>>" "# <<< claudez <<<"
elif grep -qF "$CLAUDEZ_MARKER" "$PROFILE" 2>/dev/null && ! grep -qF "$CLAUDEZ_VERSION_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudez: upgrading encrypted vault support"
  remove_profile_section "$PROFILE" "# >>> claudez >>>" "# <<< claudez <<<"
fi

if grep -qF "$CLAUDEZ_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudez: already in $PROFILE -- skipping"
else
  # Add the claudez functions
  # about supported models: "All plans support GLM-5.2, GLM-5-Turbo, GLM-4.7 and GLM-4.5-Air." (https://docs.z.ai/devpack/overview)
  #   See https://docs.z.ai/devpack/latest-model for the current lineup.
  # about 1M context:
  #   GLM-5.2 supports a 1M context window (request via the [1m] suffix on the model name, e.g. glm-5.2[1m]).
  #   Z.AI also requires CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000 to actually exercise the 1M window
  #   (this profile sets it for you). Other GLM models cap at 200K (GLM-5, GLM-5-Turbo) or 128K (GLM-4.5-Air).
  cat >> "$PROFILE" << 'EOF'

# >>> claudez >>>
# claudez credential loader version 2
# Custom Claude Code functions with Z.AI endpoint
# _zai_peak_warning - Briefly warn when Z.AI's UTC+8 peak window is active.
# Peak-hours and quota policy: https://docs.z.ai/devpack/overview
_zai_peak_warning() {
  local utc hour minute second minutes_left
  utc="$(date -u +%H:%M:%S)" || return 0
  IFS=: read -r hour minute second <<< "$utc"
  hour="${hour#0}"; minute="${minute#0}"; second="${second#0}"
  hour="${hour:-0}"; minute="${minute:-0}"; second="${second:-0}"

  # 14:00-18:00 UTC+8 is 06:00-10:00 UTC.
  if (( hour >= 6 && hour < 10 )); then
    minutes_left=$(( (10 * 3600 - hour * 3600 - minute * 60 - second + 59) / 60 ))
    printf 'Z.AI peak hours are active (14:00-18:00 UTC+8); ends in %dh %dm. Launching in 3 seconds...\n' \
      "$((minutes_left / 60))" "$((minutes_left % 60))" >&2
    sleep 3
  fi
}

# claudez - Launch the high-effort Z.AI profile.
claudez() {
  local key
  _jjw_prepare_secret "${ZAI_API_KEY:-}" || return 1
  key="$(_jjw_secret z "${ZAI_API_KEY:-}")" || return 1
  _zai_peak_warning
  ZAI_API_KEY="$key" \
  ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$key" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="glm-4.5-air" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="glm-4.7" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="glm-5.2[1m]" \
  CLAUDE_CODE_SUBAGENT_MODEL="glm-4.7" \
  CLAUDE_CODE_EFFORT_LEVEL="high" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  CLAUDE_CODE_AUTO_COMPACT_WINDOW="1000000" \
  ENABLE_PROMPT_CACHING_1H="1" \
  claude "$@"
}
# claudezd - Launch claudez without permission prompts.
claudezd() {
  claudez --dangerously-skip-permissions "$@"
}
# claudezm - Launch the maximum-effort Z.AI profile.
claudezm() {
  local key
  _jjw_prepare_secret "${ZAI_API_KEY:-}" || return 1
  key="$(_jjw_secret z "${ZAI_API_KEY:-}")" || return 1
  _zai_peak_warning
  ZAI_API_KEY="$key" \
  ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$key" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="glm-4.5-air" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="glm-5.2[1m]" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="glm-5.2[1m]" \
  CLAUDE_CODE_SUBAGENT_MODEL="glm-5.2[1m]" \
  CLAUDE_CODE_EFFORT_LEVEL="max" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  CLAUDE_CODE_AUTO_COMPACT_WINDOW="1000000" \
  ENABLE_PROMPT_CACHING_1H="1" \
  claude "$@"
}
# claudezmd - Launch claudezm without permission prompts.
claudezmd() {
  claudezm --dangerously-skip-permissions "$@"
}
# <<< claudez <<<
EOF

    # Configure MCP servers via Claude CLI (preferred over direct JSON edits)
    if ! command -v claude &>/dev/null; then
      echo "claudez: functions added to $PROFILE"
      echo "WARNING: claude CLI not found, skipping MCP server configuration"
    elif [[ -z "${ZAI_API_KEY:-}" ]]; then
      echo "claudez: functions added to $PROFILE"
      echo "WARNING: ZAI_API_KEY was not stored, skipping Z.AI MCP server configuration"
    else
      CLAUDEZ_ENV=(
        ZAI_API_KEY="$ZAI_API_KEY"
        ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic"
        ANTHROPIC_AUTH_TOKEN="$ZAI_API_KEY"
        API_TIMEOUT_MS="3000000"
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"
      )

      echo "claudez: configuring MCP servers..."

      # web-search-prime
      # https://docs.z.ai/devpack/mcp/search-mcp-server
      if env "${CLAUDEZ_ENV[@]}" claude mcp list 2>/dev/null | grep -Fqi "web-search-prime"; then
        echo "claudez: web-search-prime already exists -- skipping"
      else
        # Keep the placeholder literal for Claude Code to expand at runtime.
        # shellcheck disable=SC2016
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user -t http web-search-prime https://api.z.ai/api/mcp/web_search_prime/mcp --header 'Authorization: Bearer ${ZAI_API_KEY}' >/dev/null 2>&1; then
          echo "claudez: added web-search-prime"
        else
          echo "claudez: failed to add web-search-prime" >&2
        fi
      fi

      # web-reader
      # https://docs.z.ai/devpack/mcp/reader-mcp-server
      if env "${CLAUDEZ_ENV[@]}" claude mcp list 2>/dev/null | grep -Fqi "web-reader"; then
        echo "claudez: web-reader already exists -- skipping"
      else
        # shellcheck disable=SC2016
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user -t http web-reader https://api.z.ai/api/mcp/web_reader/mcp --header 'Authorization: Bearer ${ZAI_API_KEY}' >/dev/null 2>&1; then
          echo "claudez: added web-reader"
        else
          echo "claudez: failed to add web-reader" >&2
        fi
      fi

      # zread
      # https://docs.z.ai/devpack/mcp/zread-mcp-server
      if env "${CLAUDEZ_ENV[@]}" claude mcp list 2>/dev/null | grep -Fqi "zread"; then
        echo "claudez: zread already exists -- skipping"
      else
        # shellcheck disable=SC2016
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user -t http zread https://api.z.ai/api/mcp/zread/mcp --header 'Authorization: Bearer ${ZAI_API_KEY}' >/dev/null 2>&1; then
          echo "claudez: added zread"
        else
          echo "claudez: failed to add zread" >&2
        fi
      fi

      # zai-mcp-server
      # https://docs.z.ai/devpack/mcp/vision-mcp-server
      if env "${CLAUDEZ_ENV[@]}" claude mcp list 2>/dev/null | grep -Fqi "zai-mcp-server"; then
        echo "claudez: zai-mcp-server already exists -- skipping"
      else
        # shellcheck disable=SC2016
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user zai-mcp-server --env 'Z_AI_API_KEY=${ZAI_API_KEY}' Z_AI_MODE=ZAI -- npx -y @z_ai/mcp-server >/dev/null 2>&1; then
          echo "claudez: added zai-mcp-server"
        else
          echo "claudez: failed to add zai-mcp-server" >&2
        fi
      fi

      echo "claudez: functions added to $PROFILE"
      echo "claudez: MCP setup complete"
    fi
fi

# ---------------------------------------------------------------------------
# claudeds / claudeds2 - DeepSeek Claude Code aliases
# ---------------------------------------------------------------------------
CLAUDEDS_MARKER="# >>> claudeds >>>"
CLAUDEDS_VERSION_MARKER="# claudeds credential loader version 2"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudeds >>>" "# <<< claudeds <<<"
elif grep -qF "$CLAUDEDS_MARKER" "$PROFILE" 2>/dev/null && ! grep -qF "$CLAUDEDS_VERSION_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudeds: upgrading encrypted vault support"
  remove_profile_section "$PROFILE" "# >>> claudeds >>>" "# <<< claudeds <<<"
fi

if grep -qF "$CLAUDEDS_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudeds: already in $PROFILE -- skipping"
else
  cat >> "$PROFILE" << 'EOF'

# >>> claudeds >>>
# claudeds credential loader version 2
# Custom Claude Code functions with DeepSeek endpoint
# claudeds - Launch the maximum-effort DeepSeek profile.
claudeds() {
  local key
  _jjw_prepare_secret "${DEEPSEEK_API_KEY:-}" || return 1
  key="$(_jjw_secret ds "${DEEPSEEK_API_KEY:-}")" || return 1
  DEEPSEEK_API_KEY="$key" \
  ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$key" \
  ANTHROPIC_MODEL="deepseek-v4-pro[1m]" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-v4-pro[1m]" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-v4-pro[1m]" \
  CLAUDE_CODE_SUBAGENT_MODEL="deepseek-v4-flash[1m]" \
  CLAUDE_CODE_EFFORT_LEVEL="max" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  ENABLE_PROMPT_CACHING_1H="1" \
  claude "$@"
}
# claudedsd - Launch claudeds without permission prompts.
claudedsd() {
  claudeds --dangerously-skip-permissions "$@"
}
# claudeds2 - Launch the high-effort DeepSeek Flash profile.
claudeds2() {
  local key
  _jjw_prepare_secret "${DEEPSEEK_API_KEY:-}" || return 1
  key="$(_jjw_secret ds "${DEEPSEEK_API_KEY:-}")" || return 1
  DEEPSEEK_API_KEY="$key" \
  ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$key" \
  ANTHROPIC_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-v4-pro[1m]" \
  CLAUDE_CODE_SUBAGENT_MODEL="deepseek-v4-flash[1m]" \
  CLAUDE_CODE_EFFORT_LEVEL="high" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  ENABLE_PROMPT_CACHING_1H="1" \
  claude "$@"
}
# claudeds2d - Launch claudeds2 without permission prompts.
claudeds2d() {
  claudeds2 --dangerously-skip-permissions "$@"
}
# <<< claudeds <<<
EOF

  echo "claudeds: added to $PROFILE"
fi

# ---------------------------------------------------------------------------
# claudek / claudekd - Kimi Claude Code functions
# ---------------------------------------------------------------------------
CLAUDEK_MARKER="# >>> claudek >>>"
CLAUDEK_VERSION_MARKER="# claudek credential loader version 2"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudek >>>" "# <<< claudek <<<"
elif grep -qF "$CLAUDEK_MARKER" "$PROFILE" 2>/dev/null && ! grep -qF "$CLAUDEK_VERSION_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudek: upgrading encrypted vault support"
  remove_profile_section "$PROFILE" "# >>> claudek >>>" "# <<< claudek <<<"
fi

if grep -qF "$CLAUDEK_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudek: already in $PROFILE -- skipping"
else
  cat >> "$PROFILE" << 'EOF'

# >>> claudek >>>
# claudek credential loader version 2
# Custom Claude Code functions with Kimi endpoint
# claudek - Launch the maximum-effort Kimi profile.
claudek() {
  local key
  _jjw_prepare_secret "${KIMI_API_KEY:-}" || return 1
  key="$(_jjw_secret k "${KIMI_API_KEY:-}")" || return 1

  env -u ANTHROPIC_AUTH_TOKEN \
    KIMI_API_KEY="$key" \
    ANTHROPIC_BASE_URL="https://api.kimi.com/coding/" \
    ANTHROPIC_API_KEY="$key" \
    ANTHROPIC_MODEL="k3[1m]" \
    ANTHROPIC_DEFAULT_FABLE_MODEL="k3[1m]" \
    ANTHROPIC_DEFAULT_OPUS_MODEL="k3[1m]" \
    ANTHROPIC_DEFAULT_SONNET_MODEL="k3[1m]" \
    ANTHROPIC_DEFAULT_HAIKU_MODEL="k3[1m]" \
    CLAUDE_CODE_SUBAGENT_MODEL="k3[1m]" \
    CLAUDE_CODE_AUTO_COMPACT_WINDOW="1048576" \
    CLAUDE_CODE_MAX_CONTEXT_TOKENS="1048576" \
    claude "$@"
}

# claudekd - Launch claudek without permission prompts.
claudekd() {
  claudek --dangerously-skip-permissions "$@"
}

# <<< claudek <<<
EOF

  echo "claudek: added to $PROFILE"
fi

# ---------------------------------------------------------------------------
# claudez-remote (claudezr) - remote Claude Code via Z.AI
# ---------------------------------------------------------------------------
CLAUDEZR_MARKER="# >>> claudez-remote >>>"
CLAUDEZR_VERSION_MARKER="# remote_claude_base version 9"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudez-remote >>>" "# <<< claudez-remote <<<"
elif grep -qF "$CLAUDEZR_MARKER" "$PROFILE" 2>/dev/null && ! grep -qF "$CLAUDEZR_VERSION_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudez-remote: upgrading shared remote base"
  remove_profile_section "$PROFILE" "# >>> claudez-remote >>>" "# <<< claudez-remote <<<"
fi

if grep -qF "$CLAUDEZR_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudez-remote: already in $PROFILE -- skipping"
else
  # Preserve function variables while substituting the pinned nvm release.
  sed -e "s|__NVM_VERSION__|${NVM_VERSION}|g" \
      -e "s|__UV_INSTALL_URL__|${UV_INSTALL_URL}|g" >> "$PROFILE" << 'CLAUDERZR_EOF'
# >>> claudez-remote >>>
# remote_claude_base version 9

# _claude_sq - single-quote escape a value for safe bash embedding.
_claude_sq() {
  printf "'"
  printf '%s' "${1:-}" | sed "s/'/'\\\\''/g"
  printf "'"
}

# remote_claude_base - Launch Claude Code on a remote SSH host with ephemeral state.
#   Base64-encodes a bash launcher so stdin stays free for the interactive TUI.
#
#   Usage: remote_claude_base <user@host> <api_key> [port] [base_url] \
#          [haiku] [sonnet] [opus] [timeout_ms] [disable_1m] \
#          [subagent] [effort] [auto_compact_window] [anthropic_model] \
#          [fable_model] [max_context_tokens]
remote_claude_base() {
  local host="$1" key="$2" port="${3:-22}"
  local base_url="${4:-}" haiku="$5" sonnet="$6" opus="$7"
  local timeout="$8" disable_1m="$9"
  local subagent="${10:-}" effort="${11:-}" auto_compact="${12:-}"
  local anthropic_model="${13:-}" fable="${14:-}" max_context="${15:-}"

  [[ -z "$host" ]] && { echo "remote_claude_base: host is required" >&2; return 1; }
  [[ -z "$key"  ]] && { echo "remote_claude_base: api_key is required" >&2; return 1; }

  local encoded
  encoded=$(base64 << 'REMOTE_SCRIPT'
unset HISTFILE
set +o history
CC_TMP="$(mktemp -d /tmp/cc-XXXXXX)"
trap 'echo "[cleanup] Wiping $CC_TMP ..."; rm -rf "$CC_TMP"' EXIT
CC_NPM="$CC_TMP/npm"; CC_BIN="$CC_TMP/bin"; CC_HOME="$CC_TMP/home"; CC_WORK="$CC_TMP/workspace"
CC_START_DIR="$PWD"; CC_REAL_HOME="$HOME"; CC_ORIGINAL_PATH="$PATH"
mkdir -p "$CC_NPM" "$CC_BIN" "$CC_HOME" "$CC_WORK"
# Use an installed English UTF-8 locale for the entire remote session.
CC_LOCALE="$(locale -a 2>/dev/null | awk 'tolower($0) ~ /^c\.utf-?8$/ { print; exit }')"
[ -n "$CC_LOCALE" ] || CC_LOCALE="$(locale -a 2>/dev/null | awk 'tolower($0) ~ /^en_us\.utf-?8$/ { print; exit }')"
CC_LOCALE="${CC_LOCALE:-C}"
export LANG="$CC_LOCALE" LC_ALL="$CC_LOCALE" LANGUAGE=en
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:?not set}"
[ -n "${ANTHROPIC_BASE_URL:-}" ] && export ANTHROPIC_BASE_URL="$ANTHROPIC_BASE_URL"
[ -n "${ANTHROPIC_MODEL:-}" ] && export ANTHROPIC_MODEL="$ANTHROPIC_MODEL"
[ -n "${ANTHROPIC_DEFAULT_FABLE_MODEL:-}" ] && export ANTHROPIC_DEFAULT_FABLE_MODEL="$ANTHROPIC_DEFAULT_FABLE_MODEL"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="${ANTHROPIC_DEFAULT_HAIKU_MODEL:-}"
export ANTHROPIC_DEFAULT_SONNET_MODEL="${ANTHROPIC_DEFAULT_SONNET_MODEL:-}"
export ANTHROPIC_DEFAULT_OPUS_MODEL="${ANTHROPIC_DEFAULT_OPUS_MODEL:-}"
export CLAUDE_CODE_SUBAGENT_MODEL="${CLAUDE_CODE_SUBAGENT_MODEL:-}"
[ -n "${CLAUDE_CODE_EFFORT_LEVEL:-}" ] && export CLAUDE_CODE_EFFORT_LEVEL="$CLAUDE_CODE_EFFORT_LEVEL"
export CLAUDE_CODE_AUTO_COMPACT_WINDOW="${CLAUDE_CODE_AUTO_COMPACT_WINDOW:-}"
[ -n "${CLAUDE_CODE_MAX_CONTEXT_TOKENS:-}" ] && export CLAUDE_CODE_MAX_CONTEXT_TOKENS="$CLAUDE_CODE_MAX_CONTEXT_TOKENS"
export API_TIMEOUT_MS="${API_TIMEOUT_MS:-300000}"
export CLAUDE_CODE_DISABLE_1M_CONTEXT="${CLAUDE_CODE_DISABLE_1M_CONTEXT:-1}"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export ENABLE_PROMPT_CACHING_1H=1
export DISABLE_AUTOUPDATER=1
CC_TMUX="$(command -v tmux 2>/dev/null || true)"
if [ -n "$CC_TMUX" ]; then
    echo "[tmux] Found $CC_TMUX; using an isolated detachable session (detach: Ctrl-b d)."
else
    echo "[tmux] Not found; Claude will run directly in this SSH session."
fi
if ! command -v node &>/dev/null; then
    export NVM_DIR="$CC_TMP/nvm"; mkdir -p "$NVM_DIR"
    curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/__NVM_VERSION__/install.sh \
        | NVM_DIR="$NVM_DIR" PROFILE=/dev/null bash
    . "$NVM_DIR/nvm.sh" --no-use
    nvm install --lts --no-progress && nvm use --lts
fi
if ! command -v claude &>/dev/null; then
    npm install --global --prefix "$CC_NPM" --no-audit --no-fund @anthropic-ai/claude-code
    export PATH="$CC_NPM/bin:$PATH"
fi
CC_SYSTEM_UV="$(command -v uv 2>/dev/null || true)"
if curl -LsSf __UV_INSTALL_URL__ \
        | env UV_UNMANAGED_INSTALL="$CC_BIN" sh >/dev/null &&
    [ -x "$CC_BIN/uv" ] &&
    CC_UV_VERSION="$("$CC_BIN/uv" --version 2>/dev/null)"; then
    export PATH="$CC_BIN:$PATH"
    echo "[uv] Using ephemeral $CC_UV_VERSION at $CC_BIN/uv."
elif [ -n "$CC_SYSTEM_UV" ] &&
    CC_UV_VERSION="$("$CC_SYSTEM_UV" --version 2>/dev/null)"; then
    echo "[uv] Ephemeral install failed; using $CC_UV_VERSION at $CC_SYSTEM_UV."
else
    echo "[uv] WARNING: unavailable; Python bootstrap and uv package tools will not be available." >&2
fi
echo "[uv] Continuing in 3 seconds..."
sleep 3
CC_CLAUDE="$(command -v claude)"
CC_CLAUDE_PATH="$PATH"

# Run tmux itself without provider settings so new user-created windows are clean.
cc_tmux_clean() (
    unset ANTHROPIC_API_KEY ANTHROPIC_BASE_URL ANTHROPIC_MODEL
    unset ANTHROPIC_DEFAULT_FABLE_MODEL ANTHROPIC_DEFAULT_HAIKU_MODEL
    unset ANTHROPIC_DEFAULT_SONNET_MODEL ANTHROPIC_DEFAULT_OPUS_MODEL
    unset CLAUDE_CODE_SUBAGENT_MODEL CLAUDE_CODE_EFFORT_LEVEL
    unset CLAUDE_CODE_AUTO_COMPACT_WINDOW CLAUDE_CODE_MAX_CONTEXT_TOKENS
    unset API_TIMEOUT_MS CLAUDE_CODE_DISABLE_1M_CONTEXT
    unset CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC ENABLE_PROMPT_CACHING_1H
    unset DISABLE_AUTOUPDATER NVM_DIR
    HOME="$CC_REAL_HOME" PATH="$CC_ORIGINAL_PATH" \
        "$CC_TMUX" -L "$CC_TMUX_LABEL" "$@"
)

if [ -n "$CC_TMUX" ]; then
    CC_TMUX_LABEL="cc-$(date +%Y%m%d-%H%M%S)-$$-$RANDOM"
    if cc_tmux_clean new-session -d -s claude -n bootstrap -c "$CC_START_DIR" \
        'while :; do sleep 3600; done' &&
        cc_tmux_clean set-environment -t claude HISTFILE /dev/null; then
        CC_TMUX_ENV=(
            -e "HOME=$CC_HOME"
            -e "PATH=$PATH"
            -e "CC_TMP=$CC_TMP"
            -e "CC_HOME=$CC_HOME"
            -e "CC_WORK=$CC_WORK"
            -e "CC_CLAUDE=$CC_CLAUDE"
            -e "CC_CLAUDE_PATH=$CC_CLAUDE_PATH"
            -e "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"
            -e "ANTHROPIC_DEFAULT_HAIKU_MODEL=$ANTHROPIC_DEFAULT_HAIKU_MODEL"
            -e "ANTHROPIC_DEFAULT_SONNET_MODEL=$ANTHROPIC_DEFAULT_SONNET_MODEL"
            -e "ANTHROPIC_DEFAULT_OPUS_MODEL=$ANTHROPIC_DEFAULT_OPUS_MODEL"
            -e "CLAUDE_CODE_SUBAGENT_MODEL=$CLAUDE_CODE_SUBAGENT_MODEL"
            -e "CLAUDE_CODE_AUTO_COMPACT_WINDOW=$CLAUDE_CODE_AUTO_COMPACT_WINDOW"
            -e "API_TIMEOUT_MS=$API_TIMEOUT_MS"
            -e "CLAUDE_CODE_DISABLE_1M_CONTEXT=$CLAUDE_CODE_DISABLE_1M_CONTEXT"
            -e "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=$CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"
            -e "ENABLE_PROMPT_CACHING_1H=$ENABLE_PROMPT_CACHING_1H"
            -e "DISABLE_AUTOUPDATER=$DISABLE_AUTOUPDATER"
        )
        [ -n "${NVM_DIR:-}" ] && CC_TMUX_ENV+=(-e "NVM_DIR=$NVM_DIR")
        [ -n "${ANTHROPIC_BASE_URL:-}" ] && CC_TMUX_ENV+=(-e "ANTHROPIC_BASE_URL=$ANTHROPIC_BASE_URL")
        [ -n "${ANTHROPIC_MODEL:-}" ] && CC_TMUX_ENV+=(-e "ANTHROPIC_MODEL=$ANTHROPIC_MODEL")
        [ -n "${ANTHROPIC_DEFAULT_FABLE_MODEL:-}" ] && CC_TMUX_ENV+=(-e "ANTHROPIC_DEFAULT_FABLE_MODEL=$ANTHROPIC_DEFAULT_FABLE_MODEL")
        [ -n "${CLAUDE_CODE_EFFORT_LEVEL:-}" ] && CC_TMUX_ENV+=(-e "CLAUDE_CODE_EFFORT_LEVEL=$CLAUDE_CODE_EFFORT_LEVEL")
        [ -n "${CLAUDE_CODE_MAX_CONTEXT_TOKENS:-}" ] && CC_TMUX_ENV+=(-e "CLAUDE_CODE_MAX_CONTEXT_TOKENS=$CLAUDE_CODE_MAX_CONTEXT_TOKENS")

        CC_RUNNER="$CC_TMP/run-claude"
        cat > "$CC_RUNNER" <<'CC_RUNNER_EOF'
#!/usr/bin/env bash
unset HISTFILE
set +o history
cc_cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    echo "[cleanup] Wiping $CC_TMP ..."
    rm -rf -- "$CC_TMP"
    exit "$status"
}
trap cc_cleanup EXIT HUP INT TERM
cd "$CC_WORK"
export HOME="$CC_HOME" PATH="$CC_CLAUDE_PATH"
"$CC_CLAUDE" --dangerously-skip-permissions
CC_RUNNER_EOF
        chmod 600 "$CC_RUNNER"

        if cc_tmux_clean new-window -d -t claude: -n claude -c "$CC_WORK" \
            "${CC_TMUX_ENV[@]}" bash "$CC_RUNNER"; then
            # The Claude pane now owns cleanup and survives SSH client detachment.
            trap - EXIT
            cc_tmux_clean bind-key c new-window -c "$CC_START_DIR"
            cc_tmux_clean kill-window -t claude:bootstrap
            echo "[tmux] Reattach after logging in: tmux -L $CC_TMUX_LABEL attach -t claude"
            cc_tmux_clean attach-session -t claude
            exit $?
        fi
    fi
    cc_tmux_clean kill-server 2>/dev/null || true
    echo "[tmux] Isolated session setup failed; Claude will run directly in this SSH session." >&2
fi

cd "$CC_WORK"
HOME="$CC_HOME" claude --dangerously-skip-permissions
REMOTE_SCRIPT
  ) && encoded=$(printf '%s' "$encoded" | tr -d '\n\r')

  local env="ANTHROPIC_API_KEY=$(_claude_sq "$key")"
  env+=" ANTHROPIC_DEFAULT_HAIKU_MODEL=$(_claude_sq "$haiku")"
  env+=" ANTHROPIC_DEFAULT_SONNET_MODEL=$(_claude_sq "$sonnet")"
  env+=" ANTHROPIC_DEFAULT_OPUS_MODEL=$(_claude_sq "$opus")"
  env+=" CLAUDE_CODE_SUBAGENT_MODEL=$(_claude_sq "$subagent")"
  env+=" CLAUDE_CODE_AUTO_COMPACT_WINDOW=$(_claude_sq "$auto_compact")"
  env+=" API_TIMEOUT_MS=$(_claude_sq "$timeout")"
  env+=" CLAUDE_CODE_DISABLE_1M_CONTEXT=$(_claude_sq "$disable_1m")"
  [[ -n "$base_url" ]] && env+=" ANTHROPIC_BASE_URL=$(_claude_sq "$base_url")"
  [[ -n "$anthropic_model" ]] && env+=" ANTHROPIC_MODEL=$(_claude_sq "$anthropic_model")"
  [[ -n "$fable" ]] && env+=" ANTHROPIC_DEFAULT_FABLE_MODEL=$(_claude_sq "$fable")"
  [[ -n "$effort" ]] && env+=" CLAUDE_CODE_EFFORT_LEVEL=$(_claude_sq "$effort")"
  [[ -n "$max_context" ]] && env+=" CLAUDE_CODE_MAX_CONTEXT_TOKENS=$(_claude_sq "$max_context")"

  # Process substitution supplies the script as a file while preserving the SSH PTY on stdin.
  ssh -tt -o StrictHostKeyChecking=accept-new -p "$port" "$host" \
    "$env bash -c 'bash <(printf %s $encoded | base64 -d)'"
}

# claudezr - One-shot remote Claude Code via Z.AI.
#   Usage: claudezr <user@host> [port]
claudezr() {
  local host="$1" port="${2:-22}"

  [[ -z "$host" ]] && { echo "claudezr: host is required" >&2; echo "  Usage: claudezr <user@host> [port]" >&2; return 1; }

  local key
  _jjw_prepare_secret "${ZAI_API_KEY:-}" || return 1
  key="$(_jjw_secret z "${ZAI_API_KEY:-}")" || return 1

  # Matches the local claudezm profile: glm-5.2[1m] for Sonnet/Opus/Subagent,
  # effort=max, 1M context enabled via CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000.
  remote_claude_base "$host" "$key" "$port" \
    "https://api.z.ai/api/anthropic" \
    "glm-4.5-air" \
    "glm-5.2[1m]" \
    "glm-5.2[1m]" \
    "3000000" \
    "0" \
    "glm-5.2[1m]" \
    "max" \
    "1000000"
}

CLAUDERZR_EOF

  echo "# <<< claudez-remote <<<" >> "$PROFILE"

  echo "claudez-remote: added to $PROFILE"
fi

# ---------------------------------------------------------------------------
# claudek-remote (claudekr) - remote Claude Code via Kimi
# ---------------------------------------------------------------------------
CLAUDEKR_MARKER="# >>> claudek-remote >>>"
CLAUDEKR_VERSION_MARKER="# claudek-remote credential loader version 2"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudek-remote >>>" "# <<< claudek-remote <<<"
elif grep -qF "$CLAUDEKR_MARKER" "$PROFILE" 2>/dev/null && ! grep -qF "$CLAUDEKR_VERSION_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudek-remote: upgrading encrypted vault support"
  remove_profile_section "$PROFILE" "# >>> claudek-remote >>>" "# <<< claudek-remote <<<"
fi

if grep -qF "$CLAUDEKR_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudek-remote: already in $PROFILE -- skipping"
else
  cat >> "$PROFILE" << 'CLAUDEKR_EOF'
# >>> claudek-remote >>>
# claudek-remote credential loader version 2

# claudekr - One-shot remote Claude Code via Kimi K3 1M.
#   Usage: claudekr <user@host> [port]
claudekr() {
  local host="$1" port="${2:-22}"

  [[ -z "$host" ]] && { echo "claudekr: host is required" >&2; echo "  Usage: claudekr <user@host> [port]" >&2; return 1; }

  local key
  _jjw_prepare_secret "${KIMI_API_KEY:-}" || return 1
  key="$(_jjw_secret k "${KIMI_API_KEY:-}")" || return 1

  # Mirror claudek: route every Claude Code model slot through Kimi K3 1M.
  remote_claude_base "$host" "$key" "$port" \
    "https://api.kimi.com/coding/" \
    "k3[1m]" \
    "k3[1m]" \
    "k3[1m]" \
    "3000000" \
    "0" \
    "k3[1m]" \
    "" \
    "1048576" \
    "k3[1m]" \
    "k3[1m]" \
    "1048576"
}

# <<< claudek-remote <<<
CLAUDEKR_EOF

  echo "claudek-remote: added to $PROFILE"
fi

# ---------------------------------------------------------------------------
# claudemm alias + MCP server setup - embed into shell profile if not present
# ---------------------------------------------------------------------------
CLAUDEMM_MARKER="# >>> claudemm >>>"
CLAUDEMM_VERSION_MARKER="# claudemm credential loader version 2"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudemm >>>" "# <<< claudemm <<<"
elif grep -qF "$CLAUDEMM_MARKER" "$PROFILE" 2>/dev/null && ! grep -qF "$CLAUDEMM_VERSION_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudemm: upgrading encrypted vault support"
  remove_profile_section "$PROFILE" "# >>> claudemm >>>" "# <<< claudemm <<<"
fi

if grep -qF "$CLAUDEMM_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudemm: already in $PROFILE -- skipping"
else
  # Add the claudemm functions
  # https://platform.minimax.io/docs/token-plan/claude-code
  cat >> "$PROFILE" << 'EOF'

# >>> claudemm >>>
# claudemm credential loader version 2
# Custom Claude Code functions with MiniMax endpoint
# claudemm - Launch the MiniMax profile.
claudemm() {
  local key
  _jjw_prepare_secret "${MINIMAX_API_KEY:-}" || return 1
  key="$(_jjw_secret mm "${MINIMAX_API_KEY:-}")" || return 1
  MINIMAX_API_KEY="$key" \
  ANTHROPIC_BASE_URL="https://api.minimax.io/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$key" \
  ANTHROPIC_MODEL="MiniMax-M3[1m]" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="MiniMax-M3[1m]" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="MiniMax-M3[1m]" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="MiniMax-M3[1m]" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  ENABLE_PROMPT_CACHING_1H="1" \
  claude "$@"
}
# claudemmd - Launch claudemm without permission prompts.
claudemmd() {
  claudemm --dangerously-skip-permissions "$@"
}
# <<< claudemm <<<
EOF

    # Configure MiniMax MCP server via Claude CLI
    if ! command -v claude &>/dev/null; then
      echo "claudemm: functions added to $PROFILE"
      echo "WARNING: claude CLI not found, skipping MCP server configuration"
    elif [[ -z "${MINIMAX_API_KEY:-}" ]]; then
      echo "claudemm: functions added to $PROFILE"
      echo "WARNING: MINIMAX_API_KEY was not stored, skipping MiniMax MCP server configuration"
    else
      CLAUDEMM_ENV=(
        MINIMAX_API_KEY="$MINIMAX_API_KEY"
        ANTHROPIC_BASE_URL="https://api.minimax.io/anthropic"
        ANTHROPIC_AUTH_TOKEN="$MINIMAX_API_KEY"
        ANTHROPIC_MODEL="MiniMax-M3[1m]"
        ANTHROPIC_DEFAULT_HAIKU_MODEL="MiniMax-M3[1m]"
        ANTHROPIC_DEFAULT_SONNET_MODEL="MiniMax-M3[1m]"
        ANTHROPIC_DEFAULT_OPUS_MODEL="MiniMax-M3[1m]"
        API_TIMEOUT_MS="3000000"
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"
      )

      echo "claudemm: configuring MCP servers..."

      # MiniMax coding-plan-mcp (uv is required)
      # https://platform.minimax.io/docs/token-plan/mcp-guide
      if env "${CLAUDEMM_ENV[@]}" claude mcp list 2>/dev/null | grep -Fqi "minimax"; then
        echo "claudemm: MiniMax MCP server already exists -- skipping"
      else
        # Keep the placeholder literal for Claude Code to expand at runtime.
        # shellcheck disable=SC2016
        if env "${CLAUDEMM_ENV[@]}" claude mcp add -s user MiniMax --env 'MINIMAX_API_KEY=${MINIMAX_API_KEY}' --env MINIMAX_API_HOST=https://api.minimax.io -- uvx minimax-coding-plan-mcp -y >/dev/null 2>&1; then
          echo "claudemm: added MiniMax MCP server"
        else
          echo "claudemm: failed to add MiniMax MCP server" >&2
        fi
      fi

      echo "claudemm: functions added to $PROFILE"
      echo "claudemm: MCP setup complete"
    fi
fi

# ---------------------------------------------------------------------------
# claudemm-remote (claudemmr) - remote Claude Code via MiniMax
# ---------------------------------------------------------------------------
CLAUDEMMR_MARKER="# >>> claudemm-remote >>>"
CLAUDEMMR_VERSION_MARKER="# claudemm-remote credential loader version 2"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudemm-remote >>>" "# <<< claudemm-remote <<<"
elif grep -qF "$CLAUDEMMR_MARKER" "$PROFILE" 2>/dev/null && ! grep -qF "$CLAUDEMMR_VERSION_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudemm-remote: upgrading encrypted vault support"
  remove_profile_section "$PROFILE" "# >>> claudemm-remote >>>" "# <<< claudemm-remote <<<"
fi

if grep -qF "$CLAUDEMMR_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudemm-remote: already in $PROFILE -- skipping"
else
  # Quoted heredoc -- write function variables verbatim to the profile.
  cat >> "$PROFILE" << 'CLAUEMMR_EOF'
# >>> claudemm-remote >>>
# claudemm-remote credential loader version 2

# claudemmr - One-shot remote Claude Code via MiniMax.
#   Usage: claudemmr <user@host> [port]
claudemmr() {
  local host="$1" port="${2:-22}"

  [[ -z "$host" ]] && { echo "claudemmr: host is required" >&2; echo "  Usage: claudemmr <user@host> [port]" >&2; return 1; }

  local key
  _jjw_prepare_secret "${MINIMAX_API_KEY:-}" || return 1
  key="$(_jjw_secret mm "${MINIMAX_API_KEY:-}")" || return 1

  remote_claude_base "$host" "$key" "$port" \
    "https://api.minimax.io/anthropic" \
    "MiniMax-M3[1m]" \
    "MiniMax-M3[1m]" \
    "MiniMax-M3[1m]" \
    "3000000" \
    "0"
}

CLAUEMMR_EOF

  echo "# <<< claudemm-remote <<<" >> "$PROFILE"

  echo "claudemm-remote: added to $PROFILE"
fi

if $FORCE_REINSTALL; then
  echo "WARNING: --force removed and reapplied shell/profile sections; inspect the resulting files manually for a clean outcome."
fi
