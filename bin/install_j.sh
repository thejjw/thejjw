#!/bin/bash
# ---------------------------------------------------------------------------
# One-shot environment bootstrap
# Installs packages, nvm/node, and embeds functions into ~/.bashrc.
# ---------------------------------------------------------------------------
# 2026.4-2026.5 @thejjw

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

PACKAGES="tmux build-essential git cmatrix fonts-noto-cjk curl wget ripgrep jq parallel zstd xz-utils webp btop bubblewrap socat fd-find fzf"
NVM_VERSION="v0.40.4"
NVM_INSTALL_URL="https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh"

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

# Install official libjxl release debs on supported amd64 Debian/Ubuntu systems.
install_libjxl_release_debs() {
  local arch os_id os_version os_codename asset_name asset_url tmp_dir archive deb_dir extracted_count
  local -a installed_libjxl_packages
  local cjxl_present=false

  echo "libjxl: checking for official GitHub release deb support..."

  arch="$(dpkg --print-architecture 2>/dev/null || uname -m)"
  if command -v cjxl &>/dev/null; then
    cjxl_present=true
    echo "libjxl: cjxl found at $(command -v cjxl)"
  else
    echo "libjxl: cjxl not found"
  fi

  if [[ "$arch" != "amd64" ]]; then
    echo "libjxl: unsupported architecture '$arch' for official deb assets"
    if ! $cjxl_present; then
      PACKAGES="libjxl-tools $PACKAGES"
      echo "libjxl: added libjxl-tools back to apt package list"
    fi
    return 0
  fi

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
  fi

  os_id="${ID:-unknown}"
  os_version="${VERSION_ID:-unknown}"
  os_codename="${VERSION_CODENAME:-unknown}"

  case "${os_id}:${os_version}:${os_codename}" in
    debian:*:bookworm) asset_name="jxl-debs-amd64-debian-bookworm.zip" ;;
    debian:*:trixie) asset_name="jxl-debs-amd64-debian-trixie.zip" ;;
    ubuntu:22.04:*) asset_name="jxl-debs-amd64-ubuntu-22.04.zip" ;;
    ubuntu:24.04:*) asset_name="jxl-debs-amd64-ubuntu-24.04.zip" ;;
    *)
      echo "libjxl: unsupported distribution '${os_id}' version '${os_version}' codename '${os_codename}'"
      if ! $cjxl_present; then
        PACKAGES="libjxl-tools $PACKAGES"
        echo "libjxl: added libjxl-tools back to apt package list"
      fi
      return 0
      ;;
  esac

  echo "libjxl: supported system detected; using release asset ${asset_name}"

  tmp_dir="$(mktemp -d)"
  archive="${tmp_dir}/${asset_name}"
  deb_dir="${tmp_dir}/debs"
  mkdir -p "$deb_dir"

  asset_url="https://github.com/libjxl/libjxl/releases/latest/download/${asset_name}"
  echo "libjxl: downloading latest release asset from ${asset_url}"
  if command -v curl &>/dev/null; then
    curl -fL --retry 3 -o "$archive" "$asset_url"
  elif command -v wget &>/dev/null; then
    wget -O "$archive" "$asset_url"
  else
    echo "libjxl: curl/wget missing; installing curl for release download"
    sudo apt-get install -y curl
    curl -fL --retry 3 -o "$archive" "$asset_url"
  fi

  echo "libjxl: extracting only jxl_*.deb and libjxl_*.deb"
  if command -v python3 &>/dev/null; then
    extracted_count="$(python3 - "$archive" "$deb_dir" << 'PY'
import fnmatch
import os
import sys
import zipfile

archive, deb_dir = sys.argv[1], sys.argv[2]
count = 0
with zipfile.ZipFile(archive) as zf:
    for member in zf.infolist():
        name = os.path.basename(member.filename)
        if not name:
            continue
        if fnmatch.fnmatch(name, "jxl_*.deb") or fnmatch.fnmatch(name, "libjxl_*.deb"):
            with zf.open(member) as src, open(os.path.join(deb_dir, name), "wb") as dst:
                dst.write(src.read())
            count += 1
print(count)
PY
)"
  else
    if ! command -v unzip &>/dev/null; then
      echo "libjxl: python3/unzip missing; installing unzip for release extraction"
      sudo apt-get install -y unzip
    fi
    unzip -j "$archive" 'jxl_*.deb' '*/jxl_*.deb' 'libjxl_*.deb' '*/libjxl_*.deb' -d "$deb_dir"
    extracted_count="$(find "$deb_dir" -maxdepth 1 -type f -name '*.deb' | wc -l)"
  fi
  echo "libjxl: extracted ${extracted_count//[[:space:]]/} matching deb packages"

  if ! compgen -G "${deb_dir}/jxl_*.deb" >/dev/null || ! compgen -G "${deb_dir}/libjxl_*.deb" >/dev/null; then
    echo "libjxl: expected jxl_*.deb and libjxl_*.deb files were not found in ${asset_name}" >&2
    rm -rf "$tmp_dir"
    return 1
  fi

  # Download/extract first so a transient network failure does not remove a working cjxl.
  if $cjxl_present; then
    mapfile -t installed_libjxl_packages < <(dpkg-query -W -f='${binary:Package}\n' 'libjxl-*' 2>/dev/null || true)
    if (( ${#installed_libjxl_packages[@]} > 0 )); then
      echo "libjxl: uninstalling installed libjxl-* packages: ${installed_libjxl_packages[*]}"
      sudo apt-get purge -y "${installed_libjxl_packages[@]}"
    else
      echo "libjxl: no installed libjxl-* packages found to uninstall"
    fi
  fi

  echo "libjxl: installing official release deb packages"
  sudo apt-get install -y "${deb_dir}"/jxl_*.deb "${deb_dir}"/libjxl_*.deb
  rm -rf "$tmp_dir"
  echo "libjxl: official release deb installation complete"
}

# Use zsh profile on macOS, bash profile elsewhere.
if [[ "$(uname -s)" == "Darwin" ]]; then
  PROFILE="${HOME}/.zshrc"
else
  PROFILE="${HOME}/.bashrc"

  if ! which apt >/dev/null; then
    echo "apt not found."
    exit 1
  fi

  sudo apt-get update
  install_libjxl_release_debs
  sudo apt-get install -y $PACKAGES
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
  curl -LsSf https://astral.sh/uv/install.sh | sh
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
        sudo sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT=/{
            /zswap.enabled/! s/"$/ zswap.enabled=1 zswap.compressor=zstd"/
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
      git -C "$dir" init -q
      git -C "$dir" config --local user.name "$user"
      git -C "$dir" config --local user.email "$email"
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

* Always commit after each logical change with a descriptive commit message; never bundle unrelated changes.
* Do not stage or commit AI-agent instruction/context Markdown files unless explicitly directed. This includes `AGENTS.md`, `CLAUDE.md`, `QWEN.md`, and similar local `.md` files used to guide agents.
* This restriction does not apply to normal project documentation such as `README.md`, `CHANGELOG.md`, API docs, design docs, or user-facing Markdown files when those files are part of the requested change.
* Use Conventional Commits: `feat:`, `fix:`, `refactor:`, `docs:`, `chore:`, `test:`, etc.
* Write short, imperative descriptions (e.g. `feat: add input validation`, `fix: off-by-one in retry loop`).
* Never append Co-Authored-By trailers to commit messages.

## Dependencies

* Pick the latest version the package manager resolves against existing project constraints, including lockfiles and manifest ranges.
* Before finalizing a dependency add/update, check the registry (npm, NuGet, PyPI, GitHub, ...) for explicit deprecation signals, such as `deprecated`, yanked releases, or archived repositories, on the chosen package and version. If any are found, prefer a non-deprecated alternative when practical; otherwise warn inline with the package name, signal source, and suggested alternative if the registry provides one, then proceed.
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
       '.attribution = { commit: "", pr: "" } | .statusLine = { type: "command", command: $cmd, refreshInterval: 2 }' \
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
# claudez alias + MCP servers setup - embed into shell profile if not present
# ---------------------------------------------------------------------------
CLAUDEZ_MARKER="# >>> claudez >>>"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudez >>>" "# <<< claudez <<<"
fi

if grep -qF "$CLAUDEZ_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudez: already in $PROFILE -- skipping"
else
  # Use existing env var if set, otherwise prompt
  if [[ -z "${Z_AI_AUTH_TOKEN:-}" ]]; then
    read -r -p "Enter your Z.AI API token for claudez alias + MCP servers: " Z_AI_AUTH_TOKEN
  else
    echo "claudez: detected Z_AI_AUTH_TOKEN from environment"
  fi

  if [[ -z "$Z_AI_AUTH_TOKEN" ]]; then
    echo "claudez: token is empty, skipping alias and MCP setup"
  else
    # Add the claudez alias
    # about supported model: "All plans support GLM-5.1, GLM-5-Turbo, GLM-4.7 and GLM-4.5-Air." (https://docs.z.ai/devpack/overview)
    # about "CLAUDE_CODE_DISABLE_1M_CONTEXT": 
    #   GLM-5.1, GLM-5, GLM-5-Turbo Context Length = 200K (https://docs.z.ai/guides/llm/glm-5.1)
    #   GLM-4.5(GLM-4.5-Air) Context Length = 128K (https://docs.z.ai/guides/llm/glm-4.5)
    cat >> "$PROFILE" << EOF

# >>> claudez >>>
# Custom Claude Code alias with Z.AI endpoint
alias claudez='ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$Z_AI_AUTH_TOKEN" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="glm-4.5-air" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="glm-4.7" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="glm-5.1" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  CLAUDE_CODE_DISABLE_1M_CONTEXT="1" \
  claude'
alias claudezd='ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$Z_AI_AUTH_TOKEN" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="glm-4.5-air" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="glm-4.7" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="glm-5.1" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  CLAUDE_CODE_DISABLE_1M_CONTEXT="1" \
  claude --dangerously-skip-permissions'
alias claudezm='ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$Z_AI_AUTH_TOKEN" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="glm-4.5-air" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="glm-5-turbo" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="glm-5.1" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  CLAUDE_CODE_DISABLE_1M_CONTEXT="1" \
  claude'
alias claudezmd='ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$Z_AI_AUTH_TOKEN" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="glm-4.5-air" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="glm-5-turbo" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="glm-5.1" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  CLAUDE_CODE_DISABLE_1M_CONTEXT="1" \
  claude --dangerously-skip-permissions'
# <<< claudez <<<
EOF

    # Configure MCP servers via Claude CLI (preferred over direct JSON edits)
    if command -v claude &>/dev/null; then
      CLAUDEZ_ENV=(
        ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic"
        ANTHROPIC_AUTH_TOKEN="$Z_AI_AUTH_TOKEN"
        API_TIMEOUT_MS="3000000"
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"
        CLAUDE_CODE_DISABLE_1M_CONTEXT="1"
      )

      echo "claudez: configuring MCP servers..."

      # web-search-prime
      # https://docs.z.ai/devpack/mcp/search-mcp-server
      if env "${CLAUDEZ_ENV[@]}" claude mcp list 2>/dev/null | grep -Fqi "web-search-prime"; then
        echo "claudez: web-search-prime already exists -- skipping"
      else
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user -t http web-search-prime https://api.z.ai/api/mcp/web_search_prime/mcp --header "Authorization: Bearer $Z_AI_AUTH_TOKEN" >/dev/null 2>&1; then
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
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user -t http web-reader https://api.z.ai/api/mcp/web_reader/mcp --header "Authorization: Bearer $Z_AI_AUTH_TOKEN" >/dev/null 2>&1; then
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
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user -t http zread https://api.z.ai/api/mcp/zread/mcp --header "Authorization: Bearer $Z_AI_AUTH_TOKEN" >/dev/null 2>&1; then
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
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user zai-mcp-server --env Z_AI_API_KEY=$Z_AI_AUTH_TOKEN Z_AI_MODE=ZAI -- npx -y @z_ai/mcp-server >/dev/null 2>&1; then
          echo "claudez: added zai-mcp-server"
        else
          echo "claudez: failed to add zai-mcp-server" >&2
        fi
      fi

      echo "claudez: alias added to $PROFILE"
      echo "claudez: MCP setup complete"
    else
      echo "claudez: alias added to $PROFILE"
      echo "WARNING: claude CLI not found, skipping MCP server configuration"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# claudeds / claudeds2 - DeepSeek Claude Code aliases
# ---------------------------------------------------------------------------
CLAUDEDS_MARKER="# >>> claudeds >>>"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudeds >>>" "# <<< claudeds <<<"
fi

if grep -qF "$CLAUDEDS_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudeds: already in $PROFILE -- skipping"
else
  # Use existing env var if set, otherwise prompt
  if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
    read -r -p "Enter your DeepSeek API key for claudeds alias setup: " DEEPSEEK_API_KEY
  else
    echo "claudeds: detected DEEPSEEK_API_KEY from environment"
  fi

  if [[ -z "$DEEPSEEK_API_KEY" ]]; then
    echo "claudeds: key is empty, skipping alias setup"
  else
    cat >> "$PROFILE" << EOF

# >>> claudeds >>>
# Custom Claude Code alias with DeepSeek endpoint
alias claudeds='ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$DEEPSEEK_API_KEY" \
  ANTHROPIC_MODEL="deepseek-v4-pro[1m]" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-v4-pro[1m]" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-v4-pro[1m]" \
  CLAUDE_CODE_SUBAGENT_MODEL="deepseek-v4-flash[1m]" \
  CLAUDE_CODE_EFFORT_LEVEL="max" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  claude'
alias claudedsd='ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$DEEPSEEK_API_KEY" \
  ANTHROPIC_MODEL="deepseek-v4-pro[1m]" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-v4-pro[1m]" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-v4-pro[1m]" \
  CLAUDE_CODE_SUBAGENT_MODEL="deepseek-v4-flash[1m]" \
  CLAUDE_CODE_EFFORT_LEVEL="max" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  claude --dangerously-skip-permissions'
alias claudeds2='ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$DEEPSEEK_API_KEY" \
  ANTHROPIC_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-v4-pro[1m]" \
  CLAUDE_CODE_SUBAGENT_MODEL="deepseek-v4-flash[1m]" \
  CLAUDE_CODE_EFFORT_LEVEL="high" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  claude'
alias claudeds2d='ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$DEEPSEEK_API_KEY" \
  ANTHROPIC_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-v4-flash[1m]" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-v4-pro[1m]" \
  CLAUDE_CODE_SUBAGENT_MODEL="deepseek-v4-flash[1m]" \
  CLAUDE_CODE_EFFORT_LEVEL="high" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  claude --dangerously-skip-permissions'
export DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY"
# <<< claudeds <<<
EOF

    echo "claudeds: added to $PROFILE"
  fi
fi

# ---------------------------------------------------------------------------
# claudez-remote (claudezr) - remote Claude Code via Z.AI
# ---------------------------------------------------------------------------
CLAUDEZR_MARKER="# >>> claudez-remote >>>"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudez-remote >>>" "# <<< claudez-remote <<<"
fi

if grep -qF "$CLAUDEZR_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudez-remote: already in $PROFILE -- skipping"
else
  if [[ -n "${Z_AI_AUTH_TOKEN:-}" ]]; then
    # Quoted heredoc — no variable expansion, so $ signs in function bodies
    # are written verbatim to the profile.
    cat >> "$PROFILE" << 'CLAUDERZR_EOF'
# >>> claudez-remote >>>

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
#          [haiku] [sonnet] [opus] [timeout_ms] [disable_1m]
remote_claude_base() {
  local host="$1" key="$2" port="${3:-22}"
  local base_url="${4:-}" haiku="$5" sonnet="$6" opus="$7"
  local timeout="$8" disable_1m="$9"

  [[ -z "$host" ]] && { echo "remote_claude_base: host is required" >&2; return 1; }
  [[ -z "$key"  ]] && { echo "remote_claude_base: api_key is required" >&2; return 1; }

  local encoded
  encoded=$(base64 << 'REMOTE_SCRIPT'
CC_TMP="$(mktemp -d /tmp/cc-XXXXXX)"
trap 'echo "[cleanup] Wiping $CC_TMP ..."; rm -rf "$CC_TMP"' EXIT
CC_NPM="$CC_TMP/npm"; CC_HOME="$CC_TMP/home"; CC_WORK="$CC_TMP/workspace"
mkdir -p "$CC_NPM" "$CC_HOME" "$CC_WORK"
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:?not set}"
[ -n "${ANTHROPIC_BASE_URL:-}" ] && export ANTHROPIC_BASE_URL="$ANTHROPIC_BASE_URL"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="${ANTHROPIC_DEFAULT_HAIKU_MODEL:-}"
export ANTHROPIC_DEFAULT_SONNET_MODEL="${ANTHROPIC_DEFAULT_SONNET_MODEL:-}"
export ANTHROPIC_DEFAULT_OPUS_MODEL="${ANTHROPIC_DEFAULT_OPUS_MODEL:-}"
export API_TIMEOUT_MS="${API_TIMEOUT_MS:-300000}"
export CLAUDE_CODE_DISABLE_1M_CONTEXT="${CLAUDE_CODE_DISABLE_1M_CONTEXT:-1}"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export DISABLE_AUTOUPDATER=1
if ! command -v node &>/dev/null; then
    export NVM_DIR="$CC_TMP/nvm"; mkdir -p "$NVM_DIR"
    curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.4/install.sh \
        | NVM_DIR="$NVM_DIR" PROFILE=/dev/null bash
    . "$NVM_DIR/nvm.sh" --no-use
    nvm install --lts --no-progress && nvm use --lts
fi
if ! command -v claude &>/dev/null; then
    npm install --global --prefix "$CC_NPM" --no-audit --no-fund @anthropic-ai/claude-code
    export PATH="$CC_NPM/bin:$PATH"
fi
cd "$CC_WORK"
HOME="$CC_HOME" claude --dangerously-skip-permissions
REMOTE_SCRIPT
  ) && encoded=$(printf '%s' "$encoded" | tr -d '\n\r')

  local env="ANTHROPIC_API_KEY=$(_claude_sq "$key")"
  env+=" ANTHROPIC_DEFAULT_HAIKU_MODEL=$(_claude_sq "$haiku")"
  env+=" ANTHROPIC_DEFAULT_SONNET_MODEL=$(_claude_sq "$sonnet")"
  env+=" ANTHROPIC_DEFAULT_OPUS_MODEL=$(_claude_sq "$opus")"
  env+=" API_TIMEOUT_MS=$(_claude_sq "$timeout")"
  env+=" CLAUDE_CODE_DISABLE_1M_CONTEXT=$(_claude_sq "$disable_1m")"
  [[ -n "$base_url" ]] && env+=" ANTHROPIC_BASE_URL=$(_claude_sq "$base_url")"

  ssh -t -o StrictHostKeyChecking=accept-new -p "$port" "$host" \
    "$env bash -c 'echo $encoded | base64 -d | bash'"
}

# claudezr - One-shot remote Claude Code via Z.AI.
#   Usage: claudezr <user@host> [port]
claudezr() {
  local host="$1" port="${2:-22}"

  [[ -z "$host" ]] && { echo "claudezr: host is required" >&2; echo "  Usage: claudezr <user@host> [port]" >&2; return 1; }

  local key="${Z_AI_AUTH_TOKEN:-}"
  if [[ -z "$key" ]]; then
    echo "claudezr: Z_AI_AUTH_TOKEN is not set. Aborting." >&2
    echo "" >&2
    echo "Set it in your shell profile then reload:" >&2
    echo "  export Z_AI_AUTH_TOKEN='<your_token>'" >&2
    return 1
  fi

  remote_claude_base "$host" "$key" "$port" \
    "https://api.z.ai/api/anthropic" \
    "glm-4.5-air" \
    "glm-5-turbo" \
    "glm-5.1" \
    "3000000" \
    "1"
}

CLAUDERZR_EOF

    # Token export : separate from the quoted heredoc so $Z_AI_AUTH_TOKEN expands.
    {
      echo "export Z_AI_AUTH_TOKEN=\"$Z_AI_AUTH_TOKEN\""
      echo "# <<< claudez-remote <<<"
    } >> "$PROFILE"

    echo "claudez-remote: added to $PROFILE"
  else
    echo "claudez-remote: Z_AI_AUTH_TOKEN not set, skipping (run claudez setup first)"
  fi
fi

# ---------------------------------------------------------------------------
# claudemm alias + MCP server setup - embed into shell profile if not present
# ---------------------------------------------------------------------------
CLAUDEMM_MARKER="# >>> claudemm >>>"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudemm >>>" "# <<< claudemm <<<"
fi

if grep -qF "$CLAUDEMM_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudemm: already in $PROFILE -- skipping"
else
  # Use existing env var if set, otherwise prompt
  if [[ -z "${MINIMAX_API_KEY:-}" ]]; then
    read -r -p "Enter your MiniMax API key for claudemm alias + MCP server: " MINIMAX_API_KEY
  else
    echo "claudemm: detected MINIMAX_API_KEY from environment"
  fi

  if [[ -z "$MINIMAX_API_KEY" ]]; then
    echo "claudemm: key is empty, skipping alias and MCP setup"
  else
    # Add the claudemm aliases
    # https://platform.minimax.io/docs/token-plan/claude-code
    cat >> "$PROFILE" << EOF

# >>> claudemm >>>
# Custom Claude Code alias with MiniMax endpoint
alias claudemm='ANTHROPIC_BASE_URL="https://api.minimax.io/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$MINIMAX_API_KEY" \
  ANTHROPIC_MODEL="MiniMax-M3[1m]" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="MiniMax-M3[1m]" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="MiniMax-M3[1m]" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="MiniMax-M3[1m]" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  claude'
alias claudemmd='ANTHROPIC_BASE_URL="https://api.minimax.io/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$MINIMAX_API_KEY" \
  ANTHROPIC_MODEL="MiniMax-M3[1m]" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="MiniMax-M3[1m]" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="MiniMax-M3[1m]" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="MiniMax-M3[1m]" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  claude --dangerously-skip-permissions'
export MINIMAX_API_KEY="$MINIMAX_API_KEY"
# <<< claudemm <<<
EOF

    # Configure MiniMax MCP server via Claude CLI
    if command -v claude &>/dev/null; then
      CLAUDEMM_ENV=(
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
        if env "${CLAUDEMM_ENV[@]}" claude mcp add -s user MiniMax --env MINIMAX_API_KEY="$MINIMAX_API_KEY" --env MINIMAX_API_HOST=https://api.minimax.io -- uvx minimax-coding-plan-mcp -y >/dev/null 2>&1; then
          echo "claudemm: added MiniMax MCP server"
        else
          echo "claudemm: failed to add MiniMax MCP server" >&2
        fi
      fi

      echo "claudemm: alias added to $PROFILE"
      echo "claudemm: MCP setup complete"
    else
      echo "claudemm: alias added to $PROFILE"
      echo "WARNING: claude CLI not found, skipping MCP server configuration"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# claudemm-remote (claudemmr) - remote Claude Code via MiniMax
# ---------------------------------------------------------------------------
CLAUDEMMR_MARKER="# >>> claudemm-remote >>>"

if $FORCE_REINSTALL; then
  remove_profile_section "$PROFILE" "# >>> claudemm-remote >>>" "# <<< claudemm-remote <<<"
fi

if grep -qF "$CLAUDEMMR_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudemm-remote: already in $PROFILE -- skipping"
else
  if [[ -n "${MINIMAX_API_KEY:-}" ]]; then
    # Quoted heredoc — no variable expansion, so $ signs in function bodies
    # are written verbatim to the profile.
    cat >> "$PROFILE" << 'CLAUEMMR_EOF'
# >>> claudemm-remote >>>

# claudemmr - One-shot remote Claude Code via MiniMax.
#   Usage: claudemmr <user@host> [port]
claudemmr() {
  local host="$1" port="${2:-22}"

  [[ -z "$host" ]] && { echo "claudemmr: host is required" >&2; echo "  Usage: claudemmr <user@host> [port]" >&2; return 1; }

  local key="${MINIMAX_API_KEY:-}"
  if [[ -z "$key" ]]; then
    echo "claudemmr: MINIMAX_API_KEY is not set. Aborting." >&2
    echo "" >&2
    echo "Set it in your shell profile then reload:" >&2
    echo "  export MINIMAX_API_KEY='<your_key>'" >&2
    return 1
  fi

  remote_claude_base "$host" "$key" "$port" \
    "https://api.minimax.io/anthropic" \
    "MiniMax-M3[1m]" \
    "MiniMax-M3[1m]" \
    "MiniMax-M3[1m]" \
    "3000000" \
    "0"
}

CLAUEMMR_EOF

    # Key export : separate from the quoted heredoc so $MINIMAX_API_KEY expands.
    # (Already exported above in the claudemm section, but re-export for safety
    #  if claudemm was skipped but claudemm-remote runs standalone.)
    {
      echo "export MINIMAX_API_KEY=\"$MINIMAX_API_KEY\""
      echo "# <<< claudemm-remote <<<"
    } >> "$PROFILE"

    echo "claudemm-remote: added to $PROFILE"
  else
    echo "claudemm-remote: MINIMAX_API_KEY not set, skipping (run claudemm setup first)"
  fi
fi

if $FORCE_REINSTALL; then
  echo "WARNING: --force removed and reapplied shell/profile sections; inspect the resulting files manually for a clean outcome."
fi
