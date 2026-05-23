#!/bin/bash
# ---------------------------------------------------------------------------
# One-shot environment bootstrap
# Installs packages, nvm/node, and embeds functions into ~/.bashrc.
# ---------------------------------------------------------------------------
# 2026.4-2026.5 @thejjw

set -e

PACKAGES="libjxl-tools tmux build-essential cmatrix fonts-noto-cjk curl wget ripgrep jq parallel zstd xz-utils webp btop zram-tools bubblewrap socat"
NVM_VERSION="v0.40.4"
NVM_INSTALL_URL="https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh"

# Use zsh profile on macOS, bash profile elsewhere.
if [[ "$(uname -s)" == "Darwin" ]]; then
  PROFILE="${HOME}/.zshrc"
else
  PROFILE="${HOME}/.bashrc"

  if ! which apt >/dev/null; then
    echo "apt not found."
    exit 1
  fi

  sudo apt-get update && sudo apt-get install -y $PACKAGES
fi


if command -v node &>/dev/null && command -v npm &>/dev/null; then
  echo "node $(node -v) / npm $(npm -v) already installed -- skipping nvm"
else
  curl -o- "$NVM_INSTALL_URL" | bash
  source ~/.nvm/nvm.sh && nvm install --lts
fi

# ---------------------------------------------------------------------------
# uv — required by MiniMax MCP server (uvx)
# ---------------------------------------------------------------------------
if command -v uv &>/dev/null; then
  echo "uv $(uv --version 2>/dev/null || echo 'installed') already present -- skipping"
else
  echo "ERROR: 'uv' is not installed but is required by MiniMax MCP (uvx)." >&2
  echo "  Install uv:" >&2
  echo "    Linux:    curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
  echo "    macOS:    brew install uv" >&2
  echo "" >&2
  echo "Re-run this script after installing uv." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# nrd - embed into shell profile if not already present
# ---------------------------------------------------------------------------
MARKER="# >>> nrd >>>"

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
#   nrd -a               create AGENTS.md + CLAUDE.md + GEMINI.md (@import); requires -g
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
    $verbose && echo "creating AGENTS.md (canonical) + CLAUDE.md/GEMINI.md (@import)"
    cat > "$dir/AGENTS.md" << 'AGENT_EOF'
# AGENTS.md

## Rules

- Always commit after completing each logical change with a descriptive commit message.
- Treat AI-agent instruction files as workspace-only guidance. Do not stage or commit them unless the user explicitly asks.

## Grounding

- Always utilize web search to ground your answers, ensuring all technical advice and references are accurate and up-to-date.

## Code Style

- Prefer concise, minimal implementations -- avoid boilerplate and unnecessary abstraction.
- Comment every public function/method and any non-obvious logic inline.

## Git Discipline

- Commit each logical change separately -- never bundle unrelated changes.
- Do not stage or commit AI-agent instruction/context Markdown files unless explicitly directed. This includes `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `QWEN.md`, and similar local `.md` files used to guide agents.
- This restriction does not apply to normal project documentation such as `README.md`, `CHANGELOG.md`, API docs, design docs, or user-facing Markdown files when those files are part of the requested change.
- Use Conventional Commits: `feat:`, `fix:`, `refactor:`, `docs:`, `chore:`, `test:`, etc.
- Write short, imperative descriptions (e.g. `feat: add input validation`, `fix: off-by-one in retry loop`).

## Dependencies

- Pick the latest version the package manager resolves against existing project constraints, including lockfiles and manifest ranges.
- Before finalizing a dependency add/update, check the registry (npm, NuGet, PyPI, GitHub, ...) for explicit deprecation signals, such as `deprecated`, yanked releases, or archived repositories, on the chosen package and version. If any are found, warn inline with the package name, signal source, and suggested alternative if the registry provides one, then proceed.
AGENT_EOF
    printf '@AGENTS.md\n' > "$dir/CLAUDE.md"
    printf '@./AGENTS.md\n' > "$dir/GEMINI.md"
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
  echo "global CLAUDE.md: $GLOBAL_MD already exists -- skipping"
  echo "global CLAUDE.md: edit it manually to include multi-model MCP preferences"
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
Use MiniMax MCP server for:
- Web searches (`web_search`)
- Image understanding (`understand_image`)

**When using genuine Anthropic account (Claude Code with native models):**
Use built-in web fetch and web search tools directly -- they will yield the best results.

If an MCP tool is unavailable or underperforming, inform the user and suggest alternatives.
CLAUDE_PREF_EOF
  echo "global CLAUDE.md: created $GLOBAL_MD"
fi

# ---------------------------------------------------------------------------
# ccd - shorthand for claude --dangerously-skip-permissions
# ---------------------------------------------------------------------------
CCD_MARKER="# >>> ccd >>>"

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
# claudez-remote (claudezr) - remote Claude Code via Z.AI
# ---------------------------------------------------------------------------
CLAUDEZR_MARKER="# >>> claudez-remote >>>"

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
  ANTHROPIC_MODEL="MiniMax-M2.7" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="MiniMax-M2.7" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="MiniMax-M2.7" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="MiniMax-M2.7" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  claude'
alias claudemmd='ANTHROPIC_BASE_URL="https://api.minimax.io/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$MINIMAX_API_KEY" \
  ANTHROPIC_MODEL="MiniMax-M2.7" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="MiniMax-M2.7" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="MiniMax-M2.7" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="MiniMax-M2.7" \
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
        ANTHROPIC_MODEL="MiniMax-M2.7"
        ANTHROPIC_DEFAULT_HAIKU_MODEL="MiniMax-M2.7"
        ANTHROPIC_DEFAULT_SONNET_MODEL="MiniMax-M2.7"
        ANTHROPIC_DEFAULT_OPUS_MODEL="MiniMax-M2.7"
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
    "MiniMax-M2.7" \
    "MiniMax-M2.7" \
    "MiniMax-M2.7" \
    "3000000" \
    "1"
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
