#!/bin/bash
# ---------------------------------------------------------------------------
# One-shot environment bootstrap
# Installs packages, nvm/node, and embeds functions into ~/.bashrc.
# ---------------------------------------------------------------------------
# 2026.4 @thejjw

set -e

# Use zsh profile on macOS, bash profile elsewhere.
if [[ "$(uname -s)" == "Darwin" ]]; then
  PROFILE="${HOME}/.zshrc"
else
  PROFILE="${HOME}/.bashrc"
fi

if ! which apt >/dev/null; then
  echo "apt not found."
  exit 1
fi

PACKAGES="libjxl-tools tmux build-essential cmatrix fonts-noto-cjk neofetch curl wget ripgrep jq parallel zstd xz-utils webp btop zram-tools bubblewrap socat"
NVM_VERSION="v0.40.4"

sudo apt-get update && sudo apt-get install -y $PACKAGES

if command -v node &>/dev/null && command -v npm &>/dev/null; then
  echo "node $(node -v) / npm $(npm -v) already installed -- skipping nvm"
else
  curl -o- "https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh" | bash
  source ~/.nvm/nvm.sh && nvm install --lts
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

## Code Style

- Prefer concise, minimal implementations -- avoid boilerplate and unnecessary abstraction.
- Comment every public function/method and any non-obvious logic inline.

## Git Discipline

- Commit each logical change separately -- never bundle unrelated changes.
- Use Conventional Commits: `feat:`, `fix:`, `refactor:`, `docs:`, `chore:`, `test:`, etc.
- Write short, imperative descriptions (e.g. `feat: add input validation`, `fix: off-by-one in retry loop`).
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
# claudez alias + MCP servers setup - embed into shell profile if not present
# ---------------------------------------------------------------------------
# Global CLAUDE.md preferences - create under ~/.claude if missing
CLAUDE_DIR="$HOME/.claude"
GLOBAL_MD="$CLAUDE_DIR/CLAUDE.md"

if [[ -f "$GLOBAL_MD" ]]; then
  echo "claudez: $GLOBAL_MD already exists -- skipping"
  echo "claudez: edit it manually to include:"
  cat << 'CLAUDE_PREF_EOF'
## MCP Tool Preferences

**Always consider using MCP tools over alternatives for below purposes:**
- Web searches
- Web content
- Image analysis
- Text extraction

If MCP tools are unavailable, inform the user and suggest alternatives.
CLAUDE_PREF_EOF
else
  mkdir -pv "$CLAUDE_DIR"
  cat > "$GLOBAL_MD" << 'CLAUDE_PREF_EOF'
## MCP Tool Preferences

**Always consider using MCP tools over alternatives for below purposes:**
- Web searches
- Web content
- Image analysis
- Text extraction

If MCP tools are unavailable, inform the user and suggest alternatives.
CLAUDE_PREF_EOF
  echo "claudez: created $GLOBAL_MD"
fi

CLAUDEZ_MARKER="# >>> claudez >>>"

if grep -qF "$CLAUDEZ_MARKER" "$PROFILE" 2>/dev/null; then
  echo "claudez: already in $PROFILE -- skipping"
else
  # Prompt once for API token (used for both alias and MCP servers)
  read -r -p "Enter your Z.AI API token for claudez alias + MCP servers: " ZAI_API_TOKEN

  if [[ -z "$ZAI_API_TOKEN" ]]; then
    echo "claudez: token is empty, skipping alias and MCP setup"
  else
    # Add the claudez alias
    # about "CLAUDE_CODE_DISABLE_1M_CONTEXT": 
    #   GLM-5.1, GLM-5, GLM-5-Turbo Context Length = 200K (https://docs.z.ai/guides/llm/glm-5.1)
    #   GLM-4.5(GLM-4.5-Air) Context Length = 128K (https://docs.z.ai/guides/llm/glm-4.5)
    cat >> "$PROFILE" << EOF

# >>> claudez >>>
# Custom Claude Code alias with Z.AI endpoint
alias claudez='ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$ZAI_API_TOKEN" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  CLAUDE_CODE_DISABLE_1M_CONTEXT="1" \
  claude'
alias claudezm='ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic" \
  ANTHROPIC_AUTH_TOKEN="$ZAI_API_TOKEN" \
  ANTHROPIC_DEFAULT_HAIKU_MODEL="glm-4.5-air" \
  ANTHROPIC_DEFAULT_SONNET_MODEL="glm-5-turbo" \
  ANTHROPIC_DEFAULT_OPUS_MODEL="glm-5.1" \
  API_TIMEOUT_MS="3000000" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1" \
  CLAUDE_CODE_DISABLE_1M_CONTEXT="1" \
  claude'
# <<< claudez <<<
EOF

    # Configure MCP servers via Claude CLI (preferred over direct JSON edits)
    if command -v claude &>/dev/null; then
      CLAUDEZ_ENV=(
        ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic"
        ANTHROPIC_AUTH_TOKEN="$ZAI_API_TOKEN"
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
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user -t http web-search-prime https://api.z.ai/api/mcp/web_search_prime/mcp --header "Authorization: Bearer $ZAI_API_TOKEN" >/dev/null 2>&1; then
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
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user -t http web-reader https://api.z.ai/api/mcp/web_reader/mcp --header "Authorization: Bearer $ZAI_API_TOKEN" >/dev/null 2>&1; then
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
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user -t http zread https://api.z.ai/api/mcp/zread/mcp --header "Authorization: Bearer $ZAI_API_TOKEN" >/dev/null 2>&1; then
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
        if env "${CLAUDEZ_ENV[@]}" claude mcp add -s user zai-mcp-server --env Z_AI_API_KEY=$ZAI_API_TOKEN Z_AI_MODE=ZAI -- npx -y @z_ai/mcp-server >/dev/null 2>&1; then
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
