#!/bin/bash
# ---------------------------------------------------------------------------
# One-shot environment bootstrap
# Installs packages, nvm/node, and embeds functions into ~/.bashrc.
# ---------------------------------------------------------------------------
# 2026.4 @thejjw

set -e

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
# nrd - embed into ~/.bashrc if not already present
# ---------------------------------------------------------------------------
PROFILE="${HOME}/.bashrc"
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
