#!/bin/bash
# Claude Code statusline script
# Cross-platform: macOS, Linux, Windows (Git Bash). jq required.
# Copyright (c) 2026 @thejjw

# --- jq check ---
if ! command -v jq &>/dev/null; then
  echo "[!] jq not found -- install jq for statusline"
  exit 0
fi

input=$(cat)
STATE_FILE="${TMPDIR:-/tmp}/.claude-statusline-state"

# --- Colors ---
CYAN='\033[36m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'
DIM='\033[2m'; BOLD='\033[1m'; RESET='\033[0m'

# --- Parse fields ---
model=$(echo "$input" | jq -r '.model.display_name // "?"')
model_id=$(echo "$input" | jq -r '.model.id // ""')
ctx_pct=$(echo "$input" | jq -r '.context_window.used_percentage // 0' | cut -d. -f1)
ctx_size=$(echo "$input" | jq -r '.context_window.context_window_size // 200000')
ctx_input=$(echo "$input" | jq -r '.context_window.total_input_tokens // 0')
ctx_output=$(echo "$input" | jq -r '.context_window.total_output_tokens // 0')
cache_write=$(echo "$input" | jq -r '.context_window.current_usage.cache_creation_input_tokens // 0')
cache_read=$(echo "$input" | jq -r '.context_window.current_usage.cache_read_input_tokens // 0')
cost=$(echo "$input" | jq -r '.cost.total_cost_usd // 0')
dur_ms=$(echo "$input" | jq -r '.cost.total_duration_ms // 0')
api_ms=$(echo "$input" | jq -r '.cost.total_api_duration_ms // 0')
lines_add=$(echo "$input" | jq -r '.cost.total_lines_added // 0')
lines_rm=$(echo "$input" | jq -r '.cost.total_lines_removed // 0')
rate_5h=$(echo "$input" | jq -r '.rate_limits.five_hour.used_percentage // empty' 2>/dev/null)
rate_7d=$(echo "$input" | jq -r '.rate_limits.seven_day.used_percentage // empty' 2>/dev/null)
session_name=$(echo "$input" | jq -r '.session_name // empty' 2>/dev/null)
agent_name=$(echo "$input" | jq -r '.agent.name // empty' 2>/dev/null)
worktree_name=$(echo "$input" | jq -r '.worktree.name // empty' 2>/dev/null)

version=$(echo "$input" | jq -r '.version // "?"')
session_id=$(echo "$input" | jq -r '.session_id // "?"')
output_style=$(echo "$input" | jq -r '.output_style.name // "default"')
ws_current=$(echo "$input" | jq -r '.workspace.current_dir // "?"')
ws_project=$(echo "$input" | jq -r '.workspace.project_dir // "?"')

# --- Git info (from workspace dir) ---
git_branch=$(cd "$ws_current" 2>/dev/null && git branch --show-current 2>/dev/null)
if [ -n "$git_branch" ]; then
  # Truncate branch name to 20 chars
  if [ ${#git_branch} -gt 20 ]; then
    git_branch="${git_branch:0:19}…"
  fi
  # Dirty state: * if uncommitted changes
  dirty=""
  if cd "$ws_current" 2>/dev/null && ! git diff --quiet HEAD 2>/dev/null; then
    dirty="*"
  fi
  # Ahead/behind remote
  ahead_behind=""
  counts=$(cd "$ws_current" 2>/dev/null && git rev-list --left-right --count HEAD...@{upstream} 2>/dev/null)
  if [ -n "$counts" ]; then
    ahead=$(echo "$counts" | cut -f1)
    behind=$(echo "$counts" | cut -f2)
    [ "$ahead" -gt 0 ] 2>/dev/null && ahead_behind+="↑${ahead}"
    [ "$behind" -gt 0 ] 2>/dev/null && ahead_behind+="↓${behind}"
  fi
  # Untracked file count
  untracked=$(cd "$ws_current" 2>/dev/null && git ls-files --others --exclude-standard 2>/dev/null | wc -l | tr -d ' ')
  untracked_info=""
  [ "$untracked" -gt 0 ] 2>/dev/null && untracked_info="?${untracked}"
fi

# --- Helpers ---
fmt_tokens() {
  local t=$1
  if [ "$t" -ge 1000000 ] 2>/dev/null; then
    printf "%.1fM" "$(echo "$t / 1000000" | bc -l 2>/dev/null || echo 0)"
  elif [ "$t" -ge 1000 ] 2>/dev/null; then
    printf "%.1fk" "$(echo "$t / 1000" | bc -l 2>/dev/null || echo 0)"
  else
    echo "$t"
  fi
}

fmt_time() {
  local ms=$1
  local total_s=$(( ms / 1000 ))
  local h=$(( total_s / 3600 ))
  local m=$(( (total_s % 3600) / 60 ))
  local s=$(( total_s % 60 ))
  if [ "$h" -gt 0 ] 2>/dev/null; then
    printf "%dh%02dm" "$h" "$m"
  elif [ "$m" -gt 0 ] 2>/dev/null; then
    printf "%dm%02ds" "$m" "$s"
  else
    printf "%ds" "$s"
  fi
}

# --- Context color based on usage percentage ---
if [ "$ctx_pct" -ge 90 ] 2>/dev/null; then CTX_COLOR="$RED"
elif [ "$ctx_pct" -ge 70 ] 2>/dev/null; then CTX_COLOR="$YELLOW"
else CTX_COLOR="$GREEN"; fi

# --- Compute last message duration (delta of api_ms) ---
last_msg=""
last_ts=""
if [ -f "$STATE_FILE" ]; then
  prev_api_ms=$(head -1 "$STATE_FILE" 2>/dev/null || echo 0)
  delta_ms=$(( api_ms - prev_api_ms ))
  if [ "$delta_ms" -gt 0 ] 2>/dev/null; then
    if [ "$delta_ms" -ge 60000 ]; then
      last_msg="$(fmt_time "$delta_ms")"
    elif [ "$delta_ms" -ge 1000 ]; then
      last_msg="$(printf "%.1fs" "$(echo "$delta_ms / 1000" | bc -l 2>/dev/null || echo 0)")"
    else
      last_msg="${delta_ms}ms"
    fi
  fi
  prev_ts=$(tail -1 "$STATE_FILE" 2>/dev/null)
  if [ -n "$prev_ts" ]; then
    last_ts="$prev_ts"
  fi
fi
# Record current api_ms and current timestamp for next invocation
now_ts=$(date '+%H:%M:%S')
printf '%s\n%s\n' "$api_ms" "$now_ts" > "$STATE_FILE"

# --- Format tokens ---
tok_used=$(fmt_tokens "$(( ctx_input + ctx_output ))")
tok_max=$(fmt_tokens "$ctx_size")
cache_w_fmt=$(fmt_tokens "$cache_write")
cache_r_fmt=$(fmt_tokens "$cache_read")

# --- Cost color ---
cost_val=$(printf "%.2f" "$cost")
if (( $(echo "$cost > 1.0" | bc -l 2>/dev/null || echo 0) )); then COST_COLOR="$RED"
elif (( $(echo "$cost > 0.25" | bc -l 2>/dev/null || echo 0) )); then COST_COLOR="$YELLOW"
else COST_COLOR="$GREEN"; fi

# --- Rate limit color ---
rate_color() {
  local pct=$(printf "%.0f" "$1")
  if [ "$pct" -ge 80 ] 2>/dev/null; then echo "$RED"
  elif [ "$pct" -ge 50 ] 2>/dev/null; then echo "$YELLOW"
  else echo "$GREEN"; fi
}

# ============================================================
# LINE 1: Model | Context | Git (dirty+branch ahead/behind untracked) | Cost
# ============================================================
line1="${BOLD}[${model}]${RESET} "
line1+="${CTX_COLOR}${tok_used}${RESET}/${DIM}${tok_max}${RESET}"
if [ "$cache_read" -gt 0 ] 2>/dev/null || [ "$cache_write" -gt 0 ] 2>/dev/null; then
  line1+="  ${DIM}(c) r:${cache_r_fmt} w:${cache_w_fmt}${RESET}"
fi
if [ -n "$git_branch" ]; then
  line1+="  ${CYAN}${dirty}${git_branch}${RESET}"
  [ -n "$ahead_behind" ] && line1+=" ${CYAN}${ahead_behind}${RESET}"
  [ -n "$untracked_info" ] && line1+=" ${DIM}${untracked_info}${RESET}"
fi
# Dim cost for subscription users (detected by rate_limits presence)
if [ -n "$rate_5h" ] || [ -n "$rate_7d" ]; then
  line1+="  ${DIM}\$${cost_val}${RESET}"
else
  line1+="  ${COST_COLOR}\$${cost_val}${RESET}"
fi

# ============================================================
# LINE 2: Timings | Lines changed | Last msg + timestamp
# ============================================================
sess_t=$(fmt_time "$dur_ms")
api_t=$(fmt_time "$api_ms")
line2="${DIM}Sess${RESET} ${CYAN}${sess_t}${RESET}"
line2+=" ${DIM}|${RESET} ${DIM}API${RESET} ${CYAN}${api_t}${RESET}"
line2+=" ${DIM}|${RESET} ${GREEN}+${lines_add}${RESET}/${RED}-${lines_rm}${RESET} lines"
if [ -n "$last_msg" ]; then
  line2+=" ${DIM}|${RESET} ${DIM}Last${RESET} ${CYAN}${last_msg}${RESET}"
fi
if [ -n "$last_ts" ]; then
  line2+=" ${DIM}@${last_ts}${RESET}"
fi

# ============================================================
# LINE 3: Rate limits | Agent | Worktree | Session name
# ============================================================
line3=""
line3_parts=()
if [ -n "$rate_5h" ]; then
  rc=$(rate_color "$rate_5h")
  line3_parts+=("${DIM}Rate 5h:${RESET} ${rc}$(printf "%.0f" "$rate_5h")%${RESET}")
fi
if [ -n "$rate_7d" ]; then
  rc=$(rate_color "$rate_7d")
  line3_parts+=("${DIM}7d:${RESET} ${rc}$(printf "%.0f" "$rate_7d")%${RESET}")
fi
if [ -n "$agent_name" ]; then
  line3_parts+=("${CYAN}agent:${agent_name}${RESET}")
fi
if [ -n "$worktree_name" ]; then
  line3_parts+=("${CYAN}wt:${worktree_name}${RESET}")
fi
if [ -n "$session_name" ]; then
  line3_parts+=("${DIM}\"${session_name}\"${RESET}")
fi
if [ ${#line3_parts[@]} -gt 0 ]; then
  sep=" ${DIM}|${RESET} "
  for ((i=0; i<${#line3_parts[@]}; i++)); do
    [ $i -gt 0 ] && line3+="$sep"
    line3+="${line3_parts[$i]}"
  done
fi

# ============================================================
# LINE 5: Version | Session ID | Output style (commented out)
# ============================================================
line5="${DIM}v${version}${RESET}"
line5+=" ${DIM}|${RESET} ${DIM}sid:${RESET}${CYAN}${session_id:0:12}${RESET}"
line5+=" ${DIM}|${RESET} ${DIM}style:${output_style}${RESET}"

# ============================================================
# LINE 6: Workspace dirs (commented out)
# ============================================================
line6="${DIM}cwd:${RESET}${CYAN}${ws_current}${RESET}"
if [ "$ws_current" != "$ws_project" ]; then
  line6+=" ${DIM}|${RESET} ${DIM}proj:${RESET}${CYAN}${ws_project}${RESET}"
fi

# --- Output ---
echo -e "$line1"
echo -e "$line2"
[ -n "$line3" ] && echo -e "$line3"
# Uncomment below to show version/session/workspace lines:
# echo -e "$line5"
# echo -e "$line6"
exit 0
