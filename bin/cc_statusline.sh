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

# --- Parse all fields in a single jq call (US-delimited; non-whitespace so empty fields don't collapse) ---
parsed=$(echo "$input" | jq -rj '[
  .model.display_name // "?",
  (.context_window.used_percentage // 0 | floor),
  .context_window.context_window_size // 200000,
  .context_window.total_input_tokens // 0,
  .context_window.total_output_tokens // 0,
  .context_window.current_usage.cache_creation_input_tokens // 0,
  .context_window.current_usage.cache_read_input_tokens // 0,
  .cost.total_cost_usd // 0,
  .cost.total_duration_ms // 0,
  .cost.total_api_duration_ms // 0,
  .cost.total_lines_added // 0,
  .cost.total_lines_removed // 0,
  .rate_limits.five_hour.used_percentage // "",
  .rate_limits.seven_day.used_percentage // "",
  .session_name // "",
  .agent.name // "",
  .worktree.name // "",
  .version // "?",
  .session_id // "?",
  .output_style.name // "default",
  .workspace.current_dir // "?",
  .workspace.project_dir // "?",
  .effort.level // "",
  (.thinking.enabled // false | tostring),
  (.fast_mode // false | tostring),
  .rate_limits.five_hour.resets_at // "",
  .rate_limits.seven_day.resets_at // "",
  (.exceeds_200k_tokens // false | tostring)
] | map(tostring) | join("")')

IFS=$'\x1f' read -r \
  model ctx_pct ctx_size ctx_input ctx_output \
  cache_write cache_read cost dur_ms api_ms lines_add lines_rm \
  rate_5h rate_7d session_name agent_name worktree_name \
  version session_id output_style ws_current ws_project \
  effort_level thinking_enabled fast_mode rate_5h_resets rate_7d_resets exceeds_200k \
  <<< "$parsed"

# --- Git info: single porcelain call returns branch + ahead/behind + dirty + untracked ---
git_branch=""
ahead_behind=""
dirty=""
untracked_info=""
git_status=$(git -C "$ws_current" status --porcelain=v1 --branch 2>/dev/null)
if [ -n "$git_status" ]; then
  # First line: "## branch...remote [ahead N, behind M]" / "## HEAD (no branch)" / "## No commits yet on branch"
  branch_line="${git_status%%$'\n'*}"
  branch_line="${branch_line#\#\# }"

  # Skip detached HEAD (matches prior behavior of git branch --show-current returning empty)
  if [[ "$branch_line" != "HEAD (no branch)"* ]]; then
    if [[ "$branch_line" == "No commits yet on "* ]]; then
      git_branch="${branch_line#No commits yet on }"
    else
      git_branch="${branch_line%%...*}"
      git_branch="${git_branch%% *}"
    fi

    # Truncate branch to 20 chars
    if [ ${#git_branch} -gt 20 ]; then
      git_branch="${git_branch:0:19}…"
    fi

    # Parse [ahead N, behind M] / [ahead N] / [behind M]
    ahead_re='\[ahead ([0-9]+)(, behind ([0-9]+))?\]'
    behind_re='\[behind ([0-9]+)\]'
    if [[ "$branch_line" =~ $ahead_re ]]; then
      ahead_behind="↑${BASH_REMATCH[1]}"
      [ -n "${BASH_REMATCH[3]}" ] && ahead_behind+="↓${BASH_REMATCH[3]}"
    elif [[ "$branch_line" =~ $behind_re ]]; then
      ahead_behind="↓${BASH_REMATCH[1]}"
    fi

    # Count dirty (tracked changes) and untracked from remaining status lines
    untracked=0
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      [ "${line:0:2}" = "##" ] && continue
      if [ "${line:0:2}" = "??" ]; then
        untracked=$((untracked + 1))
      else
        dirty="*"
      fi
    done <<< "$git_status"

    [ "$untracked" -gt 0 ] && untracked_info="?${untracked}"
  fi
fi

# --- Effort / thinking display ---
case "$effort_level" in
  low)    effort_short="L" ;;
  medium) effort_short="M" ;;
  high)   effort_short="H" ;;
  xhigh)  effort_short="XH" ;;
  *)      effort_short="$effort_level" ;;
esac

think_tag=""
if [ "$fast_mode" = "true" ]; then
  think_tag="${CYAN}fast${RESET}"
elif [ "$thinking_enabled" = "true" ]; then
  think_tag="${YELLOW}T:${effort_short}${RESET}"
elif [ -n "$effort_level" ]; then
  think_tag="${DIM}${effort_short}${RESET}"
fi

# --- Advisor config: resolve effective advisorModel across the settings layers ---
# Claude Code deep-merges settings; the value that "matters" is the one from the
# highest-precedence layer that sets it. Order (low -> high): user, project,
# project-local, enterprise managed. Not exposed in the statusline JSON, so read
# the files directly. read_adv() echoes a non-empty advisorModel if the file sets one.
config_dir="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
case "$(uname -s)" in
  Darwin) managed_settings="/Library/Application Support/ClaudeCode/managed-settings.json" ;;
  Linux)  managed_settings="/etc/claude-code/managed-settings.json" ;;
  *)      managed_settings="${PROGRAMDATA:-C:/ProgramData}/ClaudeCode/managed-settings.json"
          managed_settings="${managed_settings//\\//}" ;;  # backslashes -> forward for Git Bash
esac
read_adv() { [ -f "$1" ] && jq -r '.advisorModel // empty' "$1" 2>/dev/null; }
advisor_model=""
for f in \
  "$config_dir/settings.json" \
  "$ws_project/.claude/settings.json" \
  "$ws_project/.claude/settings.local.json" \
  "$managed_settings"; do
  v=$(read_adv "$f"); [ -n "$v" ] && advisor_model="$v"  # last defining layer wins
done
adv_tag=""
[ -n "$advisor_model" ] && adv_tag="${GREEN}adv:${advisor_model}${RESET}"  # show only when set

# --- Helpers ---
fmt_tokens() {
  local t=$1
  if [ "$t" -ge 1000000 ] 2>/dev/null; then
    awk -v t="$t" 'BEGIN { printf "%.1fM", t/1000000 }'
  elif [ "$t" -ge 1000 ] 2>/dev/null; then
    awk -v t="$t" 'BEGIN { printf "%.1fk", t/1000 }'
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

fmt_reset_delta() {
  local ts=$1 now delta
  [ -z "$ts" ] && return
  now=$(date +%s)
  delta=$(( ts - now ))
  [ "$delta" -le 0 ] && return
  if [ "$delta" -ge 3600 ]; then
    printf "%dh" "$(( delta / 3600 ))"
  else
    printf "%dm" "$(( delta / 60 ))"
  fi
}

# --- Context color based on usage percentage ---
if [ "$exceeds_200k" = "true" ] || [ "$ctx_pct" -ge 90 ] 2>/dev/null; then CTX_COLOR="$RED"
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
      last_msg="$(awk -v ms="$delta_ms" 'BEGIN { printf "%.1fs", ms/1000 }')"
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
if awk -v c="$cost" 'BEGIN { exit !(c > 1.0) }'; then COST_COLOR="$RED"
elif awk -v c="$cost" 'BEGIN { exit !(c > 0.25) }'; then COST_COLOR="$YELLOW"
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
line1="${BOLD}[${model}]${RESET}"
[ -n "$think_tag" ] && line1+=" ${think_tag}"
line1+=" "
ctx_pfx=""
[ "$exceeds_200k" = "true" ] && ctx_pfx="${RED}!${RESET}"
line1+="${ctx_pfx}${CTX_COLOR}${tok_used}${RESET}/${DIM}${tok_max}${RESET}"
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
  rst=""
  r=$(fmt_reset_delta "$rate_5h_resets"); [ -n "$r" ] && rst=" ${r}"
  line3_parts+=("${DIM}Rate 5h:${RESET} ${rc}$(printf "%.0f" "$rate_5h")%${RESET}${DIM}${rst}${RESET}")
fi
if [ -n "$rate_7d" ]; then
  rc=$(rate_color "$rate_7d")
  rst=""
  r=$(fmt_reset_delta "$rate_7d_resets"); [ -n "$r" ] && rst=" ${r}"
  line3_parts+=("${DIM}7d:${RESET} ${rc}$(printf "%.0f" "$rate_7d")%${RESET}${DIM}${rst}${RESET}")
fi
if [ -n "$agent_name" ]; then
  line3_parts+=("${CYAN}agent:${agent_name}${RESET}")
fi
if [ -n "$worktree_name" ]; then
  line3_parts+=("${CYAN}wt:${worktree_name}${RESET}")
fi
[ -n "$adv_tag" ] && line3_parts+=("$adv_tag")
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
