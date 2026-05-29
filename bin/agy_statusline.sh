#!/bin/bash
# agy cli statusline script
# Cross-platform: macOS, Linux, Windows (Git Bash). jq required.
# Copyright (c) 2026 @thejjw

# --- jq check ---
if ! command -v jq &>/dev/null; then
  echo "[!] jq not found -- install jq for statusline"
  exit 0
fi

# Read the live JSON payload from agy
payload=$(cat)

# Extract data using a single jq call
parsed=$(echo "$payload" | jq -rj '[
  (.cwd // "N/A"),
  (.model.display_name // "N/A"),
  (.agent_state // "idle"),
  (.context_window.used_percentage // 0),
  (.context_window.total_input_tokens // 0),
  (.context_window.total_output_tokens // 0),
  (.context_window.context_window_size // 0),
  (.plan_tier // "Standard"),
  (.email // "user"),
  (.sandbox.enabled // false)
] | map(tostring) | join("\u001f")')

IFS=$'\x1f' read -r cwd model agent_state used_pct_raw tokens_in tokens_out ctx_max plan email sandbox <<< "$parsed"

# Format percentage and token counts as human-readable values (e.g. 176K/1024K)
used_pct=$(awk -v p="$used_pct_raw" 'BEGIN {printf "%.1f", p}')
ctx_in_fmt=$(awk -v t="$tokens_in" 'BEGIN {printf "%.0fK", t/1000}')
ctx_out_fmt=$(awk -v t="$tokens_out" 'BEGIN {printf "%.0fK", t/1000}')
ctx_max_fmt=$(awk -v t="$ctx_max" 'BEGIN {printf "%.0fK", t/1000}')

# Format Git Branch
git_info=""
if git -C "$cwd" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    branch=$(git -C "$cwd" branch --show-current)
    git_info=" | 🌿 \033[32m${branch:-detached}\033[0m"
fi

# Format Sandbox Warning
sandbox_warn=""
if [ "$sandbox" == "true" ]; then
    sandbox_warn=" | 🔒 \033[31mSANDBOXED\033[0m"
fi

# Print it out with nice colors
echo -e "🧠 \033[35m$model\033[0m | 🔄 \033[36m$agent_state\033[0m | 📊 \033[33m$used_pct%\033[0m \033[36mR\033[33m${ctx_in_fmt}\033[0m+\033[31mW\033[33m${ctx_out_fmt}\033[0m/\033[32mT\033[33m${ctx_max_fmt}\033[0m | 📁 \033[34m$cwd\033[0m$git_info | 👤 \033[37m$email ($plan)\033[0m$sandbox_warn"
