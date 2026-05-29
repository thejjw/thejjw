#!/bin/bash
# Read the live JSON payload from agy
payload=$(cat)

# Extract data using jq
cwd=$(echo "$payload" | jq -r '.cwd // "N/A"')
model=$(echo "$payload" | jq -r '.model.display_name // "N/A"')
agent_state=$(echo "$payload" | jq -r '.agent_state // "idle"')
used_pct=$(echo "$payload" | jq -r '.context_window.used_percentage // 0' | awk '{printf "%.1f", $1}')
tokens_in=$(echo "$payload" | jq -r '.context_window.total_input_tokens // 0')
tokens_out=$(echo "$payload" | jq -r '.context_window.total_output_tokens // 0')
plan=$(echo "$payload" | jq -r '.plan_tier // "Standard"')
email=$(echo "$payload" | jq -r '.email // "user"')
sandbox=$(echo "$payload" | jq -r '.sandbox.enabled')

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
echo -e "🧠 \033[35m$model\033[0m | 🔄 \033[36m$agent_state\033[0m | 📊 \033[33m$used_pct% Ctx\033[0m ($tokens_in In/$tokens_out Out) | 📁 \033[34m$cwd\033[0m$git_info | 👤 \033[37m$email ($plan)\033[0m$sandbox_warn"
