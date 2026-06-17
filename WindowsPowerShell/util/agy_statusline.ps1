# Ensure console output encoding is UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Read JSON payload from stdin
$inputJson = [Console]::In.ReadToEnd()

if ($inputJson) {
    try {
        $state = ConvertFrom-Json $inputJson
        
        $cwd = if ($state.cwd) { $state.cwd } else { "N/A" }
        
        $model = "N/A"
        if ($state.model) {
            if ($state.model.display_name) {
                $model = $state.model.display_name
            } elseif ($state.model.name) {
                $model = $state.model.name
            }
        }
        
        $agentState = if ($state.agent_state) { $state.agent_state } else { "unknown-state" }
        
        $usedPct = 0.0
        $tokensIn = 0.0
        $tokensOut = 0.0
        $ctxMax = 0.0
        if ($state.context_window) {
            if ($state.context_window.used_percentage -ne $null) { $usedPct = [double]$state.context_window.used_percentage }
            if ($state.context_window.total_input_tokens -ne $null) { $tokensIn = [double]$state.context_window.total_input_tokens }
            if ($state.context_window.total_output_tokens -ne $null) { $tokensOut = [double]$state.context_window.total_output_tokens }
            if ($state.context_window.context_window_size -ne $null) { $ctxMax = [double]$state.context_window.context_window_size }
        }
        
        $plan = if ($state.plan_tier) { $state.plan_tier } else { "unknown-tier" }
        $email = if ($state.email) { $state.email } else { "unknown-user" }
        
        $sandbox = $false
        if ($state.sandbox -and $state.sandbox.enabled -eq $true) {
            $sandbox = $true
        }
        
        # Color codes (ANSI escape sequences)
        $esc = [char]27
        $reset = "$esc[0m"
        $bold = "$esc[1m"
        $green = "$esc[32m"
        $cyan = "$esc[36m"
        $yellow = "$esc[33m"
        $magenta = "$esc[35m"
        $blue = "$esc[34m"
        $red = "$esc[31m"
        $gray = "$esc[90m"
        $white = "$esc[37m"
        
        # Format percentage and tokens
        $usedPctFmt = "{0:N1}" -f $usedPct
        $ctxInFmt = "{0:N0}K" -f ($tokensIn / 1000)
        $ctxOutFmt = "{0:N0}K" -f ($tokensOut / 1000)
        $ctxMaxFmt = "{0:N0}K" -f ($ctxMax / 1000)
        
        # Normalize/shorten CWD
        $cwdNorm = $cwd -replace '\\', '/'
        $homeNorm = $env:USERPROFILE -replace '\\', '/'
        $cwdShort = $cwdNorm
        if ($cwdNorm.StartsWith($homeNorm, [System.StringComparison]::OrdinalIgnoreCase)) {
            $cwdShort = "~" + $cwdNorm.Substring($homeNorm.Length)
        }
        if ($cwdShort.Length -gt 30) {
            $cwdShort = ".../" + [System.IO.Path]::GetFileName($cwdNorm)
        }
        
        # Git branch info
        $gitInfo = ""
        if (Test-Path -LiteralPath $cwd) {
            $isInside = git -C $cwd rev-parse --is-inside-work-tree 2>$null
            if ($isInside -eq "true") {
                $branch = git -C $cwd branch --show-current 2>$null
                if ($branch) {
                    $branch = $branch.Trim()
                    if ($branch.Length -gt 15) {
                        $branch = $branch.Substring(0, 14) + "…"
                    }
                    $gitInfo = " | 🌿 ${green}${branch}${reset}"
                } else {
                    $gitInfo = " | 🌿 ${green}detached${reset}"
                }
            }
        }
        
        # Format Sandbox Warning
        $sandboxWarn = ""
        if ($sandbox) {
            $sandboxWarn = " | 🔒 ${red}SANDBOXED${reset}"
        }
        
        # Write Output
        $outputStr = "🧠 ${magenta}${model}${reset} | 🔄 ${cyan}${agentState}${reset} | 📊 ${yellow}${usedPctFmt}%${reset} ${blue}r${yellow}${ctxInFmt}${reset}+${red}w${yellow}${ctxOutFmt}${reset}/${gray}T${yellow}${ctxMaxFmt}${reset} | 📁 ${blue}${cwdShort}${reset}${gitInfo} | 👤 ${white}${plan} (${email})${reset}${sandboxWarn}"
        Write-Output $outputStr
        
    } catch {
        Write-Output "Status: Error parsing state"
    }
} else {
    Write-Output "Status: Idle"
}