$ScriptPath = Join-Path $PSScriptRoot "install-opencode-routing.mjs"
node $ScriptPath @args
exit $LASTEXITCODE
