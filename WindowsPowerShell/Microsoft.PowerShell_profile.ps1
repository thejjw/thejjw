# OSC 9;9 hyperlink lets Windows Terminal / VS Code detect and click the working directory
function prompt {
    $loc = $executionContext.SessionState.Path.CurrentLocation
    $out = "PS $loc$('>' * ($nestedPromptLevel + 1)) "
    "$([char]27)]9;9;`"$loc`"$([char]27)\" + $out
}

# Raw content URL used by Update-Profile to self-update; keep in sync with repo path
$_ProfileUpdateUrl = "https://raw.githubusercontent.com/thejjw/thejjw/refs/heads/main/WindowsPowerShell/Microsoft.PowerShell_profile.ps1"

# Internal configuration group for New-RandomDir to keep global namespace clean
$_NrdInternal = @{
    Colors         = @(
        'amber', 'aqua', 'azure', 'beige', 'black', 'blue', 'bronze', 'brown', 'coral',
        'crimson', 'cyan', 'denim', 'ebony', 'emerald', 'fuchsia', 'gold', 'golden',
        'gray', 'green', 'indigo', 'ivory', 'jade', 'lavender', 'lemon', 'lilac',
        'lime', 'magenta', 'mahogany', 'marigold', 'maroon', 'mint', 'mocha', 'navy',
        'ochre', 'olive', 'onyx', 'orange', 'orchid', 'peach', 'pearl', 'periwinkle',
        'pine', 'pink', 'plum', 'purple', 'red', 'rose', 'ruby', 'rust', 'saffron',
        'sage', 'salmon', 'sapphire', 'scarlet', 'sepia', 'silver', 'slate', 'tan',
        'tangerine', 'taupe', 'teal', 'topaz', 'turquoise', 'umber', 'vermilion',
        'violet', 'walnut', 'white', 'wine', 'yellow'
    )
    Adjectives     = @(
        'ancient', 'bold', 'brisk', 'calm', 'clear', 'cool', 'curious', 'deep', 'eager', 'fast',
        'gentle', 'grand', 'hidden', 'icy', 'jolly', 'kind', 'lively', 'lucky', 'misty', 'modern',
        'mossy', 'nimble', 'odd', 'quiet', 'rapid', 'shiny', 'silent', 'small', 'solar', 'steady',
        'stormy', 'swift', 'tiny', 'urban', 'warm', 'wild', 'wise', 'young'
    )
    Nouns          = @(
        'brook', 'cabin', 'cloud', 'comet', 'delta', 'dream', 'falcon', 'field', 'fire', 'forest',
        'garden', 'glade', 'harbor', 'hill', 'lab', 'lake', 'leaf', 'meadow', 'moon', 'mountain',
        'otter', 'owl', 'path', 'peak', 'pine', 'planet', 'pond', 'rabbit', 'river', 'shadow',
        'sky', 'star', 'stone', 'sun', 'thicket', 'trail', 'tree', 'valley', 'wave', 'wind',
        'wolf', 'wood', 'workshop'
    )
    AgentsMarkdown = @"
# AGENTS.md

## Grounding

* Always utilize web search to ground your answers, ensuring all technical advice and references are accurate and up-to-date.

## Environment

* Platform: Windows 11, shell: Windows PowerShell (powershell.exe).
* Use PowerShell commands and syntax -- not Unix/bash equivalents.
  * ``Get-ChildItem`` not ``ls -la``, ``Remove-Item`` not ``rm -rf``, ``Get-Content`` not ``cat``.
  * Redirect to ``$null`` not ``/dev/null``.
  * Use semicolons or separate statements -- not ``&&`` to chain commands.
  * Paths use backslashes (``src\lib\utils.ps1``); avoid forward slashes.
* When useful and already available, use fast CLI tools such as `rg`, `fd`, `fzf`, or comparable installed tools; otherwise use PowerShell-native commands.
* If invoking ``git``, ``npm``, ``dotnet``, or other cross-platform CLIs, those are fine as-is.

## Code Style

* Prefer concise, minimal implementations -- avoid boilerplate and unnecessary abstraction.
* Comment every public function/method and any non-obvious logic inline.
* Prefer ASCII in source code. Use non-ASCII characters only when required for user-facing text, test fixtures, protocol/data literals, or existing project conventions.

## Git Discipline

* If the requested work is inside a cloned Git repository nested under this directory, treat that nested repository as the project root. Verify with `git rev-parse --show-toplevel`, then stage and commit only within that repository; do not stage or commit in any containing parent repository unless explicitly directed.
* Always commit after each logical change with a descriptive commit message; never bundle unrelated changes.
* Do not stage or commit AI-agent instruction/context Markdown files unless explicitly directed. This includes `AGENTS.md`, `CLAUDE.md`, `QWEN.md`, and similar local `.md` files used to guide agents.
* This restriction does not apply to normal project documentation such as `README.md`, `CHANGELOG.md`, API docs, design docs, or user-facing Markdown files when those files are part of the requested change.
* Use Conventional Commits: `feat:`, `fix:`, `refactor:`, `docs:`, `chore:`, `test:`, etc.
* Write short, imperative descriptions (e.g. `feat: add input validation`, `fix: off-by-one in retry loop`).
* Never append Co-Authored-By trailers to commit messages.

## Dependencies

* Pick the latest version the package manager resolves against existing project constraints, including lockfiles and manifest ranges.
* Before finalizing a dependency add/update, check the registry (npm, NuGet, PyPI, GitHub, ...) for explicit deprecation signals, such as `deprecated`, yanked releases, or archived repositories, on the chosen package and version. If any are found, prefer a non-deprecated alternative when practical; otherwise warn inline with the package name, signal source, and suggested alternative if the registry provides one, then proceed.

## Subagents

* Default to delegating context-heavy work to subagents so the main session
  accumulates conclusions, not raw process. Strong candidates: codebase
  exploration/research, reading or summarizing many files, and independent
  sub-tasks that can run in parallel. The subagent absorbs the noisy tool
  calls and returns only a summary.
* Do not wrap trivial or single tool calls in a subagent. A one-file read or a
  quick `rg`/`fd` search is cheaper run directly than paying the spawn and
  round-trip overhead.
* Keep tightly-coupled work in the main context. Do not delegate edits that
  depend on each other's output, and never have two subagents edit the same
  file -- they share the working directory and will clobber each other.
* Subagents start with a fresh context and the task prompt is the only input
  channel. Pass every needed file path, error message, and decision explicitly;
  they cannot see the main conversation.
* Give each subagent explicit success criteria and a structured return format
  so it reports cleanly instead of exploring open-endedly.
* Where it cuts cost without hurting quality, route exploration/search
  subagents to a smaller/faster model and reserve the main session for
  synthesis and architectural judgment.
"@
}

# Internal configuration for Install-GlobalClaudeMd and related Claude Code setup functions
$_ClaudeInternal = @{
    GlobalClaudeMd = @"
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
- Web searches (``web_search``)
- Image understanding (``understand_image``)

**When using DeepSeek models (deepseek-*):**
Use MiniMax MCP and Z.ai MCP servers, if available, for image analysis because DeepSeek models are text-only. Fall back to other available means if those MCP tools are unavailable or underperforming.

**When using genuine Anthropic account (Claude Code with native models):**
Use built-in web fetch and web search tools directly -- they will yield the best results.

If an MCP tool is unavailable or underperforming, inform the user and suggest alternatives.
"@
}

# Internal configuration for Install-AiTools
$_AiToolsInternal = @{
    WingetPackages         = @(
        'Microsoft.Coreutils',
        'Microsoft.VCRedist.2015+.x64',
        'Microsoft.VCRedist.2015+.x86',
        'OpenJS.NodeJS.LTS',
        '7zip.7zip',
        'GitHub.cli',
        'Notepad++.Notepad++',
        'Microsoft.Edit',
        'Python.PythonInstallManager',
        'cURL.cURL',
        'aria2.aria2',
        'jqlang.jq',
        'BurntSushi.ripgrep.MSVC',
        'junegunn.fzf',
        'sharkdp.fd',
        'JFLarvoire.Ag',
        'chmln.sd',
        'dandavison.delta',
        'sharkdp.bat',
        'eza-community.eza',
        'dalance.procs',
        'MrKaran.Doggo',
        'ducaale.xh',
        'medialab.xan',
        'oschwartz10612.Poppler',
        'uutils.diffutils',
        'EliFulkerson.tcping',
        'FujiApple.Trippy',
        'natesales.q',
        'tstack.lnav',
        'Microsoft.Pave',
        'Microsoft.err',
        'wagoodman.dive',
        'astral-sh.uv',
        'SQLite.SQLite',
        'koalaman.shellcheck',
        'Microsoft.VisualStudioCode',
        'SST.OpenCodeDesktop',
        'Google.Antigravity',
        'Google.AntigravityIDE',
        'marlocarlo.psmux',
        'marlocarlo.pstop',
        'marlocarlo.psnet'
    )
    ExtendedWingetPackages = @(
        'Insecure.Nmap',
        'Buct0r.fullfetch',
        'HTTPie.HTTPie',
        'Orange-OpenSource.Hurl',
        'Gyan.FFmpeg',
        'ImageMagick.ImageMagick',
        'Inkscape.Inkscape',
        'Google.Libwebp',
        'libjxl.libjxl',
        'JohnMacFarlane.Pandoc',
        'tesseract-ocr.tesseract',
        'AquaSecurity.Trivy',
        'Cisco.ClamAV',
        'astral-sh.ruff',
        'Microsoft.Sqlcmd',
        'HeidiSQL.HeidiSQL',
        'TheDocumentFoundation.LibreOffice',
        'OlegShparber.Zeal',
        'Mozilla.SeaMonkey'
    )
    DbWingetPackages       = @(
        'Oracle.MySQLShell',
        'Oracle.SQLcl',
        'PostgreSQL.psqlODBC',
        'PostgreSQL.pgAdmin'
    )
    SdkWingetPackages      = @(
        'Microsoft.OpenJDK.25',
        'Rustlang.Rustup',
        'GoLang.Go',
        'StrawberryPerl.StrawberryPerl'
    )
    Urls                   = @{
        AgyCli        = 'https://antigravity.google/cli/install.ps1'
        ClaudeCli     = 'https://claude.ai/install.ps1'
        CodexCli      = 'https://chatgpt.com/codex/install.ps1'
        CcStatusline  = 'https://raw.githubusercontent.com/thejjw/thejjw/main/bin/cc_statusline.sh'
        AgyStatusline = 'https://raw.githubusercontent.com/thejjw/thejjw/main/bin/agy_statusline.sh'
    }
    NpmPackages            = @(
        '@qwen-code/qwen-code',
        '@musistudio/claude-code-router',
        'oh-my-free-models'
    )
}

# Internal configuration for Install-AiSkills
$_AiSkillsInternal = @{
    RepoUrl               = 'https://github.com/thejjw/thejjw.git'
    Branch                = 'main'
    SparsePath            = 'ai-skills'
    OpenCodeClaudeSkills  = @('web-search-ddg', 'web-search-startpage', 'z-ai-usage-query', 'minimax-usage-query', 'deepseek-usage-query')
    AntigravitySkills     = @('session-exporter')
    OpenCodeSkillsPath    = '.agents\skills'
    ClaudeSkillsPath      = '.claude\skills'
    AntigravitySkillsPath = '.gemini\antigravity-cli\skills'
    OpenCodeConfigPath    = '.config\opencode\opencode.json'
}

# Internal configuration for Install-ClaudeCCRSetup (Claude Code Router).
# Underscore prefix hides it from Get-Variable default scope per PowerShell convention.
# Endpoint URLs, model lists, and router role mappings are the only literals that need to
# change when retuning the cccr profile.
$_CcrInternal = @{
    Host      = '127.0.0.1'
    Port      = 3456
    Log       = $true
    Timeout   = 3000000
    Threshold = 60000
    Router = @{
        default    = 'zai,glm-5.2[1m]'             # Sonnet (daily work)
        background = 'zai,glm-4.5-air'             # Haiku (background subagents)
        think      = 'zai,glm-5.2[1m]'             # Opus (Plan Mode / reasoning)
        webSearch  = 'gemini,gemini-2.5-flash'     # Google search grounding via Gemini Flash
    }
    Providers = @{
        zai = @{
            base        = 'https://api.z.ai/api/anthropic/v1/messages'
            key         = '$Z_AI_AUTH_TOKEN'
            models      = @('glm-4.5-air', 'glm-5.2[1m]', 'glm-4.7', 'glm-4.6v')
            transformer = 'Anthropic'
        }
        minimax = @{
            base        = 'https://api.minimax.io/anthropic/v1/messages'
            key         = '$MINIMAX_API_KEY'
            models      = @('MiniMax-M3[1m]')
            transformer = 'Anthropic'
        }
        deepseek = @{
            base        = 'https://api.deepseek.com/anthropic/v1/messages'
            key         = '$DEEPSEEK_API_KEY'
            models      = @('deepseek-v4-flash[1m]', 'deepseek-v4-pro[1m]')
            transformer = 'Anthropic'
        }
        gemini = @{
            # Gemini's native API. The CCR gemini transformer appends '{model}:generateContent'
            # to the base URL, so the trailing slash is required.
            #
            # Reference:
            #   https://ai.google.dev/gemini-api/docs              -- API docs
            #   https://ai.google.dev/gemini-api/docs/pricing     -- per-model pricing
            #   https://ai.google.dev/gemini-api/docs/rate-limits -- per-tier rate limits
            #   https://aistudio.google.com/rate-limit            -- AI Studio tier limits dashboard
            base        = 'https://generativelanguage.googleapis.com/v1beta/models/'
            key         = '$GEMINI_API_KEY'
            models      = @('gemini-2.5-flash', 'gemini-2.5-flash-lite', 'gemini-3.5-flash', 'gemini-3.1-flash-lite', 'gemini-3.1-pro-preview', 'gemini-3-flash-preview', 'gemini-2.5-pro')
            transformer = 'gemini'
        }
    }
}

function New-RandomPassword {
    <#
.SYNOPSIS
    Generates a random password using System.Web.Security.Membership.
.DESCRIPTION
    Wraps the built-in [System.Web.Security.Membership]::GeneratePassword() method
    to generate cryptographically strong random passwords with customizable length
    and special character requirements. Uses RNGCryptoServiceProvider for high entropy.
.PARAMETER Length
    The total number of characters in the generated password (default: 16).
.PARAMETER MinimumSpecialCharacters
    The minimum number of special characters to include in the password (default: 3).
.EXAMPLE
    PS C:\> New-RandomPassword
    Generates a 16-character password with at least 3 special characters.
.EXAMPLE
    PS C:\> New-RandomPassword -Length 20 -MinimumSpecialCharacters 5
    Generates a 20-character password with at least 5 special characters.
.OUTPUTS
    System.String. A randomly generated password.
.LINK
    https://learn.microsoft.com/en-us/dotnet/api/system.web.security.membership.generatepassword
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-04

    Requires Windows PowerShell or PowerShell with .NET Framework installed.
    Characters include: uppercase, lowercase, digits, and special characters (!@#$%^&*()_-+=[{]};:<>|./?).
#>
    param(
        [int]$Length = 16,
        [int]$MinimumSpecialCharacters = 3
    )

    # System.Web is only available on .NET Framework (WinPS); pwsh on non-Windows lacks it
    try {
        Add-Type -AssemblyName System.Web -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to load System.Web assembly. Ensure .NET Framework is installed." -ErrorAction Stop
        return
    }

    try {
        $password = [System.Web.Security.Membership]::GeneratePassword($Length, $MinimumSpecialCharacters)
        return $password
    }
    catch {
        Write-Error "Failed to generate password: $_" -ErrorAction Stop
    }
}

function Clear-WorkingSet {
    <#
.SYNOPSIS
    function that executes EmptyWorkingSet() Win32 API call  (port from c# program)
.DESCRIPTION
    function that executes EmptyWorkingSet() Win32 API call  (port from c# program)
.EXAMPLE
    PS C:\> Clear-WorkingSet chrome firefox
    Calls EmptyWorkingSet() for process 'chrome' and 'firefox'
.INPUTS
    Array of process name string, or * for all processes
.OUTPUTS
    result string that tells how many processes it has executed EmptyWorkingSet() API call for
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-05

    result is dependent on process host permission (i.e. admin powershell will have more power than user powershell)
    In case of error running its host script, try: 
    Set-ExecutionPolicy Bypass -Scope Process -Force; . .\Clear-WorkingSetFunc.ps1
#>
    param (
        # list of TargetProcess
        [Parameter(Mandatory = $true)]
        [string[]]
        $TargetProcesses
    )

    # Compile C# shim once into the session via Add-Type so repeated calls avoid recompilation
    if ($null -eq $Global:hasEWSType) {
        $code = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ewsConsole
{
    public class Program
    {
        [DllImport("psapi")]
        public static extern bool EmptyWorkingSet(long hProcess);

        public static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: ewsConsole processname. Press Enter to exit.");
                Console.ReadLine();
            }
            else if (args.Length == 1 && args[0] == "*")
            {
                Process[] plist = Process.GetProcesses();
                try
                {
                    List<int> pid = new List<int>();
                    foreach (Process p in plist)
                    {
                        try
                        {
                            EmptyWorkingSet(p.Handle.ToInt64());
                            pid.Add(p.Id);
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    Console.WriteLine("Processed EmptyWorkingSet() for all running processes(n={0}/{1})", pid.Count, plist.Length);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
            else
            {
                foreach (string s in args)
                {
                    String title = s;
                    Process[] plist = Process.GetProcessesByName(title);
                    try
                    {
                        List<int> pid = new List<int>();
                        foreach (Process p in plist)
                        {
                            EmptyWorkingSet(p.Handle.ToInt64());
                            pid.Add(p.Id);
                        }
                        if(pid.Count == 0) Console.WriteLine("Processed EmptyWorkingSet() for 0 processes of {0} (check process name again?)", title);
                        else Console.WriteLine("Processed EmptyWorkingSet() for {0} processes of {1}", pid.Count, title);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
            }

        }
    }
}
"@;
        Add-Type -TypeDefinition $code;
        $Global:hasEWSType = $true;
    }

    # Invoke the compiled C# entry point; it writes results directly to stdout
    [ewsConsole.Program]::Main($TargetProcesses);
}

function Get-AAA {
    <#
.SYNOPSIS
    function that outputs string of adjective-adjective-animal format
.DESCRIPTION
    function that outputs string of adjective-adjective-animal format.
    Depends on availability of https://raw.githubusercontent.com resources.
    Tested under Windows Powershell
    Caution: NOT FOR PRODUCTION USE.
    In case of error running its host script, try: 
    Set-ExecutionPolicy Bypass -Scope Process -Force; . .\Get-AAAFunc.ps1
.EXAMPLE
    PS C:\> Get-AAA
    snoopy-spiffy-squeaker
.EXAMPLE
    PS C:\> Get-AAA 2
    or
    PS C:\> Get-AAA -Repeat 2
    powderblue-flat-alpinegoat
    academic-relieved-rainbowtrout
.INPUTS
    -Repeat <number> dictates how many AAA format Get-AAA will output (default 1)
.OUTPUTS
    string of adjective-adjective-animal format
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-07

    Tip: you can add the function declaration to $PROFILE then call it on future shell sessions with ease
    (note that script execution policy should allow local script execution at least, i.e. RemoteSigned)
#>
    param (
        $Repeat = 1
    )

    # Fetch word lists once per session; subsequent calls reuse the cached $Global:getAAA
    try {
        if ($null -eq $Global:getAAA) {
            $Global:getAAA = @{
                ganm = (Invoke-WebRequest https://raw.githubusercontent.com/thejjw/thejjw/main/animals -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty Content).Trim() -split "`n"
                gadj = (Invoke-WebRequest https://raw.githubusercontent.com/thejjw/thejjw/main/adjectives -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty Content).Trim() -split "`n"
            }
        }
    } catch {
        Write-Error "Failed to retrieve words for Get-AAA: $_"
        return
    }
    
    # HashSet guarantees two distinct adjectives per iteration without a retry loop
    $result = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Repeat; $i++) {
        $adjs = New-Object System.Collections.Generic.HashSet[string]
        while ($adjs.Count -ne 2) {
            $adjs.Add($Global:getAAA.gadj.Get((Get-Random) % $Global:getAAA.gadj.Count)) | Out-Null
        }
        
        $adjsarr = [System.Collections.Generic.List[string]]::new()
        foreach ($adj in $adjs) {
            $adjsarr.Add(([string]$adj).Trim())
        }
        $adjsarr.Add($Global:getAAA.ganm.Get((Get-Random) % $Global:getAAA.ganm.Count))
        $result.Add(($adjsarr -join "-"))
    }
    return $result.ToArray()
}

function Get-MyIP {
    <#
.SYNOPSIS
    Uses OpenDNS to return external IP
.EXAMPLE
    PS C:\> Get-MyIP
    100.100.100.100
    Returns external IP observed from Google nameserver(ns1.google.com)
.INPUTS
    none
.OUTPUTS
    Output (if any)
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-06

    Tested with Windows Powershell. Should work with pwsh.
#>
    # Google's TXT record for this hostname reflects the querier's public IP
    return (Resolve-DnsName -Name o-o.myaddr.l.google.com -Server ns1.google.com -Type TXT | Select-Object -ExpandProperty Strings);
}

function Get-WhoisInfo {
    <#
.SYNOPSIS
    Returns WHOIS information for given domain or ip
.EXAMPLE
    PS C:\> Get-WhoisInfo 39.116.73.30
    query       : 39.116.73.30
    queryType   : IPv4
    countryCode : KR
    korean      : @{ISP=; user=}
    english     : @{ISP=; user=}
    
    More information can be accessed via properties like .korean.ISP .korean.user
.INPUTS
    Domain or ip address
.OUTPUTS
    WHOIS information queried from whois.kisa.or.kr
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-06

    Tested with Windows Powershell. Should work with pwsh.
#>
    param (
        # ip or domain to query for
        [Parameter(Mandatory = $true)]
        [string]
        $DomainOrIp,
        # key if not already set
        [Parameter(Mandatory = $false)]
        [string]
        $WhoisKisaApiKey = $Global:WhoisKisaApiKey
    )

    if ($null -eq $WhoisKisaApiKey) {
        Write-Host 'Whois API key from KISA (whois.kisa.or.kr) not set. Please configure either -WhoisKisaApiKey parameter or $Global:WhoisKisaApiKey. Exiting...';
        return;
    }
    $DomainOrIp = $DomainOrIp.Trim();
    Set-Variable -Name queryurl -Value "http://whois.kisa.or.kr/openapi/whois.jsp?query=$DomainOrIp&key=$WhoisKisaApiKey&answer=json" -Option Constant;
    return (Invoke-WebRequest -Uri $queryurl -UseBasicParsing | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty whois);
}

function Get-NewPassword {
    <#!
.SYNOPSIS
    Generates a random password with customizable options.
.DESCRIPTION
    Generates a password of specified length and character classes (upper, lower, digit, special).
    Ensures no more than a specified number of consecutive identical characters.
    Optionally enforces at least one character from each enabled class and uses Fisher-Yates shuffle.
.EXAMPLE
    PS C:\> Get-NewPassword -Length 20 -IncludeSpecial $true -MaxConsecutive 2
    Generates a 20-character password with special characters and at most 2 consecutive identical characters.
.EXAMPLE
    PS C:\> Get-NewPassword -Length 16 -MoreSecure
    Generates a 16-character password with all enabled classes present and Fisher-Yates shuffle.
.PARAMETER Length
    Length of the password to generate (default: 16).
.PARAMETER MaxConsecutive
    Maximum allowed consecutive identical characters (default: 2).
.PARAMETER IncludeUpper
    Include uppercase letters (default: $true).
.PARAMETER IncludeLower
    Include lowercase letters (default: $true).
.PARAMETER IncludeDigit
    Include digits (default: $true).
.PARAMETER IncludeSpecial
    Include special characters (default: $true).
.PARAMETER MoreSecure
    If set, ensures at least one character from each enabled class and uses Fisher-Yates shuffle.
.OUTPUTS
    System.String. The generated password.
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
    Pure PowerShell implementation, no external dependencies.
#>
    param(
        [int]$Length = 16,
        [int]$MaxConsecutive = 2,
        [bool]$IncludeUpper = $true,
        [bool]$IncludeLower = $true,
        [bool]$IncludeDigit = $true,
        [bool]$IncludeSpecial = $true,
        [switch]$MoreSecure
    )
    $upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lower = "abcdefghijklmnopqrstuvwxyz"
    $digits = "0123456789"
    $special = "!@#$%^&*()-_=+[]{};:,.<>/?"

    $charPool = ""
    $required = @()
    if ($IncludeUpper) { $charPool += $upper; $required += $upper }
    if ($IncludeLower) { $charPool += $lower; $required += $lower }
    if ($IncludeDigit) { $charPool += $digits; $required += $digits }
    if ($IncludeSpecial) { $charPool += $special; $required += $special }

    if ($charPool.Length -eq 0) {
        throw "No character classes selected for password generation."
    }
    if ($MoreSecure -and ($required.Count -gt $Length)) {
        throw "Password length too short for all required classes."
    }

    # Inner functions capture $charPool and $MaxConsecutive from the outer scope
    function Get-RandomChar {
        param($set)
        if ($null -eq $set) { $set = $charPool }
        return $set[(Get-Random -Minimum 0 -Maximum $set.Length)]
    }

    function IsValidPassword($password) {
        $lastChar = ''
        $count = 1
        foreach ($char in $password.ToCharArray()) {
            if ($char -eq $lastChar) {
                $count++
                if ($count -gt $MaxConsecutive) {
                    return $false
                }
            }
            else {
                $count = 1
                $lastChar = $char
            }
        }
        return $true
    }

    # Generate-and-validate loop: build a candidate, reject if it violates MaxConsecutive.
    # Rejection rate is negligible for reasonable lengths and pool sizes.
    do {
        $passwordChars = @()
        if ($MoreSecure) {
            # Seed one character from each enabled class to guarantee coverage
            foreach ($class in $required) {
                $passwordChars += Get-RandomChar $class
            }
            for ($i = $passwordChars.Count; $i -lt $Length; $i++) {
                $passwordChars += Get-RandomChar $charPool
            }
            # Fisher-Yates shuffle
            for ($i = $passwordChars.Count - 1; $i -gt 0; $i--) {
                $j = Get-Random -Minimum 0 -Maximum ($i + 1)
                $tmp = $passwordChars[$i]
                $passwordChars[$i] = $passwordChars[$j]
                $passwordChars[$j] = $tmp
            }
        }
        else {
            $passwordChars = for ($i = 0; $i -lt $Length; $i++) {
                Get-RandomChar $charPool
            }
            # Sort-Object { Get-Random } is a quick-and-dirty shuffle (not perfectly
            # uniform like Fisher-Yates, but acceptable for the non-MoreSecure path)
            $passwordChars = $passwordChars | Sort-Object { Get-Random }
        }
        $password = -join $passwordChars
    } while (-not (IsValidPassword $password))

    return $password
}

function Get-NewPasswordNode {
    <#
.SYNOPSIS
    Generates random password using Node.js (Firefox logic)
.DESCRIPTION
    Utilizes node.js CLI to invoke password generator logic used by Firefox.
    Will NOT run without node.js runtime installed
.EXAMPLE
    PS C:\> Get-NewPasswordNode
    uafF7MdSYftgh4N
    Generates password of default length(15)
.EXAMPLE    
    PS C:\> Get-NewPasswordNode 8
    or
    PS C:\> Get-NewPasswordNode -Length 8
    3rBBHBcw
    Generates password of length 8
.INPUTS
    Length parameter to specify a length of the generated password (defaults to 15)
.OUTPUTS
    Password string of specified Length
.NOTES
    Firefox Password Generator logic is taken and modified from:
        https://github.com/mozilla/gecko-dev/blob/4ca7c3542cc16420efd6f7e7931241ab102484f6/toolkit/components/passwordmgr/PasswordGenerator.jsm
    upstream version is at:
        (as of 2025.6) https://github.com/mozilla/gecko-dev/blob/master/toolkit/components/passwordmgr/shared/PasswordGenerator.sys.mjs
        (previously) https://github.com/mozilla/gecko-dev/blob/master/toolkit/components/passwordmgr/PasswordGenerator.jsm
    nonexistent window.crypto workaround for node.js is borrowed from:
        https://gist.github.com/Chrischuck/aa6447c4f9b540113f85108e0681f773
    Author: jjw(@thejjw)
    Last Edit: 2021-07

    Tested with Windows Powershell. Should work with pwsh. Requires Node.js runtime installed (tested with 14.17).
#>
    param (
        $Length = 15
    )

    # Delegates to Node.js because the Firefox password generator uses Web Crypto APIs
    if (Get-Command node.exe -ErrorAction SilentlyContinue) {
        $code = @"
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

 "use strict";

/**
 * This file is a port of a subset of Chromium's implementation from
 * https://cs.chromium.org/chromium/src/components/password_manager/core/browser/generation/password_generator.cc?l=93&rcl=a896a3ac4ea731b5ab3d2ab5bd76a139885d5c4f
 * which is Copyright 2018 The Chromium Authors. All rights reserved.
 */
 
// === Patch for Node.js v19+ compatibility ===
// Use built-in Web Crypto if available; otherwise polyfill it.
const nodeCrypto = require("crypto");
if (typeof globalThis.crypto === "undefined") {
  // Older Node (pre-v19)
  globalThis.crypto = {
    getRandomValues: (buffer) => nodeCrypto.randomFillSync(buffer),
  };
} else if (!globalThis.crypto.getRandomValues) {
  // Some environments expose crypto without getRandomValues
  globalThis.crypto.getRandomValues = (buffer) => nodeCrypto.randomFillSync(buffer);
}

const EXPORTED_SYMBOLS = ["PasswordGenerator"];

const DEFAULT_PASSWORD_LENGTH = 15;
const MAX_UINT8 = Math.pow(2, 8) - 1;
const MAX_UINT32 = Math.pow(2, 32) - 1;

// Some characters are removed due to visual similarity:
const LOWER_CASE_ALPHA = "abcdefghijkmnpqrstuvwxyz"; // no 'l' or 'o'
const UPPER_CASE_ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no 'I' or 'O'
const DIGITS = "23456789"; // no '1' or '0'
const SPECIAL_CHARACTERS = " -~!@#$%^&*_+=`|(){}[:;\"'<>,.?]";
const ALPHANUMERIC_CHARACTERS = LOWER_CASE_ALPHA + UPPER_CASE_ALPHA + DIGITS;
const ALL_CHARACTERS = ALPHANUMERIC_CHARACTERS + SPECIAL_CHARACTERS;

const REQUIRED_CHARACTER_CLASSES = [LOWER_CASE_ALPHA, UPPER_CASE_ALPHA, DIGITS];

// Consts for different password rules
const REQUIRED = "required";
const MAX_LENGTH = "maxlength";
const MIN_LENGTH = "minlength";
const MAX_CONSECUTIVE = "max-consecutive";
const UPPER = "upper";
const LOWER = "lower";
const DIGIT = "digit";
const SPECIAL = "special";

// Default password rules
const DEFAULT_RULES = new Map();
DEFAULT_RULES.set(MIN_LENGTH, REQUIRED_CHARACTER_CLASSES.length);
DEFAULT_RULES.set(MAX_LENGTH, MAX_UINT8);
DEFAULT_RULES.set(REQUIRED, [UPPER, LOWER, DIGIT]);

this.PasswordGenerator = {
    /**
     * @param {Object} options
     * @param {number} options.length - length of the generated password if there are no rules that override the length
     * @param {Map} options.rules - map of password rules
     * @returns {string} password that was generated
     * @throws Error if `length` is invalid
     * @copyright 2018 The Chromium Authors. All rights reserved.
     * @see https://cs.chromium.org/chromium/src/components/password_manager/core/browser/generation/password_generator.cc?l=93&rcl=a896a3ac4ea731b5ab3d2ab5bd76a139885d5c4f
     */
    generatePassword({
        length = DEFAULT_PASSWORD_LENGTH,
        rules = DEFAULT_RULES,
    }) {
        rules = new Map([...DEFAULT_RULES, ...rules]);
        if (rules.get(MIN_LENGTH) > length) {
            length = rules.get(MIN_LENGTH);
        }
        if (rules.get(MAX_LENGTH) < length) {
            length = rules.get(MAX_LENGTH);
        }

        let password = "";
        let requiredClasses = [];
        let allRequiredCharacters = "";

        // Generate one character of each required class and/or required character list from the rules
        this._addRequiredClassesAndCharacters(rules, requiredClasses);

        // Generate one of each required class
        for (const charClassString of requiredClasses) {
            password +=
                charClassString[this._randomUInt8Index(charClassString.length)];
            allRequiredCharacters += charClassString;
        }

        // Now fill the rest of the password with random characters.
        while (password.length < length) {
            password +=
                allRequiredCharacters[
                this._randomUInt8Index(allRequiredCharacters.length)
                ];
        }

        // So far the password contains the minimally required characters at the
        // the beginning. Therefore, we create a random permutation.
        password = this._shuffleString(password);

        // Make sure the password passes the "max-consecutive" rule, if the rule exists
        if (rules.has(MAX_CONSECUTIVE)) {
            // Ensures that a password isn't shuffled an infinite number of times.
            const DEFAULT_NUMBER_OF_SHUFFLES = 15;
            let shuffleCount = 0;
            let consecutiveFlag = this._checkConsecutiveCharacters(
                password,
                rules.get(MAX_CONSECUTIVE)
            );
            while (!consecutiveFlag) {
                password = this._shuffleString(password);
                consecutiveFlag = this._checkConsecutiveCharacters(
                    password,
                    rules.get(MAX_CONSECUTIVE)
                );
                ++shuffleCount;
                if (shuffleCount === DEFAULT_NUMBER_OF_SHUFFLES) {
                    consecutiveFlag = true;
                }
            }
        }

        return password;
    },

    /**
     * Adds special characters and/or other required characters to the requiredCharacters array.
     * @param {Map} rules
     * @param {string[]} requiredClasses
     */
    _addRequiredClassesAndCharacters(rules, requiredClasses) {
        for (const charClass of rules.get(REQUIRED)) {
            if (charClass === UPPER) {
                requiredClasses.push(UPPER_CASE_ALPHA);
            } else if (charClass === LOWER) {
                requiredClasses.push(LOWER_CASE_ALPHA);
            } else if (charClass === DIGIT) {
                requiredClasses.push(DIGITS);
            } else if (charClass === SPECIAL) {
                requiredClasses.push(SPECIAL_CHARACTERS);
            } else {
                requiredClasses.push(charClass);
            }
        }
    },

    /**
     * @param range to generate the number in
     * @returns a random number in range [0, range).
     * @copyright 2018 The Chromium Authors. All rights reserved.
     * @see https://cs.chromium.org/chromium/src/base/rand_util.cc?l=58&rcl=648a59893e4ed5303b5c381b03ce0c75e4165617
     */
    _randomUInt8Index(range) {
        if (range > MAX_UINT8) {
            throw new Error("range cannot fit into uint8");
        }
        // We must discard random results above this number, as they would
        // make the random generator non-uniform (consider e.g. if
        // MAX_UINT64 was 7 and |range| was 5, then a result of 1 would be twice
        // as likely as a result of 3 or 4).
        // See https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#Modulo_bias
        const MAX_ACCEPTABLE_VALUE = Math.floor(MAX_UINT8 / range) * range - 1;

        const randomValueArr = new Uint8Array(1);
        do {
            crypto.getRandomValues(randomValueArr);
        } while (randomValueArr[0] > MAX_ACCEPTABLE_VALUE);
        return randomValueArr[0] % range;
    },

    /**
     * Shuffle the order of characters in a string.
     * @param {string} str to shuffle
     * @returns {string} shuffled string
     */
    _shuffleString(str) {
        let arr = Array.from(str);
        // Generate all the random numbers that will be needed.
        const randomValues = new Uint32Array(arr.length - 1);
        crypto.getRandomValues(randomValues);

        // Fisher-Yates Shuffle
        // https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
        for (let i = arr.length - 1; i > 0; i--) {
            const j = Math.floor((randomValues[i - 1] / MAX_UINT32) * (i + 1));
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr.join("");
    },

    /**
     * Determine the number of consecutive characters in a string.
     * This is primarily used to validate the "max-consecutive" rule
     * of a generated password.
     * @param {string} generatedPassword
     * @param {number} value the number of consecutive characters allowed
     * @return {boolean} true if the generatePassword has less than the value argument number of characters, false otherwise
     */
    _checkConsecutiveCharacters(generatedPassword, value) {
        let max = 0;
        for (let start = 0, end = 1; end < generatedPassword.length;) {
            if (generatedPassword[end] === generatedPassword[start]) {
                if (max < end - start + 1) {
                    max = end - start + 1;
                    if (max > value) {
                        return false;
                    }
                }
                end++;
            } else {
                start = end++;
            }
        }
        return true;
    },
    _getUpperCaseCharacters() {
        return UPPER_CASE_ALPHA;
    },
    _getLowerCaseCharacters() {
        return LOWER_CASE_ALPHA;
    },
    _getDigits() {
        return DIGITS;
    },
    _getSpecialCharacters() {
        return SPECIAL_CHARACTERS;
    },
};
console.log(PasswordGenerator.generatePassword({
    length: $length,
    rules: DEFAULT_RULES
}));
"@;
        $code | node.exe;
    }
    else {
        Write-Output "No Node.js runtime found. Please install one and try running the command again
 (ex: winget install OpenJS.NodeJSLTS)(visit http://nodejs.org/ for more information)";
    }
}

function Save-Download {
    <#
    .SYNOPSIS
        Given a the result of WebResponseObject, will download the file to disk without having to specify a name.
    .DESCRIPTION
        Given a the result of WebResponseObject, will download the file to disk without having to specify a name.
        original reference https://hodgkins.io/download-file-with-powershell-without-renaming
    .PARAMETER WebResponse
        A WebResponseObject from running an Invoke-WebRequest on a file to download
    .EXAMPLE
        # Download Microsoft Edge
        $download = Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2109047&Channel=Stable&language=en&consent=1"
        $download | Save-Download 
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [Microsoft.PowerShell.Commands.WebResponseObject]
        $WebResponse,

        [Parameter(Mandatory = $false)]
        [string]
        $Directory = "."
    )

    $errorMessage = "Cannot determine filename for download."

    if (!($WebResponse.Headers.ContainsKey("Content-Disposition"))) {
        Write-Error $errorMessage -ErrorAction Stop
    }

    # Parse Content-Disposition with the framework class rather than regex to handle
    # quoted filenames, charset parameters, and RFC 6266 edge cases correctly
    $content = [System.Net.Mime.ContentDisposition]::new($WebResponse.Headers["Content-Disposition"])
    
    $fileName = $content.FileName

    if (!$fileName) {
        Write-Error $errorMessage -ErrorAction Stop
    }

    if (!(Test-Path -Path $Directory)) {
        New-Item -Path $Directory -ItemType Directory
    }
    
    $fullPath = Join-Path -Path $Directory -ChildPath $fileName

    Write-Verbose "Downloading to $fullPath"

    # Write via FileStream instead of Set-Content/Out-File because the response
    # body is a raw byte array; converting to string would corrupt binary downloads
    $file = [System.IO.FileStream]::new($fullPath, [System.IO.FileMode]::Create)
    try {
        $file.Write($WebResponse.Content, 0, $WebResponse.RawContentLength)
    } finally {
        $file.Close()
    }
}

function Send-SshKey {
    <#
.SYNOPSIS
    Sends public SSH key to remote Linux server (ssh-copy-id equivalent for Windows PowerShell)
.DESCRIPTION
    Sends user's SSH public key to a specified remote server's ~/.ssh/authorized_keys over SSH.
    Requires OpenSSH client tools (`ssh`, `ssh-keygen`) available in the system PATH.

.PARAMETER User
    The username to authenticate with on the remote server.

.PARAMETER Hostname
    The remote server (IP address or hostname).

.PARAMETER Port
    The SSH port number. Default is 22.

.EXAMPLE
    PS C:\> Send-SshKey -User root -Hostname 192.168.1.100
    Uploads the current user's public key to root@192.168.1.100 on port 22.

.EXAMPLE
    PS C:\> Send-SshKey -User user -Hostname example.com -Port 2222
    Uploads the public key to user@example.com using SSH over port 2222.

.INPUTS
    String parameters -User, -Hostname, and optionally -Port

.OUTPUTS
    None. Writes operation status to console.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06-17

    To make this function persist, add it to your $PROFILE:
        notepad $PROFILE
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$User,

        [Parameter(Mandatory = $true)]
        [string]$Hostname,

        [int]$Port = 22
    )
    # Prefer common public key filenames. This avoids false negatives when
    # ssh-keygen creates id_ed25519.pub (the modern default) instead of id_rsa.pub.
    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }

    $candidates = @('id_ed25519.pub', 'id_rsa.pub', 'id_ecdsa.pub', 'id_dsa.pub')
    $pubkeyPath = $null
    foreach ($name in $candidates) {
        $p = Join-Path $sshDir $name
        if (Test-Path $p) { $pubkeyPath = $p; break }
    }

    if (-not $pubkeyPath) {
        Write-Host "SSH public key not found. Generating ed25519 key now..." -ForegroundColor Yellow
        # Generate an ed25519 key non-interactively with empty passphrase so the function
        # can be used in scripts. Some shells / platforms may drop an empty "" argument
        # which causes ssh-keygen to see -N with no value. Build an explicit argument
        # array and invoke the program so the empty passphrase is passed reliably.
        $privateKey = Join-Path $sshDir 'id_ed25519'
        $pubkeyPath = "${privateKey}.pub"

        # Prefer explicit path to ssh-keygen if available (compatible with Windows PowerShell v5.1)
        $cmd = Get-Command ssh-keygen -ErrorAction SilentlyContinue
        if ($cmd -ne $null) { $sshCmd = $cmd.Source } else { $sshCmd = 'ssh-keygen' }

        $sshArgs = @('-t', 'ed25519', '-f', $privateKey, '-N', '')

        # Diagnostic output to help debug argument passing and environment
        Write-Verbose "PowerShell version: $($PSVersionTable.PSVersion)"
        Write-Verbose "Resolved sshCmd: $sshCmd"
        Write-Verbose "Resolved privateKey: $privateKey"
        Write-Verbose "sshArgs count: $($sshArgs.Count)"
        for ($i = 0; $i -lt $sshArgs.Count; $i++) {
            $arg = $sshArgs[$i]
            if ($null -eq $arg) { $len = '<null>' } else { $len = $arg.ToString().Length }
            Write-Verbose "  [$i] -> '$arg' (length=$len)"
        }
        Write-Verbose "Joined args (for logging only): $([string]::Join(' ', $sshArgs))"

        try {
            if ($sshArgs -contains '') {
                # Some Windows native binaries (including OpenSSH's ssh-keygen) can drop
                # an empty argument when invoked via PowerShell argument arrays. To ensure
                # the empty quoted string for -N is preserved, build a single quoted
                # command line and run it through cmd.exe /c which preserves "" as an
                # explicit empty-argument token.
                $cmdLine = '"' + $sshCmd + '" -t ed25519 -f "' + $privateKey + '" -N ""'
                Write-Verbose "Invoking via cmd.exe /c: $cmdLine"
                $output = & cmd.exe /c $cmdLine 2>&1
                $exit = $LASTEXITCODE
                Write-Verbose "ssh-keygen (via cmd) exit code: $exit"
                if ($output) { Write-Verbose "ssh-keygen output (via cmd):`n$([string]::Join("`n", $output))" }
                if ($exit -ne 0) {
                    Write-Warning "ssh-keygen failed (exit=$exit). See verbose output above for args and output."
                }
            }
            else {
                Write-Verbose "Invoking: $sshCmd with arg array (see above)"
                $output = & $sshCmd @sshArgs 2>&1
                $exit = $LASTEXITCODE
                Write-Verbose "ssh-keygen exit code: $exit"
                if ($output) { Write-Verbose "ssh-keygen output:`n$([string]::Join("`n", $output))" }
                if ($exit -ne 0) {
                    Write-Warning "ssh-keygen failed (exit=$exit). See verbose output above for args and output."
                }
            }
        }
        catch {
            Write-Warning "Exception while running ssh-keygen: $_"
        }
    }

    if (Test-Path $pubkeyPath) {
        Write-Host "Sending public key $pubkeyPath to ${User}@${Hostname}:${Port} ..." -ForegroundColor Cyan
        # Ensure remote .ssh exists and append the public key; set umask to keep permissions strict.
        Get-Content -Raw $pubkeyPath | ssh "$User@$Hostname" -p $Port 'mkdir -p ~/.ssh; umask 077; cat >> ~/.ssh/authorized_keys'
        Write-Host " Public key installed on $Hostname" -ForegroundColor Green
    }
    else {
        Write-Warning " Could not locate or generate SSH public key. Searched: $($candidates -join ', ')"
    }
}

function Add-WingetPackagePaths {
    <#
.SYNOPSIS
    Adds directories containing executables from winget package installs to the user PATH.

.DESCRIPTION
    Scans subdirectories in %LOCALAPPDATA%\Microsoft\WinGet\Packages that contain .exe files,
    and appends them to the user's PATH environment variable if they are not already present.

.EXAMPLE
    PS C:\> Add-WingetPackagePaths
     Added the following paths to your user PATH:
      C:\Users\User\AppData\Local\Microsoft\WinGet\Packages\ExampleTool\bin
     Updated user PATH:
      C:\Tools\Bin
      C:\Users\User\AppData\Local\Microsoft\WinGet\Packages\ExampleTool\bin
    Adds new executable directories and shows final PATH.

.INPUTS
    None

.OUTPUTS
    Writes status messages to the host; modifies the user PATH environment variable.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06

    Compatible with Windows PowerShell.
    See Remove-WingetPackagePaths
#>
    $wingetPath = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages"

    if (!(Test-Path $wingetPath)) {
        Write-Host "Winget package directory not found at $wingetPath"
        return
    }

    # Scan all subdirectories containing .exe files; winget does not use a
    # standard bin/ layout so we must discover executable dirs heuristically.
    $binPaths = Get-ChildItem -Path $wingetPath -Directory -Recurse |
    Where-Object { (Get-ChildItem -Path $_.FullName -Filter *.exe -File -ErrorAction SilentlyContinue).Count -gt 0 } |
    Select-Object -ExpandProperty FullName

    # Read the persisted user PATH from the registry, not $env:PATH, so that
    # the update sticks across sessions and doesn't duplicate machine-level entries.
    $currentPath = (Get-ItemPropertyValue -Path 'HKCU:\Environment' -Name 'PATH')
    $currentPathArr = $currentPath -split ';'

    $added = @()
    foreach ($path in $binPaths) {
        if ($currentPathArr -notcontains $path) {
            $currentPath += ";$path"
            $added += $path
        }
    }

    if ($added.Count -eq 0) {
        Write-Host "No new paths were added. All executable directories are already in PATH."
    }
    else {
        # Write back via .NET registry API instead of Set-ItemProperty to
        # guarantee REG_EXPAND_SZ, avoiding environment-variable literal expansion.
        [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true).SetValue('PATH', $currentPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
        # Also update the process PATH so the current session picks up new dirs
        # immediately without needing a shell restart.
        $env:PATH = $env:PATH.TrimEnd(';') + ';' + ($added -join ';')
        Write-Host " Added the following paths to your user PATH:"
        $added | ForEach-Object { Write-Host "  - $_" }
    }

    Write-Host "`n Updated user PATH:"
    $currentPath.Split(';') | ForEach-Object { Write-Host "  $_" }
}

function Remove-WingetPackagePaths {
    <#
.SYNOPSIS
    Removes all user PATH entries under the winget package directory.

.DESCRIPTION
    Scans the current user PATH for any entries that start with
    $env:LOCALAPPDATA\Microsoft\WinGet\Packages and removes them.

.EXAMPLE
    PS C:\> Remove-WingetPackagePaths
    [OK] Removed the following winget directories from your user PATH:
      - C:\Users\User\AppData\Local\Microsoft\WinGet\Packages\SomeTool\bin

.INPUTS
    None

.OUTPUTS
    Writes status messages to the host; modifies the user PATH environment variable.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06

    Compatible with Windows PowerShell.
    See Add-WingetPackagePaths
#>
    $wingetRoot = [IO.Path]::Combine($env:LOCALAPPDATA, "Microsoft\WinGet\Packages")
    $currentPath = (Get-ItemPropertyValue -Path 'HKCU:\Environment' -Name 'PATH')
    $currentPathArr = $currentPath -split ';' | Where-Object { $_ -ne '' }

    $filtered = @()
    $removed = @()

    # Use -like prefix match rather than exact comparison so that any
    # subdirectory under the winget packages root is caught, even if the
    # specific package structure changes between winget versions.
    foreach ($p in $currentPathArr) {
        if ($p -like "$wingetRoot*") {
            $removed += $p
        }
        else {
            $filtered += $p
        }
    }

    if ($removed.Count -eq 0) {
        Write-Host "No winget paths found in user PATH. Nothing to remove."
    }
    else {
        $newRegPath = $filtered -join ';'
        # Persist the cleaned PATH to the registry (REG_EXPAND_SZ) for future sessions.
        [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true).SetValue('PATH', $newRegPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)

        # Strip the same entries from the live process PATH so the current
        # session stops resolving executables from removed winget directories.
        $processPathArr = $env:PATH -split ';' | Where-Object { $_ -ne '' }
        $newProcessPath = ($processPathArr | Where-Object { $_ -notlike "$wingetRoot*" }) -join ';'
        $env:PATH = $newProcessPath

        Write-Host " Removed the following winget directories from your user PATH:"
        $removed | ForEach-Object { Write-Host "  - $_" }
    }

    Write-Host "`n Updated user PATH:"
    $filtered | ForEach-Object { Write-Host "  $_" }
}

function New-RandomMacAddress {
    <#
.SYNOPSIS
    Generates a random MAC address, with optional locally administered format.

.DESCRIPTION
    Creates a MAC address for virtual machines, containers, or testing scenarios.
    By default, the MAC address is locally administered (bit 1 of first octet set) and unicast (bit 0 cleared).
    Use the -FullyRandom switch to generate a completely random MAC that may not conform to local/unicast standards.

.PARAMETER FullyRandom
    If specified, generates a fully random MAC address without enforcing local or unicast bits.

.EXAMPLE
    PS C:\> New-RandomMacAddress
    06:3c:74:1a:cc:2e

.EXAMPLE
    PS C:\> New-RandomMacAddress -FullyRandom
    9f:83:ad:75:b2:01

.INPUTS
    None

.OUTPUTS
    System.String. Returns a MAC address as a string (e.g. '02:ab:cd:ef:12:34').

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06

    Compatible with Windows PowerShell and PowerShell Core.
#>
    [CmdletBinding()]
    param (
        [switch]$FullyRandom
    )

    if ($FullyRandom) {
        # All octets are fully random
        $octets = @(for ($i = 0; $i -lt 6; $i++) { (Get-Random -Minimum 0 -Maximum 256).ToString("x2") })
    }
    else {
        # First octet: locally administered (bit 1 set), unicast (bit 0 cleared)
        # Per IEEE 802, bit 0 = multicast, bit 1 = locally administered.
        # Setting bit 1 and clearing bit 0 produces addresses safe for VMs
        # and containers that won't collide with OUI-assigned hardware MACs.
        $first = ((Get-Random -Minimum 0 -Maximum 256) -bor 0x02) -band 0xFE
        $octets = @($first.ToString("x2"))
        for ($i = 1; $i -lt 6; $i++) {
            $octets += (Get-Random -Minimum 0 -Maximum 256).ToString("x2")
        }
    }

    return ($octets -join ":")
}

function Get-MacAdapters {
    <#
.SYNOPSIS
    Lists all network adapters and their MAC addresses.

.DESCRIPTION
    Queries all network adapters and displays their name, description, MAC address, and status.
    Useful for identifying the correct adapter to modify.

.EXAMPLE
    PS C:\> Get-MacAdapters

.OUTPUTS
    Table of adapter details.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
#>
    Get-NetAdapter | Format-Table Name, InterfaceDescription, MacAddress, Status
}

function Set-RandomMacAddress {
    <#
.SYNOPSIS
    Sets a network adapter's MAC address to a random value.

.DESCRIPTION
    Generates a random MAC address and applies it to the specified adapter.
    By default, the MAC is locally administered and unicast.
    Use the -FullyRandom switch to generate a completely random MAC address.

.PARAMETER AdapterName
    The name of the network adapter to modify. Use Get-MacAdapters to list available adapters.

.PARAMETER FullyRandom
    If specified, generates a fully random MAC address
    (may not be locally administered or unicast).

.EXAMPLE
    PS C:\> Set-RandomMacAddress -AdapterName "Wi-Fi"
    Sets "Wi-Fi" adapter to a locally administered, unicast random MAC.

.EXAMPLE
    PS C:\> Set-RandomMacAddress -AdapterName "Ethernet" -FullyRandom
    Sets "Ethernet" adapter to a fully random MAC.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AdapterName,
        [switch]$FullyRandom
    )

    # Generate MAC address
    if ($FullyRandom) {
        $octets = @(for ($i = 0; $i -lt 6; $i++) { (Get-Random -Minimum 0 -Maximum 256).ToString("x2") })
    }
    else {
        $first = ((Get-Random -Minimum 0 -Maximum 256) -bor 0x02) -band 0xFE
        $octets = @($first.ToString("x2"))
        for ($i = 1; $i -lt 6; $i++) {
            $octets += (Get-Random -Minimum 0 -Maximum 256).ToString("x2")
        }
    }
    # Set-NetAdapter expects a bare hex string (no colons), unlike the
    # colon-separated format New-RandomMacAddress returns for display.
    $newMac = $octets -join ""
    Write-Host "Attempting to set MAC address for adapter '$AdapterName' to $newMac..."

    try {
        Set-NetAdapter -Name $AdapterName -MacAddress $newMac -Confirm:$false
        Write-Host " Successfully changed MAC address."
        Write-Host "Restarting adapter '$AdapterName'..."
        Restart-NetAdapter -Name $AdapterName -Confirm:$false
        Write-Host "Adapter restarted."
        Get-NetAdapter -Name $AdapterName | Select-Object Name, MacAddress
    }
    catch {
        Write-Error "Failed to set MAC address: $_"
        Write-Error "Ensure you are running PowerShell as Administrator and the adapter name is correct."
    }
}

function Reset-MacAddress {
    <#
.SYNOPSIS
    Resets a network adapter's MAC address to its default (hardware) value.

.DESCRIPTION
    Clears the custom MAC address and restores the adapter's original hardware MAC.

.PARAMETER AdapterName
    The name of the network adapter to modify.

.EXAMPLE
    PS C:\> Reset-MacAddress -AdapterName "Wi-Fi"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AdapterName
    )

    Write-Host "Resetting MAC address for adapter '$AdapterName' to its default..."
    try {
        Set-NetAdapter -Name $AdapterName -MacAddress $null -Confirm:$false
        Restart-NetAdapter -Name $AdapterName -Confirm:$false
        Write-Host " MAC address reset to default."
        Get-NetAdapter -Name $AdapterName | Select-Object Name, MacAddress
    }
    catch {
        Write-Error "Failed to reset MAC address: $_"
        Write-Error "Ensure you are running PowerShell as Administrator and the adapter name is correct."
    }
}

function Convert-JpgToJxl {
    <#
.SYNOPSIS
    Converts all jpg images in a directory (recursively) to .jxl using ImageMagick, in parallel. DELETES ORIGINALS ON SUCCESS.
.DESCRIPTION
    Finds all .jpg and .jpeg files recursively from a target directory (default: current), starts a background job for each conversion,
    and deletes the original file only on successful conversion. Reports progress and elapsed time.
    Uses Windows PowerShell Start-Job for parallelism (suitable for PowerShell 5.1+).
.PARAMETER Path
    The directory to search for .jpg/.jpeg images. Default is current directory.
.PARAMETER ThrottleLimit
    Maximum number of parallel jobs allowed. Default is 4.
.EXAMPLE
    PS C:\> Convert-JpgToJxl
.EXAMPLE
    PS C:\> Convert-JpgToJxl -Path "D:\Photos" -ThrottleLimit 8
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
    - Compatible with Windows PowerShell and PowerShell Core.
    - Requires ImageMagick (magick.exe) in PATH.
    - Deletes .jpg/.jpeg only on successful conversion.
#>
    [CmdletBinding()]
    param(
        [string]$Path = ".",
        [int]$ThrottleLimit = 4
    )

    # Collect both extensions explicitly; WinPS 5.1's -Filter does not
    # accept comma-separated values or -Include reliably with -Recurse.
    $images = @(Get-ChildItem -Path $Path -Filter *.jpg -Recurse -File) + @(Get-ChildItem -Path $Path -Filter *.jpeg -Recurse -File)
    $total = $images.Count
    if ($total -eq 0) {
        Write-Host "No .jpg or .jpeg files found in $Path"
        return
    }
    $startTime = Get-Date
    $jobs = @()
    $i = 0

    foreach ($image in $images) {
        # Throttle by polling running-job count; WinPS 5.1 lacks the
        # -ThrottleLimit parameter available in pwsh's Start-Job.
        while (@(Get-Job -State "Running").Count -ge $ThrottleLimit) {
            Start-Sleep -Milliseconds 200
        }
        $jobs += Start-Job -ArgumentList $image.FullName -ScriptBlock {
            param($imgPath)
            $jxlPath = $imgPath -replace '\.(jpg|jpeg)$', '.jxl'
            try {
                & magick.exe $imgPath $jxlPath
                if (Test-Path $jxlPath) {
                    Remove-Item $imgPath -Verbose
                    [PSCustomObject]@{Status = "Success"; Path = $imgPath }
                }
                else {
                    [PSCustomObject]@{Status = "Fail"; Path = $imgPath }
                }
            }
            catch {
                [PSCustomObject]@{Status = "Error"; Path = $imgPath; Message = $_ }
            }
        }
    }

    # Drain jobs as they complete rather than Wait-Job on the full array,
    # so progress updates stream in real time instead of appearing all at once.
    $completed = 0
    while ($jobs.Count -gt 0) {
        $finishedJobs = Wait-Job -Job $jobs -Any
        $results = Receive-Job -Job $finishedJobs -AutoRemoveJob
        $jobs = @($jobs | Where-Object { $finishedJobs.Id -notcontains $_.Id })
        foreach ($result in $results) {
            $completed++
            $pct = [math]::Round($completed * 100 / $total, 2)
            $elapsed = (Get-Date) - $startTime
            if ($result.Status -eq "Success") {
                Write-Host ("[{0}] Converted [{1}] ({2}/{3}, {4}%) ({5} sec elapsed)" -f (Get-Date), $result.Path, $completed, $total, $pct, [math]::Round($elapsed.TotalSeconds, 2))
            }
            elseif ($result.Status -eq "Fail") {
                Write-Warning "Conversion failed for $($result.Path)"
            }
            elseif ($result.Status -eq "Error") {
                Write-Warning "Error converting $($result.Path): $($result.Message)"
            }
        }
        Start-Sleep -Milliseconds 200
    }

    $endTime = Get-Date
    $elapsedTime = $endTime - $startTime
    Write-Host "The script took $($elapsedTime.TotalSeconds) seconds to convert $total images."
}

# Sequential variant kept for systems where background jobs are unavailable
# or undesirable (e.g., constrained runspaces, CI pipelines, single-core VMs).
function Convert-JpgToJxl-Sequential {
    <#
.SYNOPSIS
    Converts all jpg images in a directory (recursively) to .jxl using ImageMagick. DELETES ORIGINALS ON SUCCESS.
.DESCRIPTION
    Finds all .jpg and .jpeg files recursively from a target directory (default: current), converts each to .jxl using magick.exe,
    and deletes the original file only on successful conversion.
    Reports progress and elapsed time. Designed for Windows PowerShell compatibility (v5.1+).
.PARAMETER Path
    The directory to search for .jpg/.jpeg images. Default is current directory.
.EXAMPLE
    PS C:\> Convert-JpgToJxl-Sequential
.EXAMPLE
    PS C:\> Convert-JpgToJxl-Sequential -Path "D:\Photos"
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
    - Compatible with Windows PowerShell and PowerShell Core.
    - Requires ImageMagick (magick.exe) in PATH.
    - Deletes .jpg/.jpeg only on successful conversion.
#>
    [CmdletBinding()]
    param(
        [string]$Path = "."
    )
    $images = @(Get-ChildItem -Path $Path -Filter *.jpg -Recurse -File) + @(Get-ChildItem -Path $Path -Filter *.jpeg -Recurse -File)
    $total = $images.Count
    if ($total -eq 0) {
        Write-Host "No .jpg or .jpeg files found in $Path"
        return
    }
    $startTime = Get-Date
    $i = 0
    foreach ($image in $images) {
        $jxlPath = $image.FullName -replace '\.(jpg|jpeg)$', '.jxl'
        try {
            & magick.exe $image.FullName $jxlPath
            if (Test-Path $jxlPath) {
                Remove-Item $image.FullName -Verbose
            }
            else {
                Write-Warning "Conversion failed for $($image.FullName)"
            }
        }
        catch {
            Write-Warning "Error converting $($image.FullName): $_"
        }
        $i++
        $pct = [math]::Round($i * 100 / $total, 2)
        $elapsed = (Get-Date) - $startTime
        Write-Host ("[{0}] Converted {1} of {2} images ({3}%) ({4} sec elapsed)" -f (Get-Date), $i, $total, $pct, [math]::Round($elapsed.TotalSeconds, 2))
    }
    $endTime = Get-Date
    $elapsedTime = $endTime - $startTime
    Write-Host "The script took $($elapsedTime.TotalSeconds) seconds to convert $total images."
}

# Reverse conversion utility -- kept separate from the jpg-to-jxl functions
# because the output extension logic and error semantics differ enough that
# merging them would add branching complexity for little benefit.
function Convert-JxlToJpg {
    <#
.SYNOPSIS
    Converts all .jxl images in a directory (recursively) to .jpg using ImageMagick. DELETES ORIGINALS ON SUCCESS.
.DESCRIPTION
    Finds all .jxl files recursively from a target directory (default: current), converts each to .jpg using magick.exe,
    and deletes the original .jxl only on successful conversion. Reports progress and elapsed time.
    Designed for Windows PowerShell compatibility (v5.1+).
.PARAMETER Path
    The directory to search for .jxl images. Default is current directory.
.EXAMPLE
    PS C:\> Convert-JxlToJpg
.EXAMPLE
    PS C:\> Convert-JxlToJpg -Path "D:\Photos"
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
    - Compatible with Windows PowerShell and PowerShell Core.
    - Requires ImageMagick (magick.exe) in PATH.
    - Deletes .jxl only on successful conversion.
#>
    [CmdletBinding()]
    param(
        [string]$Path = "."
    )
    $images = Get-ChildItem -Path $Path -Filter *.jxl -Recurse -File
    $total = $images.Count
    if ($total -eq 0) {
        Write-Host "No .jxl files found in $Path"
        return
    }
    $startTime = Get-Date
    $i = 0
    foreach ($image in $images) {
        $jpgPath = $image.FullName -replace '\.jxl$', '.jpg'
        try {
            & magick.exe $image.FullName $jpgPath
            if (Test-Path $jpgPath) {
                Remove-Item $image.FullName -Verbose
            }
            else {
                Write-Warning "Conversion failed for $($image.FullName)"
            }
        }
        catch {
            Write-Warning "Error converting $($image.FullName): $_"
        }
        $i++
        $pct = [math]::Round($i * 100 / $total, 2)
        $elapsed = (Get-Date) - $startTime
        Write-Host ("[{0}] Converted {1} of {2} images ({3}%) ({4} sec elapsed)" -f (Get-Date), $i, $total, $pct, [math]::Round($elapsed.TotalSeconds, 2))
    }
    $endTime = Get-Date
    $elapsedTime = $endTime - $startTime
    Write-Host "The script took $($elapsedTime.TotalSeconds) seconds to convert $total images."
}

function Get-IpInfo {
    <#
.SYNOPSIS
    Prints the command to query ipregistry.co for a given IP address using curl-like User-Agent.
.DESCRIPTION
    Outputs the exact Invoke-RestMethod command for the user to copy and run manually.
.EXAMPLE
    PS C:\> Get-IpInfo 1.1.1.1
    Prints the command to query ipregistry.co for 1.1.1.1
.INPUTS
    IP address as string.
.OUTPUTS
    String: PowerShell command to run manually.
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
#>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Ip
    )
    $cmd = "Invoke-RestMethod -Uri 'https://api.ipregistry.co/${Ip}?key=tryout' -Headers @{ 'User-Agent' = 'curl/7.68.0' }"
    Write-Host "Run this command manually in your shell:" -ForegroundColor Yellow
    Write-Host $cmd -ForegroundColor Cyan
}

function Test-IsAdministrator {
    <#
.SYNOPSIS
Tests if the current PowerShell session is running with administrator privileges.

.DESCRIPTION
Returns $true if running as administrator, $false otherwise.

.EXAMPLE
if (Test-IsAdministrator) { Write-Host "Running as admin" }

.NOTES
Author: jjw(@thejjw)
Last Edit: Aug 2025
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-SafeFileNameFromCertificateName {
    <#
.SYNOPSIS
Creates a filesystem-safe filename from a certificate subject or other string.

.DESCRIPTION
Removes or replaces characters that are invalid in filenames, extracts CN from subject strings,
and ensures the result is not empty.

.PARAMETER InputString
The string to convert to a safe filename.

.PARAMETER DefaultName
Default name to use if the input results in an empty string.

.EXAMPLE
New-SafeFileNameFromCertificateName -InputString "CN=*.example.com, O=Example Corp" -DefaultName "cert"
# Returns: example.com

.NOTES
Author: jjw(@thejjw)
Last Edit: Aug 2025
#>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $InputString,
        
        [string] $DefaultName = "cert"
    )
    
    # Extract CN if it's a certificate subject
    $cleaned = $InputString -replace 'CN=', '' -replace ',.*', ''
    
    # Replace invalid filesystem characters
    $safeName = ($cleaned -replace '[^\w\.-]+', '_').Trim('_')
    
    # Return default if empty
    if ([string]::IsNullOrWhiteSpace($safeName)) {
        return $DefaultName
    }
    
    return $safeName
}

function Get-CertutilPath {
    <#
.SYNOPSIS
Locates the certutil.exe executable on the system.

.DESCRIPTION
Searches common paths for certutil.exe and returns the full path if found.

.EXAMPLE
$certutilPath = Get-CertutilPath

.NOTES
Author: jjw(@thejjw)
Last Edit: Aug 2025
#>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    $commonPaths = @(
        "${env:SystemRoot}\System32\certutil.exe",
        "${env:SystemRoot}\SysWOW64\certutil.exe",
        "${env:windir}\Sysnative\certutil.exe"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            return $path
        }
    }
    
    # Try to find it in PATH
    $pathResult = Get-Command certutil.exe -ErrorAction SilentlyContinue
    if ($pathResult) {
        return $pathResult.Source
    }
    
    throw "certutil.exe not found on this system"
}

function Install-ServerCertificateTrust {
    <#
.SYNOPSIS
Connects to an HTTPS server, retrieves its certificate chain, and installs selected certificates into Windows trust stores.

.DESCRIPTION
Useful for trusting dev servers, internal hosts, or self-signed certs so that browsers and clients stop complaining. 
By default, installs into CurrentUser; use -MachineStore for system-wide trust with elevation. 
You can choose to install Root, Intermediate, Leaf, or all certificates.

Supports two installation methods:
- X509Store: Direct .NET API installation (default)
- Certutil: Uses certutil.exe for installation

.PARAMETER Url
The full HTTPS URL of the server (e.g. https://localhost:8443).

.PARAMETER WhatToInstall
Selects certificate level: 'Root', 'Intermediate', 'Leaf', or 'All'.

.PARAMETER InstallMethod
Method to use for certificate installation: 'X509Store' (default) or 'Certutil'.

.PARAMETER MachineStore
If set, installs to LocalMachine stores (requires admin).

.PARAMETER SaveToFiles
If set, exports selected certificates to disk for inspection.

.PARAMETER OutDir
Folder where exported certificates go. Defaults to '.\certs'.

.PARAMETER SNIHost
Optional override for the hostname sent during TLS handshake.

.PARAMETER SkipCertValidation
Skip certificate validation during TLS connection (allows self-signed/invalid certs).

.PARAMETER WhatIfOnly
Fetch and export certificates, but skip installation steps.

.PARAMETER InstallEndEntity
Also installs the server certificate (end-entity) into the Personal (My) store. 
Only applies when using Certutil method.

.PARAMETER Force
Overwrites existing certificate files in OutDir if SaveToFiles is used.

.EXAMPLE
Install-ServerCertificateTrust -Url https://dev.local -WhatToInstall All -MachineStore

.EXAMPLE
Install-ServerCertificateTrust -Url https://api.example.com -InstallMethod Certutil -WhatIfOnly

.NOTES
Author: jjw(@thejjw)
Last Edit: Aug 2025
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Url,

        [ValidateSet('Root', 'Intermediate', 'Leaf', 'All')]
        [string] $WhatToInstall = 'Root',

        [ValidateSet('X509Store', 'Certutil')]
        [string] $InstallMethod = 'X509Store',

        [switch] $MachineStore,
        [switch] $SaveToFiles,
        [string] $OutDir = (Join-Path $PWD 'certs'),
        [string] $SNIHost,
        [switch] $SkipCertValidation,
        [switch] $WhatIfOnly,
        [switch] $InstallEndEntity,
        [switch] $Force
    )

    # --- Internal helper functions ---
    # HashSet-based dedup by thumbprint; SslStream can return duplicate
    # chain elements depending on the server's chain configuration.
    function Get-UniqueByThumbprint {
        param([System.Collections.IEnumerable] $Certificates)
        $certList = @($Certificates)
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($cert in $certList) {
            if ($null -ne $cert -and $seen.Add($cert.Thumbprint)) { $cert }
        }
    }

    function Test-SelfSignedCertificate {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
        return ($Certificate.Subject -eq $Certificate.Issuer)
    }

    function Get-CertificateType {
        param(
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
            [bool] $IsFirstInChain = $false,
            [bool] $IsLastInChain = $false
        )
        
        $isSelfSigned = Test-SelfSignedCertificate -Certificate $Certificate
        
        # Check basic constraints extension for CA status
        $isCA = $false
        foreach ($ext in $Certificate.Extensions) {
            if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
                $isCA = $ext.CertificateAuthority
                break
            }
        }
        
        # Position-based classification takes precedence
        if ($IsFirstInChain -and -not $isSelfSigned) { return "Leaf" }
        elseif ($IsLastInChain -or $isSelfSigned) { return "Root" }
        elseif ($isCA) { return "Intermediate" }
        else { return "Leaf" }
    }

    # Maps a certificate to the correct Windows store name (Root/CA/My)
    # for X509Store-based installation. Falls through to 'My' (Personal) for
    # end-entity certs that lack BasicConstraints.
    function Get-CertificateStoreName {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

        if (Test-SelfSignedCertificate -Certificate $Certificate) { return 'Root' }

        $bc = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
        if ($bc -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            if ($bc.CertificateAuthority) { return 'CA' }
        }

        return 'My'
    }

    # Separate classification for certutil install planning -- uses
    # 'CA'/'EndEntity' labels instead of 'Intermediate'/'Leaf' to align
    # with certutil's own store naming (Root, CA, My).
    function Classify-Certificate {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

        $isSelfSigned = Test-SelfSignedCertificate -Certificate $Certificate
        $isCA = $false
        
        foreach ($ext in $Certificate.Extensions) {
            if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
                $isCA = $ext.CertificateAuthority
            }
        }

        if ($isCA -and $isSelfSigned) { return 'Root' }
        if ($isCA -and -not $isSelfSigned) { return 'CA' }
        return 'EndEntity'
    }

    function Save-CertificateAsFile {
        param(
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
            [string] $Directory,
            [switch] $Overwrite
        )
        
        # Improved CN extraction with better handling of escaped characters
        $subjectParts = $Certificate.Subject -split '(?<!\\),' | ForEach-Object { $_.Trim() }
        $cnPart = $subjectParts | Where-Object { $_ -like 'CN=*' } | Select-Object -First 1
        $cn = if ($cnPart) { $cnPart -replace '^CN=', '' -replace '\\(.)', '$1' } else { $null }
        
        if ([string]::IsNullOrWhiteSpace($cn)) { 
            $cn = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) 
        }
        if ([string]::IsNullOrWhiteSpace($cn)) { $cn = 'Unknown' }

        # Double-underscore separates human-readable name from thumbprint so
        # filenames stay unique across renewals without collisions.
        $safeName = New-SafeFileNameFromCertificateName -InputString $cn -DefaultName "cert"
        $thumb = $Certificate.Thumbprint -replace '\s', ''
        $fileBase = "{0}__{1}" -f $safeName, $thumb
        $path = Join-Path $Directory ($fileBase + '.cer')

        if ((-not $Overwrite) -and (Test-Path -LiteralPath $path)) {
            return $path
        }

        $bytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        [IO.File]::WriteAllBytes($path, $bytes)
        return $path
    }

    function Escape-CertutilArgument {
        param([string] $Argument)
        if ($Argument -match '\s') { return "`"$Argument`"" }
        return $Argument
    }

    # Launches certutil.exe via System.Diagnostics.Process instead of
    # direct invocation so we can capture stdout/stderr and check the exit
    # code -- certutil returns non-zero on failure but still writes to stderr
    # on partial success, so we need both streams.
    function Invoke-CertutilAddStore {
        param(
            [string] $StoreName,
            [string] $CertificatePath,
            [switch] $MachineStore
        )
        
        $certutil = Get-CertutilPath
        $args = @()
        if (-not $MachineStore) { $args += '-user' }
        $args += '-addstore'
        $args += $StoreName
        $args += $CertificatePath

        # Properly escape arguments that contain spaces
        $escapedArgs = $args | ForEach-Object { Escape-CertutilArgument $_ }
        $argumentString = $escapedArgs -join ' '

        Write-Verbose ("certutil {0}" -f $argumentString)
        
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $certutil
        $psi.Arguments = $argumentString
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        
        try {
            [void]$p.Start()
            $stdout = $p.StandardOutput.ReadToEnd()
            $stderr = $p.StandardError.ReadToEnd()
            $p.WaitForExit()

            if ($p.ExitCode -ne 0) {
                throw "certutil failed (exit $($p.ExitCode)) for $CertificatePath to $StoreName. Error: $stderr`nOutput: $stdout"
            }
            else {
                Write-Verbose $stdout.Trim()
            }
        }
        finally {
            if ($p) { $p.Dispose() }
        }
    }

    # --- Permission validation ---
    if ($MachineStore -and -not (Test-IsAdministrator)) {
        throw "Must run PowerShell as Administrator to use -MachineStore."
    }

    $storeLocation = if ($MachineStore) { 'LocalMachine' } else { 'CurrentUser' }

    # --- Parse URL ---
    if ($Url -notmatch '^\w+://') { $Url = "https://${Url}" }
    $uri = [Uri]$Url
    $targetHost = $uri.Host
    $targetPort = if ($uri.IsDefaultPort) { 443 } else { $uri.Port }
    if (-not $SNIHost) { $SNIHost = $targetHost }

    Write-Verbose "Connecting to ${targetHost}:${targetPort} with SNI '${SNIHost}'"

    # --- TLS connection and cert retrieval ---
    $tcp = $null; $ssl = $null; $leaf = $null
    try {
        Write-Verbose "Establishing TCP connection to ${targetHost}:${targetPort}..."
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.ReceiveTimeout = 10000
        $tcp.SendTimeout = 10000
        $tcp.Connect($targetHost, $targetPort)
        
        # Certificate validation callback configuration
        # GetNewClosure() captures $serverChainElements by reference so both
        # branches of the callback can populate it during the TLS handshake.
        # We always return $true to let the handshake complete even with
        # invalid certs -- the user explicitly opted in via -SkipCertValidation
        # or wants to inspect chain issues via -WhatIfOnly.
        $serverChainElements = [System.Collections.ArrayList]::new()
        $certCallback = if ($SkipCertValidation) {
            { param($s, $c, $chain, $errors)
                if ($chain) { foreach ($e in $chain.ChainElements) { [void]$serverChainElements.Add($e.Certificate) } }
                return $true 
            }.GetNewClosure()
        }
        else {
            { param($s, $c, $chain, $errors) 
                if ($chain) { foreach ($e in $chain.ChainElements) { [void]$serverChainElements.Add($e.Certificate) } }
                if ($errors -ne [System.Net.Security.SslPolicyErrors]::None) {
                    Write-Warning "TLS certificate validation errors: $errors"
                }
                return $true  # Still proceed but warn about issues
            }.GetNewClosure()
        }
        
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $certCallback)
        $ssl.AuthenticateAsClient($SNIHost)
        $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        Write-Verbose "Successfully retrieved server certificate: $($leaf.Subject)"
    }
    catch {
        throw "Failed to retrieve certificate from ${targetHost}:${targetPort}. $_"
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }

    # --- Chain building ---
    # Prefer certs collected by the validation callback (they reflect what the
    # server actually sent). Fall back to X509Chain.Build() when the callback
    # didn't capture anything -- e.g. on older .NET Framework where the chain
    # parameter may be null in the callback.
    if ($serverChainElements.Count -gt 0) {
        $chainCertsRaw = $serverChainElements.ToArray()
    } else {
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = 'NoCheck'

        if ($InstallMethod -eq 'Certutil') {
            # More extensive verification flags for certutil method
            $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EndCertificateOnly
            $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(20)
            $chain.ChainPolicy.VerificationFlags = `
                [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreCertificateAuthorityRevocationUnknown `
                -bor [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreCtlSignerRevocationUnknown `
                -bor [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreEndRevocationUnknown `
                -bor [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreRootRevocationUnknown
        }
        else {
            $chain.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
        }
        
        $buildResult = $chain.Build($leaf)
        if (-not $buildResult -and $InstallMethod -eq 'Certutil') {
            Write-Warning "Certificate chain building incomplete. Some intermediate certificates may be missing. Chain status: $($chain.ChainStatus | ForEach-Object { $_.Status })"
        }
        $chainCertsRaw = @($chain.ChainElements | ForEach-Object { $_.Certificate })
    }
    $elements = @(Get-UniqueByThumbprint -Certificates $chainCertsRaw)

    if (-not $elements -or $elements.Count -eq 0) {
        $elements = @($leaf)
        Write-Warning "Server did not provide a certificate chain. Using only leaf certificate."
    }

    # Chain is ordered leaf-first from the TLS handshake, so root is the
    # last element. Intermediates are everything between leaf and root.
    # --- Certificate selection helpers ---
    function Get-RootCert { param($e) if ($e.Count -gt 0) { $e[-1] } }
    function Get-Intermediates { param($e) if ($e.Count -gt 2) { $e[1..($e.Count - 2)] } else { @() } }

    # --- Select certificates to work with ---
    $toInstall = switch ($WhatToInstall) {
        'Root' { @(Get-RootCert $elements) | Where-Object { $_ } }
        'Intermediate' { @(Get-Intermediates $elements) | Where-Object { $_ } }
        'Leaf' { @($leaf) | Where-Object { $_ } }
        'All' { $elements | Where-Object { $_ } }
    }

    if (-not $toInstall -or $toInstall.Count -eq 0) {
        throw "No certificates selected for '${WhatToInstall}'."
    }

    # --- Optional export to files ---
    if ($SaveToFiles) {
        if (-not (Test-Path $OutDir)) { 
            $null = New-Item -ItemType Directory -Path $OutDir -Force
            Write-Verbose "Created output directory: ${OutDir}"
        }
        
        foreach ($cert in $toInstall) {
            if ($InstallMethod -eq 'Certutil') {
                # Certutil method uses Save-CertificateAsFile
                $path = Save-CertificateAsFile -Certificate $cert -Directory $OutDir -Overwrite:$Force
                Write-Verbose "Exported: ${path}"
            }
            else {
                # X509Store method uses simpler export
                $safeName = New-SafeFileNameFromCertificateName -InputString $cert.Subject
                $filePath = Join-Path $OutDir ("${safeName}-${cert.Thumbprint}.cer")
                [IO.File]::WriteAllBytes($filePath, $cert.Export('Cert'))
                Write-Verbose "Exported: ${filePath}"
            }
        }
        
        Write-Host "Exported $($toInstall.Count) certificate(s) to: ${OutDir}"
    }

    # --- Installation planning (for Certutil method) ---
    if ($InstallMethod -eq 'Certutil') {
        $plan = @()
        foreach ($cert in $toInstall) {
            $type = Classify-Certificate -Certificate $cert
            $path = if ($SaveToFiles) {
                # Already saved, just get the path
                $safeName = New-SafeFileNameFromCertificateName -InputString $cert.Subject
                Join-Path $OutDir ("${safeName}-${cert.Thumbprint}.cer")
            }
            else {
                # Need to save to temp for certutil
                $tempDir = if (-not (Test-Path $OutDir)) {
                    $null = New-Item -ItemType Directory -Path $OutDir -Force
                    $OutDir
                }
                else { $OutDir }
                Save-CertificateAsFile -Certificate $cert -Directory $tempDir -Overwrite:$Force
            }

            $store = switch ($type) {
                'Root' { 'Root' }
                'CA' { 'CA' }
                'EndEntity' {
                    if ($InstallEndEntity) { 'My' } else { $null }
                }
                default { $null }
            }

            $plan += [pscustomobject]@{
                Subject     = $cert.Subject
                Thumbprint  = $cert.Thumbprint -replace '\s', ''
                Type        = $type
                Path        = $path
                Store       = $store
                Certificate = $cert
            }
        }

        # Display plan
        Write-Host "`nCertificate installation plan:"
        foreach ($item in $plan) {
            $storeLabel = if ($item.Store) { $item.Store } else { '(skip install)' }
            Write-Host (" - {0} [{1}] -> {2}" -f $item.Subject, $item.Type, $storeLabel)
        }

        if ($WhatIfOnly) {
            Write-Host "`nWhatIfOnly specified: no installation attempted."
            Write-Host "`n--- Certificate Chain Summary ---"
            Write-Host "Target server: ${targetHost}:${targetPort}"
            Write-Host "Leaf:   ${leaf.Subject} [${leaf.Thumbprint}]"
            Write-Host "Chain:"
            for ($i = 0; $i -lt $elements.Count; $i++) {
                $tag = if ($i -eq 0) { '[Leaf]' } elseif ($i -eq $elements.Count - 1) { '[Root]' } else { '[Interm]' }
                Write-Host ("  ${tag} ${elements[$i].Subject} [${elements[$i].Thumbprint}]")
            }
            return $plan
        }

        # Install using certutil
        foreach ($item in $plan | Where-Object { $_.Store }) {
            try {
                Invoke-CertutilAddStore -StoreName $item.Store -CertificatePath $item.Path -MachineStore:$MachineStore
                Write-Host ("Installed via certutil: {0} -> {1}" -f (Split-Path -Leaf $item.Path), $item.Store)
            }
            catch {
                Write-Warning "Failed to install $($item.Path) into store $($item.Store): $($_.Exception.Message)"
            }
        }
    }
    else {
        # Install using X509Store method
        if ($WhatIfOnly) {
            Write-Host "`nWhatIfOnly specified: no installation attempted (X509Store method)."
        }
        else {
            foreach ($cert in $toInstall) {
                if ($WhatToInstall -eq 'Leaf' -and -not (Test-SelfSignedCertificate -Certificate $cert)) {
                    Write-Warning "Skipping non-self-signed leaf certificate. Install its issuer instead."
                    continue
                }

                $storeName = Get-CertificateStoreName -Certificate $cert
                
                # Skip end-entity certs unless explicitly requested -- installing
                # a server cert into the Personal store is rarely needed for
                # trust and can cause confusion with SChannel cert selection.
                if ($storeName -eq 'My' -and -not $InstallEndEntity -and $WhatToInstall -ne 'Leaf') {
                    Write-Verbose "Skipping end-entity certificate (use -InstallEndEntity to include)"
                    continue
                }

                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
                $store.Open('ReadWrite')
                try {
                    $existing = $store.Certificates.Find('FindByThumbprint', $cert.Thumbprint, $false)
                    if ($existing.Count -eq 0) {
                        $store.Add($cert)
                        Write-Host ("Installed via X509Store: ${cert.Subject} => ${storeLocation}\${storeName}")
                    }
                    else {
                        Write-Host ("Already present: ${cert.Subject} in ${storeLocation}\${storeName}")
                    }
                }
                finally {
                    $store.Close()
                }
            }
        }
    }

    # --- Summary ---
    Write-Host "`n--- Certificate Chain Summary ---"
    Write-Host "Target server: ${targetHost}:${targetPort}"
    Write-Host "Leaf:   ${leaf.Subject} [${leaf.Thumbprint}]"
    Write-Host "Chain:"
    for ($i = 0; $i -lt $elements.Count; $i++) {
        $tag = if ($i -eq 0) { '[Leaf]' } elseif ($i -eq $elements.Count - 1) { '[Root]' } else { '[Intermediate]' }
        Write-Host ("  ${tag} ${elements[$i].Subject} [${elements[$i].Thumbprint}]")
    }
}

function Export-TlsCertificates {
    <#
.SYNOPSIS
Retrieves and exports TLS certificates from a remote server without installing them.

.DESCRIPTION
Connects to a remote server via TLS, retrieves the certificate chain, and exports
selected certificates to files in PEM and/or DER format. Does not modify the 
Windows certificate store. Useful for certificate analysis, backup, or 
importing into other systems.

.PARAMETER TargetHost
The hostname or IP address of the target server to retrieve certificates from.

.PARAMETER TargetPort
The TCP port to connect to. Defaults to 443 (HTTPS).

.PARAMETER SNIHost
The Server Name Indication (SNI) hostname to use during TLS handshake.
Defaults to the same value as TargetHost. Useful for servers hosting 
multiple certificates.

.PARAMETER WhatToExport
Specifies which certificates from the chain to export:
- 'Root': Only the root CA certificate
- 'Intermediate': Only intermediate CA certificates  
- 'Leaf': Only the server certificate
- 'All': All certificates in the chain (default)

.PARAMETER OutDir
Directory path where exported certificate files will be saved.
Defaults to ".\certificates". Directory will be created if it doesn't exist.

.PARAMETER Format
Certificate export format:
- 'PEM': Base64 encoded with BEGIN/END markers
- 'DER': Binary format
- 'Both': Export in both formats (default)

.PARAMETER NoExport
Switch to only display certificate information without exporting files.
Useful for certificate analysis and troubleshooting.

.OUTPUTS
PSCustomObject with properties:
- LeafCertificate: The server certificate
- CertificateChain: Array of all certificates in chain
- ExportedCertificates: Array of certificates that were exported
- OutputDirectory: Path where files were saved (null if -NoExport)

.EXAMPLE
Export-TlsCertificates -TargetHost "google.com"

Exports all certificates from google.com:443 in both PEM and DER formats
to the .\certificates directory.

.EXAMPLE
Export-TlsCertificates -TargetHost "github.com" -WhatToExport "Intermediate" -Format "PEM"

Exports only intermediate CA certificates from github.com in PEM format.

.EXAMPLE
Export-TlsCertificates -TargetHost "example.com" -NoExport

Retrieves and displays certificate information from example.com without
saving any files.

.EXAMPLE
Export-TlsCertificates -TargetHost "internal.company.com" -TargetPort 8443 -SNIHost "api.company.com"

Connects to internal.company.com:8443 using SNI hostname api.company.com
and exports all certificates.

.EXAMPLE
$result = Export-TlsCertificates -TargetHost "microsoft.com" -OutDir "C:\temp\certs"
$result.LeafCertificate.Subject

Exports certificates to custom directory and examines the leaf certificate.

.NOTES
Requires .NET Framework with System.Net.Security.SslStream support.
Certificate validation is bypassed during retrieval to allow analysis of
invalid or self-signed certificates.

Author: jjw(@thejjw)
Last Edit: Aug 2025

.LINK
https://docs.microsoft.com/en-us/dotnet/api/system.net.security.sslstream
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetHost,
        
        [Parameter(Mandatory = $false)]
        [int]$TargetPort = 443,
        
        [Parameter(Mandatory = $false)]
        [string]$SNIHost = $TargetHost,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Root', 'Intermediate', 'Leaf', 'All')]
        [string]$WhatToExport = 'All',
        
        [Parameter(Mandatory = $false)]
        [string]$OutDir = ".\certificates",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('PEM', 'DER', 'Both')]
        [string]$Format = 'Both',
        
        [Parameter(Mandatory = $false)]
        [switch]$NoExport
    )
    
    # --- Internal helper functions ---
    function Get-UniqueByThumbprint {
        param([System.Collections.IEnumerable] $Certificates)
        $certList = @($Certificates)
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($cert in $certList) {
            if ($null -ne $cert -and $seen.Add($cert.Thumbprint)) { $cert }
        }
    }

    function Test-SelfSignedCertificate {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
        return ($Certificate.Subject -eq $Certificate.Issuer)
    }

    function Get-CertificateType {
        param(
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
            [bool] $IsFirstInChain = $false,
            [bool] $IsLastInChain = $false
        )
        
        $isSelfSigned = Test-SelfSignedCertificate -Certificate $Certificate
        
        # Check basic constraints extension for CA status
        $isCA = $false
        foreach ($ext in $Certificate.Extensions) {
            if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
                $isCA = $ext.CertificateAuthority
                break
            }
        }
        
        # Position-based classification takes precedence
        if ($IsFirstInChain -and -not $isSelfSigned) { return "Leaf" }
        elseif ($IsLastInChain -or $isSelfSigned) { return "Root" }
        elseif ($isCA) { return "Intermediate" }
        else { return "Leaf" }
    }
    
    Write-Host "Connecting to ${TargetHost}:${TargetPort} (SNI: ${SNIHost})"
    Write-Verbose "Target server: ${TargetHost}:${TargetPort}"
    
    # --- TLS connection and cert retrieval ---
    $tcp = $null; $ssl = $null; $leaf = $null
    try {
        Write-Verbose "Establishing TCP connection to ${TargetHost}:${TargetPort}..."
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.Connect($TargetHost, $TargetPort)
        $serverChainElements = [System.Collections.ArrayList]::new()
        $ssl = [System.Net.Security.SslStream]::new(
            $tcp.GetStream(), $false,
            { param($sender, $cert, $chain, $errors) 
                if ($chain) { foreach ($e in $chain.ChainElements) { [void]$serverChainElements.Add($e.Certificate) } }
                return $true 
            }.GetNewClosure()
        )
        $ssl.AuthenticateAsClient($SNIHost)
        $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        Write-Verbose "Successfully retrieved server certificate from ${TargetHost}:${TargetPort}"
    }
    catch {
        throw "Failed to retrieve certificate from ${TargetHost}:${TargetPort}. $_"
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }

    # --- Chain building ---
    if ($serverChainElements.Count -gt 0) {
        $chainCertsRaw = $serverChainElements.ToArray()
    } else {
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        $chain.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
        $null = $chain.Build($leaf)
        $chainCertsRaw = @($chain.ChainElements | ForEach-Object { $_.Certificate })
    }
    $elements = @(Get-UniqueByThumbprint -Certificates $chainCertsRaw)

    if (-not $elements -or $elements.Count -eq 0) {
        $elements = @($leaf)
        Write-Warning "Server did not provide a certificate chain. Using only leaf certificate."
    }

    # --- Helper functions for certificate selection ---
    function Get-RootCert { param($e) if ($e.Count -gt 0) { $e[-1] } }
    function Get-Intermediates { param($e) if ($e.Count -gt 2) { $e[1..($e.Count - 2)] } else { @() } }

    # --- Certificate selection and filtering ---
    $toExport = switch ($WhatToExport) {
        'Root' { @(Get-RootCert $elements) | Where-Object { $_ } }
        'Intermediate' { @(Get-Intermediates $elements) | Where-Object { $_ } }
        'Leaf' { @($leaf) | Where-Object { $_ } }
        'All' { $elements | Where-Object { $_ } }
    }

    if (-not $toExport -or $toExport.Count -eq 0) {
        throw "No certificates were obtained from ${TargetHost}:${TargetPort} for export type '${WhatToExport}'."
    }

    # --- File export operations ---
    if (-not $NoExport) {
        if (-not (Test-Path $OutDir)) { 
            $null = New-Item -ItemType Directory -Path $OutDir -Force
            Write-Host "Created output directory: ${OutDir}"
        }
        
        foreach ($cert in $toExport) {
            # Safe filename generation
            $safeName = New-SafeFileNameFromCertificateName -InputString $cert.Subject
            $certType = Get-CertificateType -Certificate $cert `
                -IsFirstInChain ($cert -eq $elements[0]) `
                -IsLastInChain ($cert -eq $elements[-1])
            $thumbprint = $cert.Thumbprint.Substring(0, 8)  # First 8 chars of thumbprint
            $baseFileName = "${safeName}_${certType}_${thumbprint}"
            
            # Format-specific export
            if ($Format -eq 'DER' -or $Format -eq 'Both') {
                $derPath = Join-Path $OutDir "${baseFileName}.cer"
                [IO.File]::WriteAllBytes($derPath, $cert.Export('Cert'))
                Write-Host "Exported DER: ${derPath}"
            }
            
            if ($Format -eq 'PEM' -or $Format -eq 'Both') {
                $pemPath = Join-Path $OutDir "${baseFileName}.pem"
                # Explicit CRLF line endings match what most tools (OpenSSL, certutil)
                # expect on Windows; .NET's InsertLineBreaks produces LF-only.
                $pemContent = @(
                    "-----BEGIN CERTIFICATE-----"
                    [Convert]::ToBase64String($cert.Export('Cert'), 'InsertLineBreaks')
                    "-----END CERTIFICATE-----"
                ) -join "`r`n"
                [IO.File]::WriteAllText($pemPath, $pemContent)
                Write-Host "Exported PEM: ${pemPath}"
            }
        }
        
        Write-Host "`nExported $($toExport.Count) certificate(s) to: ${OutDir}"
    }

    # --- Certificate chain summary display ---
    Write-Host "`n--- Certificate Chain Summary ---"
    Write-Host "Target server: ${TargetHost}:${TargetPort}"
    Write-Host "Leaf Certificate:"
    Write-Host "  Subject: $($leaf.Subject)"
    Write-Host "  Issuer:  $($leaf.Issuer)"
    Write-Host "  Thumbprint: $($leaf.Thumbprint)"
    Write-Host "  Valid From: $($leaf.NotBefore)"
    Write-Host "  Valid To:   $($leaf.NotAfter)"
    
    Write-Host "`nComplete Chain:"
    for ($i = 0; $i -lt $elements.Count; $i++) {
        $cert = $elements[$i]
        $type = Get-CertificateType -Certificate $cert `
            -IsFirstInChain ($i -eq 0) `
            -IsLastInChain ($i -eq $elements.Count - 1)
        $tag = if ($i -eq 0) { '[Leaf]' } elseif ($i -eq $elements.Count - 1) { '[Root]' } else { '[Intermediate]' }
        Write-Host "  ${tag} [${type}] $($cert.Subject) [$($cert.Thumbprint)]"
    }
    
    # --- Return certificate objects for further processing ---
    return [PSCustomObject]@{
        LeafCertificate      = $leaf
        CertificateChain     = $elements
        ExportedCertificates = $toExport
        OutputDirectory      = if (-not $NoExport) { $OutDir } else { $null }
        TargetHost           = $TargetHost
        TargetPort           = $TargetPort
        SNIHost              = $SNIHost
    }
}

function Lock-File {
    <#
.SYNOPSIS
Completely locks down a file by removing all explicit and inherited access rules.

.DESCRIPTION
The Lock-File function disables inheritance on the specified file and removes
all access control entries (ACEs). This leaves the file with no access rules,
effectively preventing all users (including Administrators) from accessing it
until permissions are explicitly restored.

.PARAMETER Path
The full path to the file you want to lock down.

.EXAMPLE
Lock-File -Path "C:\Path\To\Secret.txt"

Locks down the file Secret.txt so that no one has access.

.NOTES
- You may need to run PowerShell as Administrator if the file is in a protected location.
- To restore access, you must take ownership and reapply permissions manually

Author: jjw(@thejjw)
Last Edit: Sept 2025
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        Write-Error "The file '$Path' does not exist."
        return
    }

    try {
        # Get current ACL
        $acl = Get-Acl $Path

        # Disable inheritance and remove inherited rules
        $acl.SetAccessRuleProtection($true, $false)

        # Remove any explicit rules that might remain
        $acl.Access | ForEach-Object {
            $acl.RemoveAccessRule($_) | Out-Null
        }

        # Apply the stripped ACL back to the file
        Set-Acl -Path $Path -AclObject $acl

        Write-Output "File '$Path' has been locked down. Current access rules:"

        $rules = (Get-Acl $Path).Access
        if ($rules.Count -eq 0) {
            Write-Output "  [Empty: no access rules](expected result)"
        }
        else {
            $rules
            Write-Error "some access rules are detected(unexpected result)"
        }
    }
    catch {
        Write-Error "Failed to lock down file '$Path'. Error: $_"
    }
}

function Convert-VideoWithTransposeIntelQuickSync {
    <#
.SYNOPSIS
Rotates a video 90 degrees using Intel Quick Sync hardware acceleration.

.DESCRIPTION
Transposes (rotates) video files 90 degrees clockwise or counter-clockwise using Intel Quick Sync
encoding. Outputs an HEVC-encoded MKV file with AAC audio. Hardware acceleration via Intel QSV
significantly speeds up transcoding compared to software processing.

.PARAMETER InputFile
The full path to the input video file to rotate.

.PARAMETER CounterClockwise
If specified, rotates the video 90 degrees counter-clockwise. By default, rotates clockwise.

.PARAMETER Quality
HEVC quality level (0-51). Lower values mean higher quality. Defaults to 15.

.EXAMPLE
Convert-VideoWithTransposeIntelQuickSync -InputFile "C:\Videos\input.mp4"

Rotates input.mp4 90 degrees clockwise and saves as input_v.mkv.

.EXAMPLE
Convert-VideoWithTransposeIntelQuickSync -InputFile "C:\Videos\video.mov" -CounterClockwise

Rotates video.mov 90 degrees counter-clockwise and saves as video_v.mkv.

.EXAMPLE
Convert-VideoWithTransposeIntelQuickSync -InputFile "C:\Videos\video.mp4" -Quality 20

Rotates video.mp4 with quality level 20 (lower quality, faster encoding).

.NOTES
Requires ffmpeg with Intel QSV support and compatible Intel GPU hardware.
Output file is appended with "_v.mkv" suffix and saved in the same directory as the input.

Quality Presets (HEVC 0-51 scale, lower = better quality):
- 0-10:   Very high quality (slow encoding, ~0.5x speed)
- 11-18:  High quality (medium speed, ~1-2x speed) - DEFAULT RANGE (15)
- 19-28:  Medium/Normal quality (good balance, ~3-5x speed)
- 29-38:  Lower quality (fast encoding, ~5-10x speed)
- 39-51:  Very low quality (very fast, ~10x+ speed)

Quality 8 for archival/high-quality use cases
Quality 20 for balanced quality/speed
Quality 32 for fast encoding with acceptable quality loss

Author: jjw(@thejjw)
Last Edit: Mar 2026
#>
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputFile,
        [switch]$CounterClockwise,
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 51)]
        [int]$Quality = 15,
        [switch]$Enhance
    )
    # Strip backtick escapes before [ and ] (PowerShell tab-completion artifact)
    $InputFile = $InputFile -replace '`(?=[\[\]])', ''
    $ResolvedInput = (Get-Item -LiteralPath $InputFile).FullName
    # Build output filename by appending "_v.mkv"
    $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($ResolvedInput)
    $Directory = [System.IO.Path]::GetDirectoryName($ResolvedInput)
    if ([string]::IsNullOrEmpty($Directory)) {
        $Directory = "."
    }
    $OutputFile = Join-Path $Directory ($BaseName + "_v.mkv")
    # QSV vpp_qsv transpose operates in the GPU's video pipeline, avoiding CPU decode/encode
    if ($CounterClockwise) {
        $Mode = "vpp_qsv=transpose=cclock"
    }
    else {
        $Mode = "vpp_qsv=transpose=clock"
    }
    # Add detail enhancement if requested
    if ($Enhance) {
        $Mode = "${Mode}:detail=30"
    }
    # Pipe input through QSV hardware pipeline: decode -> transpose -> HEVC encode
    # -hwaccel qsv and -hwaccel_output_format qsv keep frames on the GPU throughout
    $ffmpegArgs = @(
        "-hwaccel", "qsv",
        "-hwaccel_output_format", "qsv",
        "-i", $ResolvedInput,
        "-vf", $Mode,
        "-c:v", "hevc_qsv",
        "-global_quality", $Quality,
        "-c:a", "aac",
        "-b:a", "192k",
        $OutputFile
    )
    Write-Host "Running ffmpeg on $ResolvedInput..."
    & ffmpeg @ffmpegArgs
}

function New-RandomDir {
    <#
.SYNOPSIS
Creates a new directory (random name by default) and changes into it.

.DESCRIPTION
New-RandomDir creates a directory inside the specified BasePath. If -Name is
not provided, a random human-readable name is generated. The command then
changes the current location to the newly created directory.

Optional switches allow initializing a git repository with a synthetic local
identity and creating basic agent documentation files (AGENTS.md, etc).

.PARAMETER BasePath
The parent directory where the new directory will be created.
Defaults to the current location.

.PARAMETER Name
Explicit name for the directory. If omitted, a random name is generated.

.PARAMETER Git
Initializes a git repository in the new directory and configures a local
identity using the format: username@hostname.local.

.PARAMETER Agents
Creates basic AGENTS.md, CLAUDE.md, and GEMINI.md template files in the
directory.
Requires -Git.

.PARAMETER Temp
Uses the user temp directory ($env:TEMP) as the base path instead of
the current location.

.PARAMETER MaxAttempts
Maximum number of attempts when generating a random directory name.

.EXAMPLE
nrd
Creates a randomly named directory in the current location and changes into it.

.EXAMPLE
nrd -Git
Creates a random directory, initializes git, and sets a synthetic local identity.

.EXAMPLE
nrd -Name scratch-api
Creates a directory with the specified name and changes into it.

.EXAMPLE
nrd -Temp -Git
Creates a random directory under $env:TEMP, initializes git.

.EXAMPLE
nrd -Git -Agents -Verbose
Creates a random directory, initializes git, creates agent templates,
and prints verbose output.

.NOTES
Alias: nrd
Author: jjw(@thejjw)
Last Edit: 2026-04

#>
    [CmdletBinding()]
    param(
        [string]$BasePath = (Get-Location).Path,
        [string]$Name,
        [switch]$Git,
        [switch]$Agents,
        [switch]$Temp,
        [int]$MaxAttempts = 50
    )

    if ($Agents -and -not $Git) {
        throw "-Agents requires -Git."
    }

    # Override base path to user temp directory when -Temp is specified
    if ($Temp) { $BasePath = $env:TEMP }

    # Retrieve randomized elements from global internal configuration
    $colors = $_NrdInternal.Colors
    $adjectives = $_NrdInternal.Adjectives
    $nouns = $_NrdInternal.Nouns

    if (-not (Test-Path -LiteralPath $BasePath)) {
        throw "Base path does not exist: $BasePath"
    }

    $BasePath = (Resolve-Path -LiteralPath $BasePath).Path
    Write-Verbose "Base path: $BasePath"

    if (-not $Name) {
        for ($i = 1; $i -le $MaxAttempts; $i++) {
            $Name = '{0}-{1}-{2}' -f
            $colors[(Get-Random -Minimum 0 -Maximum $colors.Count)],
            $adjectives[(Get-Random -Minimum 0 -Maximum $adjectives.Count)],
            $nouns[(Get-Random -Minimum 0 -Maximum $nouns.Count)]

            $candidate = Join-Path $BasePath $Name
            Write-Verbose "Attempt ${i}: $candidate"

            if (-not (Test-Path -LiteralPath $candidate)) { break }
            $Name = $null
        }

        if (-not $Name) {
            throw "Failed to generate a unique directory name after $MaxAttempts attempts."
        }
    }

    $Path = Join-Path $BasePath $Name

    if (Test-Path -LiteralPath $Path) {
        throw "Directory already exists: $Path"
    }
    Write-Verbose "Creating directory: $Path"
    $null = New-Item -ItemType Directory -Path $Path

    if ($Git) {
        $gitCmd = Get-Command git -ErrorAction SilentlyContinue
        if (-not $gitCmd) {
            Write-Warning "git not found on PATH. Skipping git setup."
        }
        else {
            $user = $env:USERNAME
            $hostName = $env:COMPUTERNAME
            $email = '{0}@{1}.local' -f $user.ToLower(), $hostName.ToLower()

            Write-Verbose "Initializing git repository"
            & git -C $Path init | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "git init failed for: $Path"
            }

            # Confirm the repository exists before writing repository-local config.
            & git -C $Path rev-parse --is-inside-work-tree *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "git init did not create a repository at: $Path"
            }

            & git -C $Path config --local user.name $user
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to set local git user.name for: $Path"
            }

            & git -C $Path config --local user.email $email
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to set local git user.email for: $Path"
            }

            Write-Host ("Git identity: {0} <{1}>" -f $user, $email)
        }
    }

    if ($Agents) {
        Write-Verbose "Creating AGENTS.md (canonical) + CLAUDE.md/GEMINI.md (@import)"

        # Write canonical AGENTS.md using the template defined in global internal configuration
        $_NrdInternal.AgentsMarkdown | Set-Content -LiteralPath (Join-Path $Path 'AGENTS.md') -Encoding UTF8

        # CLAUDE.md imports AGENTS.md -- Claude Code reads CLAUDE.md, not AGENTS.md
        '@AGENTS.md' | Set-Content -LiteralPath (Join-Path $Path 'CLAUDE.local.md') -Encoding UTF8

        # QWEN.md imports AGENTS.md -- Qwen Code reads QWEN.md, not AGENTS.md
        '@./AGENTS.md' | Set-Content -LiteralPath (Join-Path $Path 'QWEN.md') -Encoding UTF8
    }
    Write-Verbose "Changing location to: $Path"
    Set-Location -LiteralPath $Path

    Get-Item -LiteralPath $Path
}

Set-Alias nrd New-RandomDir

function Invoke-LoginAudit {
    <#
.SYNOPSIS
  Audits Windows login activity for the last N hours and writes a Markdown report.

.DESCRIPTION
  Reads the Security event log for logon-related events, summarizes them, and
  produces a human-readable Markdown file you can skim yourself and raw event
  data for further analysis. Raw event data is saved alongside as CSV so
  you can drill into specific rows.

.EXAMPLE
    Invoke-LoginAudit
    Invoke-LoginAudit -Hours 168 -OutDir C:\audits

.PARAMETER Hours
  How many hours back to look. Default 48.

.PARAMETER OutDir
  Where to write the report and CSVs. Default: cwd

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-04

    Tip: you can add the function declaration to $PROFILE then call it on future shell sessions with ease
    (note that script execution policy should allow local script execution at least, i.e. RemoteSigned)
#>
    [CmdletBinding()]
    param(
        [int]$Hours = 48,
        [string]$OutDir = (Get-Location).Path
    )

    $ErrorActionPreference = 'Stop'

    # Fail fast if not elevated - Security event log read requires admin
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Invoke-LoginAudit requires an elevated PowerShell session (reading the Security event log needs Administrator rights).'
    }

    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

    $since = (Get-Date).AddHours(-$Hours)
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $reportMd = Join-Path $OutDir "login-audit-$stamp.md"
    $successCsv = Join-Path $OutDir "4624-success-$stamp.csv"
    $failCsv = Join-Path $OutDir "4625-failed-$stamp.csv"

    $logonTypeMap = @{
        2  = 'Interactive'
        3  = 'Network'
        4  = 'Batch'
        5  = 'Service'
        7  = 'Unlock'
        8  = 'NetworkCleartext'
        9  = 'NewCredentials'
        10 = 'RemoteInteractive(RDP)'
        11 = 'CachedInteractive'
    }

    # 4625 sub-status codes -> plain English (common ones)
    $subStatusMap = @{
        '0xC0000064' = 'User does not exist'
        '0xC000006A' = 'Bad password'
        '0xC000006D' = 'Bad username or password'
        '0xC000006F' = 'Outside allowed hours'
        '0xC0000070' = 'Workstation restriction'
        '0xC0000071' = 'Password expired'
        '0xC0000072' = 'Account disabled'
        '0xC0000193' = 'Account expired'
        '0xC0000224' = 'Password must change'
        '0xC0000234' = 'Account locked out'
        '0xC000015B' = 'Logon type not granted'
    }

    function Get-Events($id) {
        try {
            Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = $id; StartTime = $since } -ErrorAction Stop
        }
        catch [System.Exception] {
            if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { @() } else { throw }
        }
    }

    function Md-Table($rows, $columns) {
        if (-not $rows) { return "_(none)_`n" }
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('| ' + ($columns -join ' | ') + ' |')
        [void]$sb.AppendLine('|' + (($columns | ForEach-Object { '---' }) -join '|') + '|')
        foreach ($r in $rows) {
            $cells = $columns | ForEach-Object {
                $v = $r.$_
                if ($null -eq $v -or $v -eq '') { '-' } else { ($v -replace '\|', '\|') }
            }
            [void]$sb.AppendLine('| ' + ($cells -join ' | ') + ' |')
        }
        $sb.ToString()
    }

    Write-Host "Collecting events since $since ..." -ForegroundColor Cyan

    $raw4624 = Get-Events 4624
    $raw4625 = Get-Events 4625
    $raw4634 = Get-Events 4634
    $raw4647 = Get-Events 4647
    $raw4740 = try {
        Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4740; StartTime = (Get-Date).AddDays(-30) } -ErrorAction Stop
    }
    catch { @() }
    $raw4800 = Get-Events 4800
    $raw4801 = Get-Events 4801

    $ok = $raw4624 | ForEach-Object {
        $lt = [int]$_.Properties[8].Value
        [PSCustomObject]@{
            Time          = $_.TimeCreated
            User          = $_.Properties[5].Value
            Domain        = $_.Properties[6].Value
            LogonType     = $lt
            LogonTypeName = $logonTypeMap[$lt]
            Workstation   = $_.Properties[11].Value
            IP            = $_.Properties[18].Value
            LogonProcess  = $_.Properties[9].Value
            AuthPackage   = $_.Properties[10].Value
            ProcessName   = $_.Properties[17].Value
        }
    }

    $fail = $raw4625 | ForEach-Object {
        $lt = [int]$_.Properties[10].Value
        $sub = ('0x{0:X}' -f [int64]$_.Properties[9].Value)
        [PSCustomObject]@{
            Time          = $_.TimeCreated
            User          = $_.Properties[5].Value
            Domain        = $_.Properties[6].Value
            LogonType     = $lt
            LogonTypeName = $logonTypeMap[$lt]
            Status        = ('0x{0:X}' -f [int64]$_.Properties[7].Value)
            SubStatus     = $sub
            Reason        = $subStatusMap[$sub]
            Workstation   = $_.Properties[13].Value
            IP            = $_.Properties[19].Value
            ProcessName   = $_.Properties[18].Value
        }
    }

    if ($ok) { $ok   | Export-Csv -NoTypeInformation -Path $successCsv }
    if ($fail) { $fail | Export-Csv -NoTypeInformation -Path $failCsv }

    # Logon types that indicate a real person at a keyboard (interactive, unlock, RDP, cached)
    $humanTypes = 2, 7, 10, 11
    $human = $ok | Where-Object { $_.LogonType -in $humanTypes }
    # Network (type 3) logons from real user accounts are worth reviewing -- these represent
    # remote access to this machine via SMB, WinRM, etc.
    $netNonSys = $ok | Where-Object {
        $_.LogonType -eq 3 -and
        $_.User -notin 'SYSTEM', 'ANONYMOUS LOGON', 'LOCAL SERVICE', 'NETWORK SERVICE' -and
        $_.IP -and $_.IP -ne '-'
    }

    # Flag non-loopback IPs on interactive/unlock events - unusual for console sign-in
    $remoteHumanFlags = $human | Where-Object { $_.IP -and $_.IP -ne '-' -and $_.IP -ne '127.0.0.1' -and $_.IP -ne '::1' }

    # Flag human logons outside business hours -- often worth investigating for compromised accounts
    $offHours = $human | Where-Object { $_.Time.Hour -lt 6 -or $_.Time.Hour -ge 22 }

    $userBreakdown = $ok | Group-Object User, LogonTypeName |
    Sort-Object Count -Descending |
    ForEach-Object {
        [PSCustomObject]@{
            Count = $_.Count
            Group = $_.Name
        }
    }

    $computer = $env:COMPUTERNAME
    $now = Get-Date
    $windowEnd = $now.ToString('yyyy-MM-dd HH:mm:ss')
    $windowStart = $since.ToString('yyyy-MM-dd HH:mm:ss')

    $md = @()
    $md += "# Login Activity Report - $computer"
    $md += ""
    $md += "- **Window:** $windowStart -> $windowEnd  (last $Hours hours)"
    $md += "- **Generated:** $now"
    $md += "- **Generated by:** ``Invoke-LoginAudit``"
    $csvRefs = @()
    if (Test-Path $successCsv) { $csvRefs += "``$successCsv``" }
    if (Test-Path $failCsv) { $csvRefs += "``$failCsv``" }
    if ($csvRefs) { $md += "- **Raw CSVs:** " + ($csvRefs -join ', ') }
    $md += ""
    $md += "## Totals"
    $md += ""
    $md += "| Event | Count | Meaning |"
    $md += "|---|---:|---|"
    $md += "| 4624 Successful logon | $($ok.Count) | All successful session creations |"
    $md += "| 4625 Failed logon | $($fail.Count) | Bad passwords / rejected auth |"
    $md += "| 4634 Logoff | $(($raw4634 | Measure-Object).Count) | Session teardowns |"
    $md += "| 4647 User-initiated logoff | $(($raw4647 | Measure-Object).Count) | Explicit sign-outs |"
    $md += "| 4740 Lockouts (last 30d) | $(($raw4740 | Measure-Object).Count) | Account lockouts |"
    $md += "| 4800 Lock | $(($raw4800 | Measure-Object).Count) | Workstation locks |"
    $md += "| 4801 Unlock | $(($raw4801 | Measure-Object).Count) | Workstation unlocks |"
    $md += ""

    $md += "## Automatic flags"
    $md += ""
    $flags = @()
    if ($fail.Count -gt 0) { $flags += "- **$($fail.Count) failed logon attempts** - see the failures table below." }
    if ((($raw4740 | Measure-Object).Count) -gt 0) { $flags += "- **Account lockouts occurred** in the last 30 days." }
    if ($remoteHumanFlags) { $flags += "- **$($remoteHumanFlags.Count) human-type logons recorded a non-loopback source IP** - unusual for a console sign-in." }
    if ($offHours) { $flags += "- **$($offHours.Count) human-type logons outside 06:00-22:00** - double-check these are yours." }
    if ($netNonSys) { $flags += "- **$($netNonSys.Count) non-SYSTEM network logons** from remote hosts - confirm each source is expected." }
    if (-not $flags) { $flags += "_No automatic flags raised. Still eyeball the tables below._" }
    $md += $flags
    $md += ""

    $md += "## Breakdown by user + logon type (4624)"
    $md += ""
    $md += (Md-Table $userBreakdown @('Count', 'Group'))

    $md += "## Human-type logons (Interactive / Unlock / RDP / CachedInteractive)"
    $md += ""
    $md += "Logon types 2, 7, 10, 11. These are the events that represent a real person signing in."
    $md += ""
    $md += (Md-Table ($human | Sort-Object Time -Descending) @('Time', 'User', 'Domain', 'LogonTypeName', 'Workstation', 'IP'))

    $md += "## Network logons from non-SYSTEM accounts (type 3)"
    $md += ""
    $md += "Remote access to this machine (SMB shares, WinRM, etc.) that used a real user credential."
    $md += ""
    $md += (Md-Table ($netNonSys | Sort-Object Time -Descending) @('Time', 'User', 'Domain', 'IP', 'Workstation'))

    $md += "## Failed logons (4625)"
    $md += ""
    $md += (Md-Table ($fail | Sort-Object Time -Descending) @('Time', 'User', 'Domain', 'LogonTypeName', 'Reason', 'SubStatus', 'IP', 'Workstation'))

    $md += "## Account lockouts (4740, last 30 days)"
    $md += ""
    $lockoutRows = $raw4740 | ForEach-Object {
        [PSCustomObject]@{
            Time           = $_.TimeCreated
            LockedAccount  = $_.Properties[0].Value
            CallerComputer = $_.Properties[1].Value
        }
    }
    $md += (Md-Table $lockoutRows @('Time', 'LockedAccount', 'CallerComputer'))

    $md += "## Logon type reference"
    $md += ""
    $md += "| Type | Name | Meaning |"
    $md += "|---:|---|---|"
    $md += "| 2 | Interactive | Signed in at the console (keyboard) |"
    $md += "| 3 | Network | Accessed a share / WinRM / remote API |"
    $md += "| 4 | Batch | Scheduled task |"
    $md += "| 5 | Service | Service account starting |"
    $md += "| 7 | Unlock | Unlocked a locked session |"
    $md += "| 8 | NetworkCleartext | Network logon with cleartext creds (!) |"
    $md += "| 9 | NewCredentials | RunAs /netonly |"
    $md += "| 10 | RemoteInteractive | RDP |"
    $md += "| 11 | CachedInteractive | Cached domain creds (offline) |"
    $md += ""

    $md += "## What to do next"
    $md += ""
    $md += "1. Skim the **Human-type logons** table - do you recognize every row?"
    $md += "2. For any flagged non-loopback IP on an interactive/unlock event, check whether an RDP / remote-management tool was running at that time."
    $md += "3. For **Network logons**, confirm each source hostname/IP is a device you own."
    $md += "4. If something looks off, run again with a longer window: ``-Hours 168`` for a week."
    $md += "5. Paste this Markdown file back to other tools for further analysis - include the raw CSVs if you want row-level drilldown."
    $md += ""

    $md -join "`r`n" | Set-Content -Encoding UTF8 -Path $reportMd

    Write-Host ""
    Write-Host "Report written: $reportMd" -ForegroundColor Green
    if (Test-Path $successCsv) { Write-Host "Success CSV:    $successCsv" } else { Write-Host "Success CSV:    (not created - no 4624 events)" -ForegroundColor DarkGray }
    if (Test-Path $failCsv) { Write-Host "Failed CSV:     $failCsv" }    else { Write-Host "Failed CSV:     (not created - no 4625 events)" -ForegroundColor DarkGray }
    Write-Host ""
    Write-Host "Open the report:" -ForegroundColor Cyan
    Write-Host "  notepad `"$reportMd`""
}

function Invoke-RebootAudit {
    <#
.SYNOPSIS
  Audits recent Windows shutdown/reboot events and writes a Markdown diagnosis.

.DESCRIPTION
  Reads System event log reboot markers, planned-shutdown records, unexpected
  shutdown records, Kernel-Power bugcheck fields, and nearby update/service
  context. Produces a short Markdown report plus raw CSV data, with search
  hints for bugcheck codes and other evidence that is useful for follow-up
  diagnosis.

.EXAMPLE
    Invoke-RebootAudit
    Invoke-RebootAudit -Hours 336 -ContextMinutes 90 -OutDir C:\audits

.PARAMETER Hours
  How many hours back to look. Default 168.

.PARAMETER ContextMinutes
  How many minutes around the current boot time to use for the main diagnosis.
  Default 60.

.PARAMETER OutDir
  Where to write the report and CSV. Default: cwd

.PARAMETER IncludeReliability
  Also query Reliability Monitor WMI records for nearby Windows failures.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06

    References:
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
    - https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart
    - https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
#>
    [CmdletBinding()]
    param(
        [int]$Hours = 168,
        [int]$ContextMinutes = 60,
        [string]$OutDir = (Get-Location).Path,
        [switch]$IncludeReliability
    )

    $ErrorActionPreference = 'Stop'

    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir | Out-Null
    }

    $since = (Get-Date).AddHours(-$Hours)
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $reportMd = Join-Path $OutDir "reboot-audit-$stamp.md"
    $eventsCsv = Join-Path $OutDir "reboot-events-$stamp.csv"
    $reliabilityCsv = Join-Path $OutDir "reboot-reliability-$stamp.csv"

    $eventNames = @{
        12   = 'OS start'
        13   = 'OS shutdown'
        19   = 'Windows Update install'
        41   = 'Kernel-Power unexpected restart'
        1001 = 'Bugcheck / WER'
        1074 = 'Planned restart/shutdown'
        6005 = 'Event Log service started'
        6006 = 'Event Log service stopped'
        6008 = 'Previous shutdown unexpected'
        6009 = 'OS version at boot'
        7045 = 'Service installed'
    }

    $bugcheckNames = @{
        '0x1A'  = 'MEMORY_MANAGEMENT'
        '0x3B'  = 'SYSTEM_SERVICE_EXCEPTION'
        '0x50'  = 'PAGE_FAULT_IN_NONPAGED_AREA'
        '0x7A'  = 'KERNEL_DATA_INPAGE_ERROR'
        '0x7B'  = 'INACCESSIBLE_BOOT_DEVICE'
        '0x7E'  = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'
        '0x9C'  = 'MACHINE_CHECK_EXCEPTION'
        '0xA'   = 'IRQL_NOT_LESS_OR_EQUAL'
        '0xD1'  = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'
        '0xEF'  = 'CRITICAL_PROCESS_DIED'
        '0xF4'  = 'CRITICAL_OBJECT_TERMINATION'
        '0x101' = 'CLOCK_WATCHDOG_TIMEOUT'
        '0x116' = 'VIDEO_TDR_FAILURE'
        '0x124' = 'WHEA_UNCORRECTABLE_ERROR'
        '0x133' = 'DPC_WATCHDOG_VIOLATION'
        '0x139' = 'KERNEL_SECURITY_CHECK_FAILURE'
        '0x154' = 'UNEXPECTED_STORE_EXCEPTION'
        '0x1E'  = 'KMODE_EXCEPTION_NOT_HANDLED'
        '0x1F7' = 'KERNEL_MODE_HEAP_CORRUPTION'
    }

    function Get-RebootEvents {
        param([int[]]$Ids)
        try {
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = $Ids; StartTime = $since } -ErrorAction Stop
        }
        catch [System.Exception] {
            if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { @() } else { throw }
        }
    }

    function Get-EventDataMap {
        param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
        $map = @{}
        try {
            [xml]$xml = $Event.ToXml()
            foreach ($data in $xml.Event.EventData.Data) {
                $name = [string]$data.Name
                if (-not $name) { continue }
                $map[$name] = [string]$data.'#text'
            }
        }
        catch {
            return @{}
        }
        return $map
    }

    function Convert-BugcheckCode {
        param([object]$Value)
        if ($null -eq $Value -or [string]$Value -eq '') { return $null }

        $text = [string]$Value
        try {
            if ($text.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
                $decimal = [convert]::ToInt64($text.Substring(2), 16)
            }
            else {
                $decimal = [int64]$text
            }

            return [pscustomobject]@{
                Decimal = $decimal
                Hex     = ('0x{0:X}' -f $decimal)
                Name    = $bugcheckNames[('0x{0:X}' -f $decimal)]
            }
        }
        catch {
            return [pscustomobject]@{
                Decimal = $null
                Hex     = $text
                Name    = $null
            }
        }
    }

    function Get-WerDetails {
        param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

        $code = $null
        $dump = $null
        if ($Event.Message -match '(?i)bugcheck was:\s+(0x[0-9a-f]+)') { $code = $Matches[1].ToUpperInvariant() }
        if ($Event.Message -match '(?i)dump was saved in:\s+([^\r\n]+)') { $dump = $Matches[1].Trim() }

        return [pscustomobject]@{
            BugcheckCode = $code
            DumpPath     = $dump
        }
    }

    function Format-SearchHint {
        param([string]$Query)
        if (-not $Query) { return $null }
        return "Search: $Query"
    }

    function Format-MdTable {
        param(
            [object[]]$Rows,
            [string[]]$Columns
        )
        if (-not $Rows -or $Rows.Count -eq 0) { return "_(none)_`n" }

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('| ' + ($Columns -join ' | ') + ' |')
        [void]$sb.AppendLine('|' + (($Columns | ForEach-Object { '---' }) -join '|') + '|')
        foreach ($row in $Rows) {
            $cells = $Columns | ForEach-Object {
                $value = $row.$_
                if ($null -eq $value -or $value -eq '') { '-' } else { ([string]$value -replace '\|', '\|') }
            }
            [void]$sb.AppendLine('| ' + ($cells -join ' | ') + ' |')
        }
        return $sb.ToString()
    }

    Write-Host "Collecting reboot events since $since ..." -ForegroundColor Cyan

    $rawEvents = Get-RebootEvents -Ids ([int[]]$eventNames.Keys)
    $lastBootSource = 'Win32_OperatingSystem.LastBootUpTime'
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $lastBoot = $os.LastBootUpTime
    }
    catch {
        $lastBootSource = 'latest System boot marker event'
        $lastBootEvent = $rawEvents |
            Where-Object { $_.Id -in 12, 6005, 6009 } |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 1
        if (-not $lastBootEvent) {
            throw "Could not determine last boot time from CIM or System boot marker events: $($_.Exception.Message)"
        }
        $lastBoot = $lastBootEvent.TimeCreated
    }
    $contextStart = $lastBoot.AddMinutes(-1 * $ContextMinutes)
    $contextEnd = $lastBoot.AddMinutes($ContextMinutes)
    $events = $rawEvents | Sort-Object TimeCreated | ForEach-Object {
        $data = Get-EventDataMap $_
        $bugcheck = $null
        $bugcheckName = $null
        $powerButton = $null
        $sleepInProgress = $null
        $dumpPath = $null
        $hint = $null

        if ($_.Id -eq 41 -and $data.ContainsKey('BugcheckCode')) {
            $bugcheck = Convert-BugcheckCode $data.BugcheckCode
            $bugcheckName = $bugcheck.Name
            $powerButton = $data.PowerButtonTimestamp
            $sleepInProgress = $data.SleepInProgress
            if ($bugcheck.Decimal -and $bugcheck.Decimal -ne 0) {
                $query = if ($bugcheck.Name) { "Windows bugcheck $($bugcheck.Hex) $($bugcheck.Name)" } else { "Windows bugcheck $($bugcheck.Hex)" }
                $hint = Format-SearchHint $query
            }
        }
        elseif ($_.Id -eq 1001) {
            $wer = Get-WerDetails $_
            if ($wer.BugcheckCode) {
                $bugcheck = Convert-BugcheckCode $wer.BugcheckCode
                $bugcheckName = $bugcheck.Name
                $query = if ($bugcheck.Name) { "Windows bugcheck $($bugcheck.Hex) $($bugcheck.Name)" } else { "Windows bugcheck $($bugcheck.Hex)" }
                $hint = Format-SearchHint $query
            }
            $dumpPath = $wer.DumpPath
        }
        elseif ($_.Id -eq 1074) {
            $hint = Format-SearchHint 'Windows Event ID 1074 shutdown reason code process user'
        }
        elseif ($_.Id -eq 6008) {
            $hint = Format-SearchHint 'Windows Event ID 6008 previous shutdown was unexpected'
        }

        [pscustomobject]@{
            Time            = $_.TimeCreated
            Id              = $_.Id
            Event           = $eventNames[$_.Id]
            Provider        = $_.ProviderName
            Level           = $_.LevelDisplayName
            BugcheckCode    = if ($bugcheck) { $bugcheck.Hex } else { $null }
            BugcheckName    = $bugcheckName
            PowerButtonTime = $powerButton
            SleepInProgress = $sleepInProgress
            DumpPath        = $dumpPath
            SearchHint      = $hint
            Message         = ($_.Message -replace '\s+', ' ').Trim()
        }
    }

    if ($events) {
        $events | Export-Csv -NoTypeInformation -Path $eventsCsv
    }

    $nearBoot = @($events | Where-Object { $_.Time -ge $contextStart -and $_.Time -le $contextEnd })
    $planned = @($nearBoot | Where-Object { $_.Id -eq 1074 } | Sort-Object Time -Descending)
    $unexpected = @($nearBoot | Where-Object { $_.Id -in 41, 6008 } | Sort-Object Time -Descending)
    $bugchecks = @($nearBoot | Where-Object { $_.BugcheckCode -and $_.BugcheckCode -ne '0x0' } | Sort-Object Time -Descending)
    $werBugchecks = @($nearBoot | Where-Object { $_.Id -eq 1001 -and $_.BugcheckCode } | Sort-Object Time -Descending)
    $updateContext = @($events | Where-Object { $_.Id -in 19, 7045 -and $_.Time -ge $lastBoot.AddHours(-6) -and $_.Time -le $lastBoot } | Sort-Object Time -Descending)
    $lastKernelPower = @($nearBoot | Where-Object { $_.Id -eq 41 } | Sort-Object Time -Descending | Select-Object -First 1)
    $lastUnexpected = @($nearBoot | Where-Object { $_.Id -eq 6008 } | Sort-Object Time -Descending | Select-Object -First 1)

    $likelyType = 'Inconclusive'
    $interpretation = 'No planned shutdown, unexpected shutdown, or bugcheck marker was found near the current boot window.'
    if ($bugchecks -or $werBugchecks) {
        $likelyType = 'Unexpected reboot with bugcheck / BSOD evidence'
        $firstBugcheck = @($bugchecks + $werBugchecks | Sort-Object Time -Descending | Select-Object -First 1)[0]
        $label = if ($firstBugcheck.BugcheckName) { "$($firstBugcheck.BugcheckCode) $($firstBugcheck.BugcheckName)" } else { $firstBugcheck.BugcheckCode }
        $interpretation = "Windows recorded a non-zero bugcheck code near boot: $label."
    }
    elseif ($unexpected) {
        $likelyType = 'Unexpected reboot without captured bugcheck'
        $kp = @($lastKernelPower)[0]
        if ($kp -and $kp.PowerButtonTime -and $kp.PowerButtonTime -ne '0' -and $kp.PowerButtonTime -ne '0x0') {
            $interpretation = 'Kernel-Power recorded a power-button timestamp, so a long power-button press is plausible.'
        }
        else {
            $interpretation = 'Windows did not record a clean shutdown or a non-zero bugcheck. Suspect power loss, hard hang, reset, firmware, thermal, storage, or PSU causes.'
        }
    }
    elseif ($planned) {
        $likelyType = 'Planned restart/shutdown'
        $interpretation = 'A USER32/Event ID 1074 planned shutdown or restart event was found near the current boot.'
    }

    $reliabilityRows = @()
    if ($IncludeReliability) {
        try {
            $reliabilityRows = @(Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction Stop |
                ForEach-Object {
                    $time = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.TimeGenerated)
                    if ($time -lt $since) { return }
                    [pscustomobject]@{
                        Time    = $time
                        Source  = $_.SourceName
                        Product = $_.ProductName
                        EventId = $_.EventIdentifier
                        Message = ($_.Message -replace '\s+', ' ').Trim()
                    }
                } |
                Sort-Object Time -Descending)

            if ($reliabilityRows) {
                $reliabilityRows | Export-Csv -NoTypeInformation -Path $reliabilityCsv
            }
        }
        catch {
            $reliabilityRows = @([pscustomobject]@{
                    Time    = Get-Date
                    Source  = 'Invoke-RebootAudit'
                    Product = 'Reliability Monitor'
                    EventId = ''
                    Message = "Reliability records unavailable: $($_.Exception.Message)"
                })
        }
    }

    $computer = $env:COMPUTERNAME
    $now = Get-Date
    $windowStart = $since.ToString('yyyy-MM-dd HH:mm:ss')
    $windowEnd = $now.ToString('yyyy-MM-dd HH:mm:ss')

    $evidence = @()
    if ($planned) { $evidence += "- Planned shutdown/restart events near boot: $($planned.Count)" }
    if ($unexpected) { $evidence += "- Unexpected shutdown/restart events near boot: $($unexpected.Count)" }
    if ($bugchecks -or $werBugchecks) {
        foreach ($row in @($bugchecks + $werBugchecks | Sort-Object Time -Descending | Select-Object -First 3)) {
            $codeLabel = if ($row.BugcheckName) { "$($row.BugcheckCode) $($row.BugcheckName)" } else { $row.BugcheckCode }
            $evidence += "- Bugcheck evidence: $codeLabel at $($row.Time)"
        }
    }
    if ($lastKernelPower) {
        $kp = @($lastKernelPower)[0]
        $evidence += "- Kernel-Power 41: BugcheckCode=$($kp.BugcheckCode), PowerButtonTimestamp=$($kp.PowerButtonTime), SleepInProgress=$($kp.SleepInProgress)"
    }
    if ($lastUnexpected) { $evidence += "- EventLog 6008 reports the previous shutdown was unexpected." }
    if (-not $evidence) { $evidence += "_No direct evidence found in the current boot context window._" }

    $hints = @()
    foreach ($row in @($nearBoot | Where-Object SearchHint | Select-Object -ExpandProperty SearchHint -Unique)) {
        $hints += "- $row"
    }
    foreach ($row in @($bugchecks + $werBugchecks | Where-Object DumpPath | Select-Object -First 3)) {
        $hints += "- Dump file to inspect with WinDbg: ``$($row.DumpPath)``"
    }
    $hints += "- Reference: Microsoft Bug Check Code Reference - https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2"
    $hints += "- Reference: Kernel-Power Event ID 41 - https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart"

    $md = @()
    $md += "# Reboot Cause Report - $computer"
    $md += ""
    $md += "- **Window:** $windowStart -> $windowEnd  (last $Hours hours)"
    $md += "- **Generated:** $now"
    $md += "- **Generated by:** ``Invoke-RebootAudit``"
    $md += "- **Last boot:** $lastBoot  ($lastBootSource)"
    $md += "- **Diagnosis context:** $($contextStart.ToString('yyyy-MM-dd HH:mm:ss')) -> $($contextEnd.ToString('yyyy-MM-dd HH:mm:ss'))"
    if (Test-Path -LiteralPath $eventsCsv) { $md += "- **Raw event CSV:** ``$eventsCsv``" }
    if (Test-Path -LiteralPath $reliabilityCsv) { $md += "- **Reliability CSV:** ``$reliabilityCsv``" }
    $md += ""
    $md += "## Likely cause"
    $md += ""
    $md += "- **Type:** $likelyType"
    $md += "- **Interpretation:** $interpretation"
    $md += ""
    $md += "## Evidence"
    $md += ""
    $md += $evidence
    $md += ""
    $md += "## Search hints"
    $md += ""
    $md += ($hints | Select-Object -Unique)
    $md += ""
    $md += "## Events around current boot"
    $md += ""
    $md += (Format-MdTable ($nearBoot | Sort-Object Time -Descending | Select-Object Time, Id, Event, Provider, BugcheckCode, BugcheckName, PowerButtonTime, SearchHint) @('Time', 'Id', 'Event', 'Provider', 'BugcheckCode', 'BugcheckName', 'PowerButtonTime', 'SearchHint'))
    $md += "## Planned shutdown/restart records"
    $md += ""
    $md += (Format-MdTable ($planned | Select-Object Time, Id, Event, Provider, Message) @('Time', 'Id', 'Event', 'Provider', 'Message'))
    $md += "## Nearby update/service context"
    $md += ""
    $md += (Format-MdTable ($updateContext | Select-Object Time, Id, Event, Provider, Message) @('Time', 'Id', 'Event', 'Provider', 'Message'))
    if ($IncludeReliability) {
        $md += "## Reliability Monitor records"
        $md += ""
        $md += (Format-MdTable ($reliabilityRows | Select-Object -First 30) @('Time', 'Source', 'Product', 'EventId', 'Message'))
    }
    $md += "## What to do next"
    $md += ""
    $md += "1. If a bugcheck code is listed, search the exact code plus the bugcheck name and inspect the dump path with WinDbg."
    $md += "2. If Kernel-Power 41 has BugcheckCode 0 and PowerButtonTimestamp 0, prioritize power loss, hard hang, thermal, firmware, PSU, and storage checks."
    $md += "3. If Event ID 1074 is present, inspect the process/user in the planned shutdown table to see what initiated the restart."
    $md += "4. If update or service-install events appear shortly before the reboot, correlate those packages or drivers with the failure time."
    $md += "5. Run with ``-IncludeReliability`` for Reliability Monitor records, or extend the range with ``-Hours 336``."
    $md += ""

    $md -join "`r`n" | Set-Content -Encoding UTF8 -Path $reportMd

    Write-Host ""
    Write-Host "Likely type: $likelyType" -ForegroundColor Yellow
    Write-Host "Last boot:   $lastBoot"
    Write-Host "Report:      $reportMd" -ForegroundColor Green
    if (Test-Path -LiteralPath $eventsCsv) { Write-Host "Events CSV:  $eventsCsv" }
    if (Test-Path -LiteralPath $reliabilityCsv) { Write-Host "Reliability: $reliabilityCsv" }
    Write-Host ""
    Write-Host "Open the report:" -ForegroundColor Cyan
    Write-Host "  notepad `"$reportMd`""

    [pscustomobject]@{
        LastBoot       = $lastBoot
        LikelyType     = $likelyType
        Interpretation = $interpretation
        ReportPath     = $reportMd
        EventsCsv      = if (Test-Path -LiteralPath $eventsCsv) { $eventsCsv } else { $null }
    }
}

function Install-GlobalClaudeMd {
    <#
.SYNOPSIS
    Creates the global ~/.claude/CLAUDE.md with multi-model MCP tool preferences.

.DESCRIPTION
    Idempotent - skips creation if the file already exists.
    Shared by all Claude Code provider setup functions (claudez, claudemm, etc.).

.EXAMPLE
    Install-GlobalClaudeMd

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param()

    $claudeDir = Join-Path $HOME '.claude'
    $globalMd = Join-Path $claudeDir 'CLAUDE.md'
    # Retrieve template from internal configuration
    $prefText = $_ClaudeInternal.GlobalClaudeMd

    if (-not (Test-Path -LiteralPath $claudeDir)) {
        $null = New-Item -ItemType Directory -Path $claudeDir -Force
    }

    if (Test-Path -LiteralPath $globalMd) {
        Write-Host "global CLAUDE.md: $globalMd already exists -- skipping"
        Write-Verbose 'global CLAUDE.md: edit it manually to include multi-model MCP preferences'
    }
    else {
        Set-Content -LiteralPath $globalMd -Value $prefText -Encoding UTF8
        Write-Host "global CLAUDE.md: created $globalMd" -ForegroundColor Green
    }
}

function Install-GlobalClaudeSettings {
    <#
.SYNOPSIS
    Ensures ~/.claude/settings.json has attribution disabled (no Co-Authored-By).

.DESCRIPTION
    One-shot: after successful update, drops a sentinel file (.claude/.no_attribution)
    so subsequent calls skip immediately. Uses native PowerShell JSON handling (no jq).
    Shared by all Claude Code provider setup functions (claudez, claudemm, etc.).

.EXAMPLE
    Install-GlobalClaudeSettings

.EXAMPLE
    Install-GlobalClaudeSettings -Force

.PARAMETER Force
    Bypass the sentinel check and reapply settings even if setup was previously completed.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    $claudeDir = Join-Path $HOME '.claude'
    $claudeBinDir = Join-Path $claudeDir 'bin'
    $sentinel = Join-Path $claudeDir '.config_setup_done'

    if ((Test-Path -LiteralPath $sentinel) -and -not $Force) {
        Write-Host "claude: global config setup already done -- skipping"
        return
    }

    if (-not (Test-Path -LiteralPath $claudeBinDir)) {
        $null = New-Item -ItemType Directory -Path $claudeBinDir -Force
    }

    $targetStatusLine = Join-Path $claudeBinDir 'cc_statusline.sh'

    try {
        Invoke-RestMethod -Uri $_AiToolsInternal.Urls.CcStatusline -OutFile $targetStatusLine
    } catch {
        Write-Warning "claude: download failure caused setup to stop ($($_)). Please check internet availability and run the command again."
        return
    }

    $settingsJson = Join-Path $claudeDir 'settings.json'

    if (Test-Path -LiteralPath $settingsJson) {
        $settings = Get-Content -LiteralPath $settingsJson -Raw | ConvertFrom-Json
    }
    else {
        $settings = [pscustomobject]@{}
    }

    $settings | Add-Member -NotePropertyName 'attribution' -NotePropertyValue ([pscustomobject]@{ commit = ''; pr = '' }) -Force

    # Prefer PowerShell tool over Bash on Windows
    $settings | Add-Member -NotePropertyName 'env' -NotePropertyValue ([pscustomobject]@{ CLAUDE_CODE_USE_POWERSHELL_TOOL = '1' }) -Force

    if (Test-Path -LiteralPath $targetStatusLine) {
        # On Windows, .sh files are not directly executable; locate Git bash and
        # write a .cmd wrapper so Claude Code can invoke the script without PATH issues.
        $bashExe = $null
        foreach ($candidate in @('C:\Program Files\Git\bin\bash.exe', 'C:\Program Files\Git\usr\bin\bash.exe')) {
            if (Test-Path $candidate) { $bashExe = $candidate; break }
        }
        if (-not $bashExe) {
            $bashCmd = Get-Command bash.exe -ErrorAction SilentlyContinue
            if ($bashCmd) { $bashExe = $bashCmd.Source }
        }

        if ($bashExe) {
            $wrapperPath = Join-Path $claudeBinDir 'statusline.cmd'
            $wrapperContent = "@echo off`r`n`"$bashExe`" `"$targetStatusLine`"`r`n"
            [IO.File]::WriteAllText($wrapperPath, $wrapperContent, [Text.Encoding]::ASCII)
            $statusLineCommand = $wrapperPath -replace '\\', '/'
        } else {
            # No bash found; fall back to raw .sh (may not work on Windows)
            $statusLineCommand = $targetStatusLine -replace '\\', '/'
            Write-Warning "claude: bash.exe not found; statusline may not work. Install Git for Windows and re-run."
        }
        $settings | Add-Member -NotePropertyName 'statusLine' -NotePropertyValue ([pscustomobject]@{ type = 'command'; command = $statusLineCommand; refreshInterval = 2 }) -Force
    }

    [IO.File]::WriteAllText($settingsJson, ($settings | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    $null = New-Item -ItemType File -Path $sentinel -Force
    Write-Host "claude: config setup complete" -ForegroundColor Green
}

function Install-AgySettings {
    <#
.SYNOPSIS
    Ensures ~/.gemini/antigravity-cli/settings.json has the custom status line configured.

.PARAMETER Force
    Bypass the sentinel check and reapply settings even if setup was previously completed.
#>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    $agyDir = Join-Path $HOME '.gemini\antigravity-cli'
    $agyBinDir = Join-Path $agyDir 'bin'
    $sentinel = Join-Path $agyDir '.config_setup_done'

    if ((Test-Path -LiteralPath $sentinel) -and -not $Force) {
        Write-Host "agy: config setup already done -- skipping"
        return
    }

    if (-not (Test-Path -LiteralPath $agyBinDir)) {
        $null = New-Item -ItemType Directory -Path $agyBinDir -Force
    }

    $targetStatusLine = Join-Path $agyBinDir 'agy_statusline.sh'

    try {
        Invoke-RestMethod -Uri $_AiToolsInternal.Urls.AgyStatusline -OutFile $targetStatusLine
    } catch {
        if (-not (Test-Path -LiteralPath $targetStatusLine)) {
            Write-Warning "agy: download failure caused setup to stop ($($_)). Please check internet availability and run the command again."
            return
        }
        Write-Warning "agy: unable to update agy_statusline.sh script ($($_)), using existing file."
    }

    $settingsJson = Join-Path $agyDir 'settings.json'

    if (Test-Path -LiteralPath $settingsJson) {
        $settings = Get-Content -LiteralPath $settingsJson -Raw | ConvertFrom-Json
    }
    else {
        $settings = [pscustomobject]@{}
    }

    if (Test-Path -LiteralPath $targetStatusLine) {
        # agy is written in Go and executes the statusline command using "sh" under the hood.
        # Since Windows does not have a native "sh" in the PATH by default, we detect Git's sh.exe
        # and create a sh.cmd wrapper both in the folder of agy.exe and the agy bin directory.
        $gitShExe = $null
        foreach ($candidate in @('C:\Program Files\Git\bin\sh.exe', 'C:\Program Files\Git\usr\bin\sh.exe')) {
            if (Test-Path $candidate) { $gitShExe = $candidate; break }
        }
        if (-not $gitShExe) {
            $shCmd = Get-Command sh.exe -ErrorAction SilentlyContinue
            if ($shCmd) { $gitShExe = $shCmd.Source }
        }

        if ($gitShExe) {
            $shWrapperContent = "@echo off`r`n`"$gitShExe`" %*`r`n"
            
            # 1. Write wrapper to agy.exe directory if resolved (ensures immediate PATH discovery)
            $agyExe = Get-Command agy -ErrorAction SilentlyContinue
            if ($agyExe) {
                $agyExeDir = Split-Path $agyExe.Source -Parent
                $shWrapperPath = Join-Path $agyExeDir 'sh.cmd'
                [IO.File]::WriteAllText($shWrapperPath, $shWrapperContent, [Text.Encoding]::ASCII)
            }
            
            # 2. Write wrapper to the agy bin directory as a secondary fallback
            $shBinWrapperPath = Join-Path $agyBinDir 'sh.cmd'
            [IO.File]::WriteAllText($shBinWrapperPath, $shWrapperContent, [Text.Encoding]::ASCII)
        } else {
            Write-Warning "agy: Git sh.exe not found. Please install Git for Windows."
        }

        $targetStatusLineBash = $targetStatusLine -replace '\\', '/'
        $settings | Add-Member -NotePropertyName 'statusLine' -NotePropertyValue ([pscustomobject]@{ type = 'command'; command = $targetStatusLineBash }) -Force
    }

    # Set-Content -Encoding UTF8 writes a BOM in WinPS 5.1; use WriteAllText
    # with an explicit no-BOM encoder so JSON parsers don't choke on it.
    [IO.File]::WriteAllText($settingsJson, ($settings | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    $null = New-Item -ItemType File -Path $sentinel -Force
    Write-Host "agy: config setup complete" -ForegroundColor Green
}

function Install-CodexSettings {
    <#
.SYNOPSIS
    Ensures ~/.codex/config.toml has the custom status line array and no attribution.

.PARAMETER Force
    Bypass the sentinel check and reapply settings even if setup was previously completed.
#>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    $codexDir = Join-Path $HOME '.codex'
    $sentinel = Join-Path $codexDir '.config_setup_done'

    if ((Test-Path -LiteralPath $sentinel) -and -not $Force) {
        Write-Host "codex: config setup already done -- skipping"
        return
    }

    if (-not (Test-Path -LiteralPath $codexDir)) {
        $null = New-Item -ItemType Directory -Path $codexDir -Force
    }

    $configToml = Join-Path $codexDir 'config.toml'
    if (-not (Test-Path -LiteralPath $configToml)) {
        New-Item -ItemType File -Path $configToml -Force | Out-Null
    }

    $content = Get-Content -LiteralPath $configToml -Raw
    if ($content -match '\[tui\]') {
        Write-Host "codex: [tui] block already present -- skipping statusline preset"
    }
    else {
        $preset = @"

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
"@
        Add-Content -LiteralPath $configToml -Value $preset -Encoding UTF8
        Write-Host "codex: statusline preset configured"
    }

    $null = New-Item -ItemType File -Path $sentinel -Force
    Write-Host "codex: config setup complete" -ForegroundColor Green
}

function Install-ClaudezSetup {
    <#
.SYNOPSIS
    Configures claudez MCP servers for Z.AI.

.DESCRIPTION
    Configures claude MCP servers for Z.AI.
    Uses a flag file under ~/.claude to skip duplicate MCP setup runs unless -Force is specified.

.PARAMETER Token
    Z.AI API token used for MCP server configuration.

.PARAMETER Force
    Re-runs MCP setup even if the setup flag already exists.

.EXAMPLE
    Install-ClaudezSetup -Token "<token>"

.EXAMPLE
    Install-ClaudezSetup -Token "<token>" -Force

.NOTES
    for delete/cleanup of existing MCP servers (if you want to start fresh):
    claude mcp list | ForEach-Object {
        $name = ($_ -split ':')[0].Trim()
        if ($name) { claude mcp remove $name }
    }

    Author: jjw(@thejjw)
    Last Edit: 2026-04
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [switch]$Force
    )

    $claudeDir = Join-Path $HOME '.claude'
    $setupFlag = Join-Path $claudeDir '.claudez_setup_complete'

    $claudeCmd = Get-Command claude -ErrorAction SilentlyContinue
    if ($null -eq $claudeCmd) {
        Write-Host 'WARNING: claude CLI not found, skipping MCP server configuration' -ForegroundColor Yellow
        return $false
    }

    if ((Test-Path -LiteralPath $setupFlag) -and -not $Force) {
        Write-Host "claudez: MCP setup already completed (flag: $setupFlag) -- skipping"
        Write-Host 'claudez: use Install-ClaudezSetup -Force to reconfigure MCP servers' -ForegroundColor DarkGray
        return $true
    }

    Write-Host "claudez: configuring MCP servers..." -ForegroundColor Cyan

    # Check-before-add pattern: 'claude mcp list' is slow but idempotent; avoids duplicate entries
    # web-search-prime
    # https://docs.z.ai/devpack/mcp/search-mcp-server
    if (& claude mcp list | Select-String -Pattern 'web-search-prime' -Quiet) {
        Write-Host "claudez: web-search-prime already exists -- skipping" -ForegroundColor DarkGray
    }
    else {
        & claude mcp add -s user -t http web-search-prime https://api.z.ai/api/mcp/web_search_prime/mcp --header "Authorization: Bearer $Token" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "claudez: added web-search-prime" -ForegroundColor Green
        }
        else {
            Write-Warning "claudez: failed to add web-search-prime"
        }
    }

    # web-reader
    # https://docs.z.ai/devpack/mcp/reader-mcp-server
    if (& claude mcp list | Select-String -Pattern 'web-reader' -Quiet) {
        Write-Host "claudez: web-reader already exists -- skipping" -ForegroundColor DarkGray
    }
    else {
        & claude mcp add -s user -t http web-reader https://api.z.ai/api/mcp/web_reader/mcp --header "Authorization: Bearer $Token" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "claudez: added web-reader" -ForegroundColor Green
        }
        else {
            Write-Warning "claudez: failed to add web-reader"
        }
    }

    # zread
    # https://docs.z.ai/devpack/mcp/zread-mcp-server
    if (& claude mcp list | Select-String -Pattern 'zread' -Quiet) {
        Write-Host "claudez: zread already exists -- skipping" -ForegroundColor DarkGray
    }
    else {
        & claude mcp add -s user -t http zread https://api.z.ai/api/mcp/zread/mcp --header "Authorization: Bearer $Token" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "claudez: added zread" -ForegroundColor Green
        }
        else {
            Write-Warning "claudez: failed to add zread"
        }
    }

    # zai-mcp-server runs locally via npx (stdio transport), unlike the HTTP-based servers above
    # zai-mcp-server
    # https://docs.z.ai/devpack/mcp/vision-mcp-server
    if (& claude mcp list | Select-String -Pattern 'zai-mcp-server' -Quiet) {
        Write-Host "claudez: zai-mcp-server already exists -- skipping" -ForegroundColor DarkGray
    }
    else {
        & claude mcp add -s user zai-mcp-server --env Z_AI_API_KEY=$Token Z_AI_MODE=ZAI -- cmd /c npx -y "@z_ai/mcp-server" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "claudez: added zai-mcp-server" -ForegroundColor Green
        }
        else {
            Write-Warning "claudez: failed to add zai-mcp-server"
        }
    }

    # Write a sentinel flag with metadata so future runs can detect and skip re-setup
    $flagInfo = @(
        "configuredAt=$(Get-Date -Format o)",
        "user=$env:USERNAME",
        'mode=ZAI'
    ) -join "`r`n"
    Set-Content -LiteralPath $setupFlag -Value $flagInfo -Encoding UTF8
    Write-Host 'claudez: MCP setup complete' -ForegroundColor Green
    return $true
}

function Save-ProcessEnvVars {
    <#
.SYNOPSIS
    Snapshot process-scope environment variables so they can be restored later.

.DESCRIPTION
    Returns an ordered hashtable mapping each name to its current process-scope
    value (or $null when unset). Pass the result to Restore-ProcessEnvVars in a
    finally block to undo any temporary overrides cleanly.

.PARAMETER Names
    The environment variable names to capture.
#>
    param([Parameter(Mandatory)][string[]]$Names)

    $saved = [ordered]@{}
    foreach ($n in $Names) {
        $saved[$n] = [Environment]::GetEnvironmentVariable($n, 'Process')
    }
    return $saved
}

function Restore-ProcessEnvVars {
    <#
.SYNOPSIS
    Restore environment variables captured by Save-ProcessEnvVars.

.DESCRIPTION
    Re-applies each saved value, or removes the variable entirely when it was
    unset at snapshot time, leaving the process environment as it was found.

.PARAMETER Saved
    The hashtable produced by Save-ProcessEnvVars.
#>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Saved)

    foreach ($n in $Saved.Keys) {
        if ($null -eq $Saved[$n]) {
            Remove-Item "Env:\$n" -ErrorAction SilentlyContinue
        } else {
            [Environment]::SetEnvironmentVariable($n, $Saved[$n], 'Process')
        }
    }
}

function claudez {
    <#
.SYNOPSIS
    Launches Claude Code through the Z.AI-backed profile helper.

.DESCRIPTION
    Reads the Z.AI API key from the Z_AI_AUTH_TOKEN environment variable
    (current session first, then User scope), runs one-time claudez setup,
    configures runtime environment, then invokes claude with the supplied arguments.
    If Z_AI_AUTH_TOKEN is not set, the function aborts and prints setup guidance.
    about supported models:
        "All plans support GLM-5.2, GLM-5-Turbo, GLM-4.7 and GLM-4.5-Air." (https://docs.z.ai/devpack/overview)
        See https://docs.z.ai/devpack/latest-model for the current lineup.
    about 1M context:
        GLM-5.2 supports a 1M context window (request via the [1m] suffix on the model name, e.g. glm-5.2[1m]).
        Z.AI also requires CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000 to actually exercise the 1M window
        (this profile sets it for you). Other GLM models cap at 200K (GLM-5, GLM-5-Turbo) or 128K (GLM-4.5-Air).

.EXAMPLE
    claudez

.EXAMPLE
    claudez "Explain the current repository"

.EXAMPLE
    [Environment]::SetEnvironmentVariable('Z_AI_AUTH_TOKEN', '<your_token>', 'User')
    # Restart PowerShell, then run:
    claudez

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    # Read token using Get-AiApiKey helper (process first, then Credential Manager, then legacy User env)
    $token = Get-AiApiKey 'Z_AI_AUTH_TOKEN'

    if (-not $token) {
        Write-Host "Z_AI_AUTH_TOKEN is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'API_TIMEOUT_MS',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'CLAUDE_CODE_AUTO_COMPACT_WINDOW',
        'CLAUDE_CODE_USE_POWERSHELL_TOOL', 'ANTHROPIC_DEFAULT_HAIKU_MODEL',
        'ANTHROPIC_DEFAULT_SONNET_MODEL', 'ANTHROPIC_DEFAULT_OPUS_MODEL',
        'CLAUDE_CODE_SUBAGENT_MODEL', 'CLAUDE_CODE_EFFORT_LEVEL'
    )

    $env:ANTHROPIC_BASE_URL = "https://api.z.ai/api/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $token
    $env:API_TIMEOUT_MS = "3000000"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    # GLM-5.2 supports 1M context (suffix [1m] on the model name); see https://docs.z.ai/devpack/latest-model
    $env:CLAUDE_CODE_AUTO_COMPACT_WINDOW = "1000000"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    # Map Anthropic model slots to Z.AI equivalents; remove once Claude Code auto-detects these
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "glm-4.5-air"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "glm-4.7"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "glm-5.2[1m]"

    $env:CLAUDE_CODE_SUBAGENT_MODEL = "glm-4.7"
    $env:CLAUDE_CODE_EFFORT_LEVEL = "high"

    try {
        Install-GlobalClaudeMd
        Install-GlobalClaudeSettings
        [void](Install-ClaudezSetup -Token $token)

        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudezm {
    <#
.SYNOPSIS
    Launches Claude Code with Z.AI settings and GLM model overrides. (Max plan compatibility mode)

.DESCRIPTION
    Performs the same setup as claudez, then temporarily sets the default Anthropic model variables
    to GLM-backed values before invoking claude.

.EXAMPLE
    claudezm

.EXAMPLE
    claudezm "Summarize the changed files"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    # Read token using Get-AiApiKey helper (process first, then Credential Manager, then legacy User env)
    $token = Get-AiApiKey 'Z_AI_AUTH_TOKEN'

    if (-not $token) {
        Write-Host "Z_AI_AUTH_TOKEN is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'API_TIMEOUT_MS',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'CLAUDE_CODE_AUTO_COMPACT_WINDOW',
        'CLAUDE_CODE_USE_POWERSHELL_TOOL', 'ANTHROPIC_DEFAULT_HAIKU_MODEL',
        'ANTHROPIC_DEFAULT_SONNET_MODEL', 'ANTHROPIC_DEFAULT_OPUS_MODEL',
        'CLAUDE_CODE_SUBAGENT_MODEL', 'CLAUDE_CODE_EFFORT_LEVEL'
    )

    $env:ANTHROPIC_BASE_URL = "https://api.z.ai/api/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $token
    $env:API_TIMEOUT_MS = "3000000"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    # GLM-5.2 supports 1M context (suffix [1m] on the model name); see https://docs.z.ai/devpack/latest-model
    $env:CLAUDE_CODE_AUTO_COMPACT_WINDOW = "1000000"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    # Max plan compatibility mode uses different default model routing.
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "glm-4.5-air"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "glm-5.2[1m]"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "glm-5.2[1m]"

    $env:CLAUDE_CODE_SUBAGENT_MODEL = "glm-5.2[1m]"
    $env:CLAUDE_CODE_EFFORT_LEVEL = "max"

    try {
        Install-GlobalClaudeMd
        Install-GlobalClaudeSettings
        [void](Install-ClaudezSetup -Token $token)

        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudezd {
    <#
.SYNOPSIS
    Launches claudez with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudez and appends --dangerously-skip-permissions.

.EXAMPLE
    claudezd

.EXAMPLE
    claudezd "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-04
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudez @claudeArgs
}

function claudezmd {
    <#
.SYNOPSIS
    Launches claudezm with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudezm and appends --dangerously-skip-permissions.

.EXAMPLE
    claudezmd

.EXAMPLE
    claudezmd "Summarize the changed files"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-04
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudezm @claudeArgs
}

function claudeds {
    <#
.SYNOPSIS
    Launches Claude Code through the DeepSeek endpoint.

.DESCRIPTION
    Reads the DeepSeek API key from the DEEPSEEK_API_KEY environment variable
    (current session first, then User scope), configures runtime environment,
    then invokes claude with the supplied arguments.
    If DEEPSEEK_API_KEY is not set, the function aborts and prints setup guidance.

.EXAMPLE
    claudeds

.EXAMPLE
    claudeds "Explain the current repository"

.EXAMPLE
    [Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', '<your_key>', 'User')
    # Restart PowerShell, then run:
    claudeds

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    # Read key using Get-AiApiKey helper (process first, then Credential Manager, then legacy User env)
    $key = Get-AiApiKey 'DEEPSEEK_API_KEY'

    if (-not $key) {
        Write-Host "DEEPSEEK_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_MODEL',
        'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL',
        'ANTHROPIC_DEFAULT_OPUS_MODEL', 'CLAUDE_CODE_SUBAGENT_MODEL',
        'CLAUDE_CODE_EFFORT_LEVEL', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC',
        'CLAUDE_CODE_USE_POWERSHELL_TOOL'
    )

    $env:ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $key
    # [1m] suffix requests 1M context window from DeepSeek's Anthropic-compatible endpoint
    $env:ANTHROPIC_MODEL = "deepseek-v4-pro[1m]"
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "deepseek-v4-flash[1m]"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "deepseek-v4-pro[1m]"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "deepseek-v4-pro[1m]"
    # Use flash for subagents -- they handle tool routing, not heavy reasoning
    $env:CLAUDE_CODE_SUBAGENT_MODEL = "deepseek-v4-flash[1m]"
    $env:CLAUDE_CODE_EFFORT_LEVEL = "max"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    try {
        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudedsd {
    <#
.SYNOPSIS
    Launches claudeds with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudeds and appends --dangerously-skip-permissions.

.EXAMPLE
    claudedsd

.EXAMPLE
    claudedsd "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudeds @claudeArgs
}

function claudeds2 {
    <#
.SYNOPSIS
    Launches Claude Code through the cheaper DeepSeek endpoint profile.

.DESCRIPTION
    Reads the DeepSeek API key from the DEEPSEEK_API_KEY environment variable
    (current session first, then User scope), configures a cheaper routing profile
    where Sonnet uses the flash model and only Opus uses the pro model, then
    invokes claude with the supplied arguments.
    If DEEPSEEK_API_KEY is not set, the function aborts and prints setup guidance.

.EXAMPLE
    claudeds2

.EXAMPLE
    claudeds2 "Explain the current repository"

.EXAMPLE
    [Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', '<your_key>', 'User')
    # Restart PowerShell, then run:
    claudeds2

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    # Read key using Get-AiApiKey helper (process first, then Credential Manager, then legacy User env)
    $key = Get-AiApiKey 'DEEPSEEK_API_KEY'

    if (-not $key) {
        Write-Host "DEEPSEEK_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_MODEL',
        'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL',
        'ANTHROPIC_DEFAULT_OPUS_MODEL', 'CLAUDE_CODE_SUBAGENT_MODEL',
        'CLAUDE_CODE_EFFORT_LEVEL', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC',
        'CLAUDE_CODE_USE_POWERSHELL_TOOL'
    )

    $env:ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $key
    # Cheaper profile: Sonnet routes to flash (fast/cheap), only Opus uses pro (expensive/capable)
    $env:ANTHROPIC_MODEL = "deepseek-v4-flash[1m]"
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "deepseek-v4-flash[1m]"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "deepseek-v4-flash[1m]"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "deepseek-v4-pro[1m]"
    $env:CLAUDE_CODE_SUBAGENT_MODEL = "deepseek-v4-flash[1m]"
    $env:CLAUDE_CODE_EFFORT_LEVEL = "high"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    try {
        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudeds2d {
    <#
.SYNOPSIS
    Launches claudeds2 with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudeds2 and appends --dangerously-skip-permissions.

.EXAMPLE
    claudeds2d

.EXAMPLE
    claudeds2d "Summarize the changed files"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudeds2 @claudeArgs
}


function Invoke-RemoteClaudeCodeBase {
    <#
.SYNOPSIS
Runs Claude Code on a remote SSH endpoint with temporary remote state.

.DESCRIPTION
Base64-encodes a bash launcher and delivers it via the SSH command argument,
keeping stdin free for the interactive Claude Code TUI. Sets the Anthropic
environment variables inline and starts claude on the remote host with a
temporary HOME, npm prefix, and workspace.
Use this when you want a one-shot remote Claude session without leaving
permanent state behind.

.PARAMETER RemoteHost
SSH target in user@host form.

.PARAMETER ApiKey
Anthropic-compatible API key for the remote session.

.PARAMETER Port
SSH port to connect to. Defaults to 22.

.PARAMETER KeyFile
Path to an SSH private key file. When specified, ssh uses this key
exclusively (-i). Otherwise SSH falls back to the default agent/key or
password prompt.

.PARAMETER BaseUrl
Anthropic-compatible API base URL. Optional - omit for direct Anthropic API access.
Only needed when routing through a proxy or alternative endpoint.

.PARAMETER HaikuModel
Default Haiku model name.

.PARAMETER SonnetModel
Default Sonnet model name.

.PARAMETER OpusModel
Default Opus model name.

.PARAMETER TimeoutMs
API timeout in milliseconds.

.PARAMETER Disable1M
Sets CLAUDE_CODE_DISABLE_1M_CONTEXT on the remote host.

.PARAMETER SubagentModel
Optional subagent model name (CLAUDE_CODE_SUBAGENT_MODEL). Default: empty.
Pass the same value the local claudez/claudezm profile uses so remote subagent
routing matches the local one.

.PARAMETER EffortLevel
Optional effort level (CLAUDE_CODE_EFFORT_LEVEL), e.g. "high" or "max".
Default: empty.

.PARAMETER AutoCompactWindow
Optional 1M-context auto-compact window (CLAUDE_CODE_AUTO_COMPACT_WINDOW).
Z.AI's glm-5.2[1m] requires "1000000" to actually exercise the 1M context window.
Default: empty.

.EXAMPLE
Invoke-RemoteClaudeCodeBase -RemoteHost user@remote-host -ApiKey $env:ANTHROPIC_API_KEY

.EXAMPLE
Invoke-RemoteClaudeCodeBase -RemoteHost user@remote-host -ApiKey $env:Z_AI_AUTH_TOKEN -BaseUrl "https://api.z.ai/api/anthropic"

.EXAMPLE
# Match local claudezm routing for Z.AI:
Invoke-RemoteClaudeCodeBase -RemoteHost user@remote-host -ApiKey $env:Z_AI_AUTH_TOKEN `
    -BaseUrl "https://api.z.ai/api/anthropic" `
    -HaikuModel "glm-4.5-air" -SonnetModel "glm-5.2[1m]" -OpusModel "glm-5.2[1m]" `
    -SubagentModel "glm-5.2[1m]" -EffortLevel "max" -AutoCompactWindow "1000000" `
    -Disable1M "0"

.NOTES
Author: jjw(@thejjw)
Last Edit: 2026-06
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteHost,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [int]$Port = 22,

        # Optional: SSH private key file for authentication.
        [string]$KeyFile,

        # Optional: only needed for proxy/alternative endpoints.
        # Leave empty to use the default Anthropic API (api.anthropic.com).
        [string]$BaseUrl = "",

        [Parameter(Mandatory = $true)]
        [string]$HaikuModel,

        [Parameter(Mandatory = $true)]
        [string]$SonnetModel,

        [Parameter(Mandatory = $true)]
        [string]$OpusModel,

        [Parameter(Mandatory = $true)]
        [string]$TimeoutMs,

        [Parameter(Mandatory = $true)]
        [string]$Disable1M,

        # Optional: subagent model (CLAUDE_CODE_SUBAGENT_MODEL). Empty leaves it unset on the remote.
        [string]$SubagentModel = "",

        # Optional: effort level (CLAUDE_CODE_EFFORT_LEVEL). Empty leaves it unset.
        [string]$EffortLevel = "",

        # Optional: 1M-context auto-compact window (CLAUDE_CODE_AUTO_COMPACT_WINDOW).
        # Z.AI's glm-5.2[1m] requires "1000000" to actually exercise 1M context.
        [string]$AutoCompactWindow = ""
    )

    # Bash single-quote escaping: end quote, insert a literal quote, reopen quote
    # (Bash has no backslash escape inside single quotes, so this is the only way)
    # Bash has no backslash escape inside single quotes; the only way to embed a
    # literal quote is to end the quote, add an escaped quote, and reopen: 'foo'\''bar'
    function Escape-BashSingleQuotedValue {
        param([string]$Value)
        if ($null -eq $Value) { return "''" }
        return "'" + ($Value -replace "'", "'`"'`"'") + "'"
    }

    if ([string]::IsNullOrWhiteSpace($RemoteHost)) {
        throw 'RemoteHost is required.'
    }

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        throw 'ApiKey is required.'
    }

    $script = @'
CC_TMP="$(mktemp -d /tmp/cc-XXXXXX)"
trap 'echo "[cleanup] Wiping $CC_TMP ..."; rm -rf "$CC_TMP"' EXIT
CC_NPM="$CC_TMP/npm"; CC_HOME="$CC_TMP/home"; CC_WORK="$CC_TMP/workspace"
mkdir -p "$CC_NPM" "$CC_HOME" "$CC_WORK"
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:?not set}"
# ANTHROPIC_BASE_URL is optional - only exported when the caller provided a value
[ -n "${ANTHROPIC_BASE_URL:-}" ] && export ANTHROPIC_BASE_URL="$ANTHROPIC_BASE_URL"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="${ANTHROPIC_DEFAULT_HAIKU_MODEL:-}"
export ANTHROPIC_DEFAULT_SONNET_MODEL="${ANTHROPIC_DEFAULT_SONNET_MODEL:-}"
export ANTHROPIC_DEFAULT_OPUS_MODEL="${ANTHROPIC_DEFAULT_OPUS_MODEL:-}"
export CLAUDE_CODE_SUBAGENT_MODEL="${CLAUDE_CODE_SUBAGENT_MODEL:-}"
export CLAUDE_CODE_EFFORT_LEVEL="${CLAUDE_CODE_EFFORT_LEVEL:-}"
export CLAUDE_CODE_AUTO_COMPACT_WINDOW="${CLAUDE_CODE_AUTO_COMPACT_WINDOW:-}"
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
'@

    # Base64-encode the script so it travels as an SSH command argument, not stdin.
    # Claude Code's interactive TUI needs stdin; piping via 'bash -s' would steal it.
    $encoded = [Convert]::ToBase64String(
        [System.Text.Encoding]::UTF8.GetBytes($script)
    )

    # Prepend environment variables as SSH command arguments.
    # BaseUrl is conditionally included to avoid sending an empty value that
    # would override the remote's default (Anthropic direct) endpoint.
    $envParts = [System.Collections.Generic.List[string]]@(
        "ANTHROPIC_API_KEY=$(Escape-BashSingleQuotedValue $ApiKey)"
        "ANTHROPIC_DEFAULT_HAIKU_MODEL=$(Escape-BashSingleQuotedValue $HaikuModel)"
        "ANTHROPIC_DEFAULT_SONNET_MODEL=$(Escape-BashSingleQuotedValue $SonnetModel)"
        "ANTHROPIC_DEFAULT_OPUS_MODEL=$(Escape-BashSingleQuotedValue $OpusModel)"
        "CLAUDE_CODE_SUBAGENT_MODEL=$(Escape-BashSingleQuotedValue $SubagentModel)"
        "CLAUDE_CODE_EFFORT_LEVEL=$(Escape-BashSingleQuotedValue $EffortLevel)"
        "CLAUDE_CODE_AUTO_COMPACT_WINDOW=$(Escape-BashSingleQuotedValue $AutoCompactWindow)"
        "API_TIMEOUT_MS=$(Escape-BashSingleQuotedValue $TimeoutMs)"
        "CLAUDE_CODE_DISABLE_1M_CONTEXT=$(Escape-BashSingleQuotedValue $Disable1M)"
    )
    if (-not [string]::IsNullOrWhiteSpace($BaseUrl)) {
        $envParts.Insert(1, "ANTHROPIC_BASE_URL=$(Escape-BashSingleQuotedValue $BaseUrl)")
    }
    $envPrefix = $envParts -join ' '

    # -t: pseudo-TTY required for Claude Code's TUI rendering
    # StrictHostKeyChecking=accept-new: trusts first-seen host keys but
    #   still rejects changed keys (protects against MITM on reconnects)
    # The base64 payload is decoded and executed with stdin still available to claude
    # Build ssh arguments; add -i only when a key file is explicitly provided
    $sshArgs = @('-t', '-o', 'StrictHostKeyChecking=accept-new', '-p', $Port)
    if (-not [string]::IsNullOrWhiteSpace($KeyFile)) {
        # Resolve to absolute path before passing to ssh on Windows (PS cwd may differ from ssh's)
        $resolved = (Resolve-Path -LiteralPath $KeyFile -ErrorAction Stop).Path
        $sshArgs += @('-i', $resolved)
    }
    $sshArgs += $RemoteHost
    # The encoded script is echoed into base64 for decoding; echo avoids stdin consumption
    $sshArgs += "$envPrefix bash -c 'echo $encoded | base64 -d | bash'"
    ssh @sshArgs
}

function Invoke-RemoteClaudeCodeZ {
    <#
.SYNOPSIS
Runs Claude Code on a remote SSH endpoint with temporary remote state.

.DESCRIPTION
Prompts for the API key from Z_AI_AUTH_TOKEN if it is not provided, then runs
the remote Claude launcher with the remote defaults defined inside
Invoke-RemoteClaudeCodeBase. The remote Claude invocation always uses
--dangerously-skip-permissions.

.PARAMETER RemoteHost
SSH target in user@host form.

.PARAMETER ApiKey
Anthropic-compatible API key for the remote session.
Optional - falls back to Z_AI_AUTH_TOKEN env var.

.PARAMETER Port
SSH port to connect to. Defaults to 22.

.EXAMPLE
Invoke-RemoteClaudeCodeZ -RemoteHost user@remote-host

.EXAMPLE
Invoke-RemoteClaudeCodeZ -RemoteHost user@remote-host -ApiKey $env:Z_AI_AUTH_TOKEN

.NOTES
Author: jjw(@thejjw)
Last Edit: 2026-06
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteHost,

        [string]$ApiKey,

        [int]$Port = 22,

        # Optional: SSH private key file for authentication.
        [string]$KeyFile
    )

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        $ApiKey = Get-AiApiKey 'Z_AI_AUTH_TOKEN'
    }

    if (-not $ApiKey) {
        Write-Host "Z_AI_AUTH_TOKEN is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    # Keep the editable remote defaults here so they are easy to tweak later.
    # Matches the local claudezm profile: glm-5.2[1m] for Sonnet/Opus/Subagent,
    # effort=max, 1M context enabled via CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000.
    $BaseUrl = "https://api.z.ai/api/anthropic"
    $HaikuModel = "glm-4.5-air"
    $SonnetModel = "glm-5.2[1m]"
    $OpusModel = "glm-5.2[1m]"
    $SubagentModel = "glm-5.2[1m]"
    $EffortLevel = "max"
    $AutoCompactWindow = "1000000"
    $TimeoutMs = "3000000"
    $Disable1M = "0"

    $baseParams = @{
        RemoteHost        = $RemoteHost
        ApiKey            = $ApiKey
        Port              = $Port
        BaseUrl           = $BaseUrl
        HaikuModel        = $HaikuModel
        SonnetModel       = $SonnetModel
        OpusModel         = $OpusModel
        SubagentModel     = $SubagentModel
        EffortLevel       = $EffortLevel
        AutoCompactWindow = $AutoCompactWindow
        TimeoutMs         = $TimeoutMs
        Disable1M         = $Disable1M
    }
    if (-not [string]::IsNullOrWhiteSpace($KeyFile)) { $baseParams['KeyFile'] = $KeyFile }
    Invoke-RemoteClaudeCodeBase @baseParams
}

function Install-ClaudemmSetup {
    <#
.SYNOPSIS
    Configures MiniMax MCP server for Claude Code.

.DESCRIPTION
    Adds the minimax-coding-plan-mcp server via Claude CLI if not already present.
    Requires 'uv' (uvx) to be installed. Uses a flag file under ~/.claude to skip
    duplicate setup runs unless -Force is specified.

.PARAMETER Token
    MiniMax API key used for MCP server configuration.

.PARAMETER Force
    Re-runs MCP setup even if the setup flag already exists.

.EXAMPLE
    Install-ClaudemmSetup -Token "<api_key>"

.EXAMPLE
    Install-ClaudemmSetup -Token "<api_key>" -Force

.NOTES
    Requires 'uv' to be installed (uvx is used to run minimax-coding-plan-mcp).
    Install uv: winget install astral-sh.uv

    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [switch]$Force
    )

    $claudeDir = Join-Path $HOME '.claude'
    $setupFlag = Join-Path $claudeDir '.claudemm_setup_complete'

    if (-not (Test-Path -LiteralPath $claudeDir)) {
        $null = New-Item -ItemType Directory -Path $claudeDir -Force
    }

    $claudeCmd = Get-Command claude -ErrorAction SilentlyContinue
    if ($null -eq $claudeCmd) {
        Write-Host 'WARNING: claude CLI not found, skipping MCP server configuration' -ForegroundColor Yellow
        return $false
    }

    if ((Test-Path -LiteralPath $setupFlag) -and -not $Force) {
        Write-Host "claudemm: MCP setup already completed (flag: $setupFlag) -- skipping"
        Write-Host 'claudemm: use Install-ClaudemmSetup -Force to reconfigure' -ForegroundColor DarkGray
        return $true
    }

    # Check for uv (required by uvx for minimax-coding-plan-mcp)
    $uvCmd = Get-Command uv -ErrorAction SilentlyContinue
    if ($null -eq $uvCmd) {
        Write-Host "claudemm: WARNING: 'uv' not found -- skipping MiniMax MCP server" -ForegroundColor Yellow
        Write-Host "  Install uv:  winget install astral-sh.uv" -ForegroundColor Cyan
        return $false
    }

    Write-Host "claudemm: configuring MCP servers..." -ForegroundColor Cyan

    # MiniMax coding-plan-mcp
    if (& claude mcp list | Select-String -Pattern 'minimax' -Quiet) {
        Write-Host "claudemm: MiniMax MCP server already exists -- skipping" -ForegroundColor DarkGray
    }
    else {
        & claude mcp add -s user MiniMax --env MINIMAX_API_KEY="$Token" --env MINIMAX_API_HOST=https://api.minimax.io -- uvx minimax-coding-plan-mcp -y 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "claudemm: added MiniMax MCP server" -ForegroundColor Green
        }
        else {
            Write-Warning "claudemm: failed to add MiniMax MCP server"
        }
    }

    $flagInfo = @(
        "configuredAt=$(Get-Date -Format o)",
        "user=$env:USERNAME",
        'mode=MiniMax'
    ) -join "`r`n"
    Set-Content -LiteralPath $setupFlag -Value $flagInfo -Encoding UTF8
    Write-Host 'claudemm: MCP setup complete' -ForegroundColor Green
    return $true
}

function claudemm {
    <#
.SYNOPSIS
    Launches Claude Code through the MiniMax endpoint.

.DESCRIPTION
    Reads the MiniMax API key from the MINIMAX_API_KEY environment variable
    (current session first, then User scope), runs one-time claudemm MCP setup,
    configures runtime environment, then invokes claude with the supplied arguments.
    If MINIMAX_API_KEY is not set, the function aborts and prints setup guidance.

.EXAMPLE
    claudemm

.EXAMPLE
    claudemm "Explain the current repository"

.EXAMPLE
    [Environment]::SetEnvironmentVariable('MINIMAX_API_KEY', '<your_key>', 'User')
    # Restart PowerShell, then run:
    claudemm

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    # Read key using Get-AiApiKey helper (process first, then Credential Manager, then legacy User env)
    $key = Get-AiApiKey 'MINIMAX_API_KEY'

    if (-not $key) {
        Write-Host "MINIMAX_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_MODEL',
        'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL',
        'ANTHROPIC_DEFAULT_OPUS_MODEL', 'API_TIMEOUT_MS',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'CLAUDE_CODE_USE_POWERSHELL_TOOL',
        'CLAUDE_CODE_SUBAGENT_MODEL', 'CLAUDE_CODE_EFFORT_LEVEL'
    )

    $env:ANTHROPIC_BASE_URL = "https://api.minimax.io/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $key
    # MiniMax offers a single model (M3[1m]), so all Anthropic model slots route to it
    $env:ANTHROPIC_MODEL = "MiniMax-M3[1m]"
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "MiniMax-M3[1m]"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "MiniMax-M3[1m]"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "MiniMax-M3[1m]"
    $env:API_TIMEOUT_MS = "3000000"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    $env:CLAUDE_CODE_SUBAGENT_MODEL = "MiniMax-M3[1m]"
    $env:CLAUDE_CODE_EFFORT_LEVEL = "max"

    try {
        Install-GlobalClaudeMd
        Install-GlobalClaudeSettings
        [void](Install-ClaudemmSetup -Token $key)

        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudemmd {
    <#
.SYNOPSIS
    Launches claudemm with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudemm and appends --dangerously-skip-permissions.

.EXAMPLE
    claudemmd

.EXAMPLE
    claudemmd "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudemm @claudeArgs
}

function Install-ClaudeCCRSetup {
    <#
.SYNOPSIS
    Configures Claude Code Router for the local multi-provider Claude Code profile.

.DESCRIPTION
    Creates ~/.claude-code-router/config.json (or rewrites it with -Force) wiring Z.AI, MiniMax,
    DeepSeek, and Gemini as providers, and routing default/background/think/longContext/image
    roles to the user's preferred GLM model tiers. webSearch routes to Gemini Flash for Google
    search grounding. API keys are stored as $ENV references in the config; the launcher
    exposes the resolved values from the Credential Manager just-in-time.

    This setup also runs the shared Claude Code global setup and the existing Z.AI/MiniMax MCP
    setup helpers so cccr can use the same MCP servers as claudez and claudemm.

.PARAMETER ZaiToken
    Z.AI token. Defaults to Get-AiApiKey 'Z_AI_AUTH_TOKEN'.

.PARAMETER MiniMaxKey
    MiniMax API key. Defaults to Get-AiApiKey 'MINIMAX_API_KEY'. Optional; if missing, MiniMax
    is omitted from Providers and the longContext route falls back to DeepSeek.

.PARAMETER DeepSeekKey
    DeepSeek API key. Defaults to Get-AiApiKey 'DEEPSEEK_API_KEY'. Optional; required only if
    longContext would otherwise have no fallback provider.

.PARAMETER GeminiKey
    Google Gemini API key. Defaults to Get-AiApiKey 'GEMINI_API_KEY'. Optional; if missing, the
    Gemini provider is omitted (and the webSearch router role becomes a no-op).

.PARAMETER Force
    Rewrites config.json and re-runs nested setup helpers even when sentinel files exist.

.EXAMPLE
    Install-ClaudeCCRSetup

.EXAMPLE
    Install-ClaudeCCRSetup -Force

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    [CmdletBinding()]
    param(
        [string]$ZaiToken,
        [string]$MiniMaxKey,
        [string]$DeepSeekKey,
        [string]$GeminiKey,
        [switch]$Force
    )

    if ([string]::IsNullOrWhiteSpace($ZaiToken))    { $ZaiToken    = Get-AiApiKey 'Z_AI_AUTH_TOKEN' }
    if ([string]::IsNullOrWhiteSpace($MiniMaxKey))  { $MiniMaxKey  = Get-AiApiKey 'MINIMAX_API_KEY' }
    if ([string]::IsNullOrWhiteSpace($DeepSeekKey)) { $DeepSeekKey = Get-AiApiKey 'DEEPSEEK_API_KEY' }
    if ([string]::IsNullOrWhiteSpace($GeminiKey))   { $GeminiKey   = Get-AiApiKey 'GEMINI_API_KEY' }

    if (-not $GeminiKey) {
        Write-Host "cccr: GEMINI_API_KEY not set -- Gemini provider and webSearch route skipped" -ForegroundColor Yellow
    }

    if (-not $ZaiToken) {
        Write-Host "Z_AI_AUTH_TOKEN is not set. Aborting CCR setup." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return $false
    }

    $ccrDir     = Join-Path $HOME '.claude-code-router'
    $configJson = Join-Path $ccrDir 'config.json'
    $setupFlag  = Join-Path $ccrDir '.cccr_setup_complete'

    if (-not (Test-Path -LiteralPath $ccrDir)) {
        $null = New-Item -ItemType Directory -Path $ccrDir -Force
    }

    # Run shared Claude Code global setup + the existing provider MCP setup helpers so cccr
    # has the same ~/.claude/CLAUDE.md, settings.json, and MCP servers as claudez/claudemm.
    Install-GlobalClaudeMd
    Install-GlobalClaudeSettings
    [void](Install-ClaudezSetup -Token $ZaiToken -Force:$Force)

    if ($MiniMaxKey) {
        [void](Install-ClaudemmSetup -Token $MiniMaxKey -Force:$Force)
    }
    else {
        Write-Host "cccr: MINIMAX_API_KEY not set -- MiniMax MCP setup skipped" -ForegroundColor Yellow
    }

    # Skip config rewrite when both the sentinel and config.json exist and -Force was not passed.
    $alreadyConfigured = (Test-Path -LiteralPath $setupFlag) -and (Test-Path -LiteralPath $configJson) -and -not $Force
    if ($alreadyConfigured) {
        Write-Host "cccr: CCR config setup already done -- skipping"
        return $true
    }

    # Pick the long-context provider. MiniMax is preferred (1M context); otherwise DeepSeek.
    # The model slot is derived from the provider's first model in $_CcrInternal so editing the model
    # list above is enough -- no second place to update.
    $longContextRoute = $null
    if ($MiniMaxKey) {
        $longContextRoute = '{0},{1}' -f 'minimax', $_CcrInternal.Providers.minimax.models[0]
    }
    elseif ($DeepSeekKey) {
        $proModel = $_CcrInternal.Providers.deepseek.models | Where-Object { $_ -like '*pro*' } | Select-Object -First 1
        if (-not $proModel) { $proModel = $_CcrInternal.Providers.deepseek.models[0] }
        $longContextRoute = '{0},{1}' -f 'deepseek', $proModel
    }
    else {
        Write-Host "cccr: no MiniMax or DeepSeek key -- longContext will fall through to default" -ForegroundColor Yellow
    }

    # Always (re)write the config when sentinel is missing or -Force was passed, OR when the
    # user has never had a config.json. If a stale config.json exists without a sentinel we
    # still rewrite it so the env-var interpolation stays in sync with current credentials.
    $shouldWriteConfig = $Force -or -not (Test-Path -LiteralPath $setupFlag)
    if ((Test-Path -LiteralPath $configJson) -and -not $shouldWriteConfig) {
        Write-Host "cccr: existing config.json found -- leaving it unchanged" -ForegroundColor Yellow
        Write-Host "cccr: use Install-ClaudeCCRSetup -Force to rewrite it" -ForegroundColor DarkGray
    }

    if ($shouldWriteConfig) {
        if (Test-Path -LiteralPath $configJson) {
            # Bump existing config out of the way so a broken rewrite is recoverable.
            $backupPath = "$configJson.$(Get-Date -Format 'yyyyMMddHHmmss').bak"
            Copy-Item -LiteralPath $configJson -Destination $backupPath -Force
            Write-Host "cccr: backed up existing config to $backupPath" -ForegroundColor DarkGray
        }

        $router = [ordered]@{
            default              = $_CcrInternal.Router.default
            background           = $_CcrInternal.Router.background
            think                = $_CcrInternal.Router.think
            longContextThreshold = $_CcrInternal.Threshold
        }
        if ($longContextRoute)  { $router['longContext'] = $longContextRoute }
        if ($MiniMaxKey)        { $router['image']       = '{0},{1}' -f 'minimax', $_CcrInternal.Providers.minimax.models[0] }
        if ($GeminiKey)         { $router['webSearch']   = $_CcrInternal.Router.webSearch }

        # Provider order in the generated config. Each entry is included only when the matching
        # API key is available; zai is always present since the launcher requires it.
        $providers = foreach ($pName in @('zai', 'minimax', 'deepseek', 'gemini')) {
            $hasKey = switch ($pName) {
                'zai'     { $true }
                'minimax' { [bool]$MiniMaxKey }
                'deepseek'{ [bool]$DeepSeekKey }
                'gemini'  { [bool]$GeminiKey }
            }
            if (-not $hasKey) { continue }
            $p = $_CcrInternal.Providers[$pName]
            [ordered]@{
                name         = $pName
                # Anthropic transformer passes through, so use the FULL endpoint URL (incl.
                # /v1/messages). The base URL used by claudez intentionally omits the suffix
                # because Claude Code's Anthropic client appends it for you.
                api_base_url = $p.base
                api_key      = $p.key
                models       = $p.models
                transformer  = [ordered]@{ use = @($p.transformer) }
            }
        }

        $config = [ordered]@{
            PORT           = $_CcrInternal.Port
            HOST           = $_CcrInternal.Host
            LOG            = $_CcrInternal.Log
            API_TIMEOUT_MS = $_CcrInternal.Timeout
            Providers      = $providers
            Router         = $router
        }

        # No-BOM UTF-8 so the file is valid JSON and CCR's JSON5 reader stays happy.
        $json = $config | ConvertTo-Json -Depth 20
        [IO.File]::WriteAllText($configJson, $json, [Text.UTF8Encoding]::new($false))
        Write-Host "cccr: wrote CCR config to $configJson" -ForegroundColor Green
    }

    $flagInfo = @(
        "configuredAt=$(Get-Date -Format o)"
        "user=$env:USERNAME"
        "configJson=$configJson"
        'mode=CCR'
        "default=$($_CcrInternal.Router.default)"
        "background=$($_CcrInternal.Router.background)"
        "think=$($_CcrInternal.Router.think)"
        "webSearch=$(if ($GeminiKey) { $_CcrInternal.Router.webSearch } else { '<unset>' })"
        "longContext=$(if ($longContextRoute) { $longContextRoute } else { '<unset>' })"
    ) -join "`r`n"
    Set-Content -LiteralPath $setupFlag -Value $flagInfo -Encoding UTF8
    Write-Host 'cccr: CCR setup complete' -ForegroundColor Green
    return $true
}

function cccr {
    <#
.SYNOPSIS
    Launches Claude Code through Claude Code Router (CCR).

.DESCRIPTION
    Ensures the local CCR config/MCP setup exists, exposes provider API keys to the current
    process so CCR's $VAR interpolation resolves them, starts/restarts the local CCR service,
    points Claude Code at http://127.0.0.1:3456, then invokes claude with the supplied arguments.

    Pass -Force or --force-ccr-setup to rewrite the CCR config and re-run nested setup helpers.

.EXAMPLE
    cccr

.EXAMPLE
    cccr "Explain the current repository"

.EXAMPLE
    cccr -Force

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    # Strip the CCR-only force flag from the forwarded claude args so /model etc. still work.
    $forceSetup   = $false
    $claudeArgArr = @()
    foreach ($arg in $args) {
        if ($arg -in @('-Force', '--force-ccr-setup')) { $forceSetup = $true }
        else                                           { $claudeArgArr += $arg }
    }

    $zaiToken    = Get-AiApiKey 'Z_AI_AUTH_TOKEN'
    if (-not $zaiToken) {
        Write-Host "Z_AI_AUTH_TOKEN is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }
    $miniMaxKey  = Get-AiApiKey 'MINIMAX_API_KEY'
    $deepSeekKey = Get-AiApiKey 'DEEPSEEK_API_KEY'
    $geminiKey   = Get-AiApiKey 'GEMINI_API_KEY'

    # Snapshot every env var we may transiently mutate so the caller's session is untouched
    # once claude exits (or this function returns early).
    $originalEnvVars = Save-ProcessEnvVars @(
        'Z_AI_AUTH_TOKEN', 'MINIMAX_API_KEY', 'DEEPSEEK_API_KEY', 'GEMINI_API_KEY',
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY',
        'ANTHROPIC_MODEL', 'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL',
        'ANTHROPIC_DEFAULT_OPUS_MODEL', 'API_TIMEOUT_MS', 'NO_PROXY',
        'DISABLE_TELEMETRY', 'DISABLE_COST_WARNINGS',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'CLAUDE_CODE_DISABLE_1M_CONTEXT',
        'CLAUDE_CODE_USE_POWERSHELL_TOOL',
        'CLAUDE_CODE_SUBAGENT_MODEL', 'CLAUDE_CODE_EFFORT_LEVEL'
    )

    try {
        # CCR reads provider api_key values from the env at startup. The keys normally live in
        # the Windows Credential Manager; surface them as process env so $Z_AI_AUTH_TOKEN, etc.
        # resolve inside config.json. They are torn down in the finally block.
        $env:Z_AI_AUTH_TOKEN = $zaiToken
        if ($miniMaxKey)  { $env:MINIMAX_API_KEY  = $miniMaxKey }
        if ($deepSeekKey) { $env:DEEPSEEK_API_KEY = $deepSeekKey }
        if ($geminiKey)   { $env:GEMINI_API_KEY   = $geminiKey }

        if (-not (Install-ClaudeCCRSetup -ZaiToken $zaiToken -MiniMaxKey $miniMaxKey -DeepSeekKey $deepSeekKey -GeminiKey $geminiKey -Force:$forceSetup)) {
            return
        }

        if (-not (Get-Command ccr -ErrorAction SilentlyContinue)) {
            Write-Host 'ccr CLI not found.' -ForegroundColor Red
            Write-Host 'Install via: npm install -g @musistudio/claude-code-router' -ForegroundColor Yellow
            return
        }
        if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
            Write-Host 'claude CLI not found.' -ForegroundColor Red
            Write-Host 'Install via: irm https://claude.ai/install.ps1 | iex' -ForegroundColor Yellow
            return
        }

        # `ccr restart` is the documented way to apply config changes; fall back to `ccr start`
        # for the first launch (when no process exists yet) since some CCR builds reject restart
        # in that case.
        $restartOutput = & ccr restart 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'cccr: ccr restart did not complete cleanly; trying ccr start...' -ForegroundColor Yellow
            $startOutput = & ccr start 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host 'cccr: failed to start Claude Code Router.' -ForegroundColor Red
                if ($restartOutput) { $restartOutput | ForEach-Object { Write-Host $_ } }
                if ($startOutput)   { $startOutput   | ForEach-Object { Write-Host $_ } }
                return
            }
        }

        # Point Claude Code at the local CCR proxy. ANTHROPIC_AUTH_TOKEN is a placeholder --
        # CCR forwards the real provider key, so the value here is never validated. Clearing
        # ANTHROPIC_API_KEY prevents a User-scope Anthropic key from taking precedence.
        $env:ANTHROPIC_BASE_URL    = 'http://127.0.0.1:3456'
        $env:ANTHROPIC_AUTH_TOKEN  = 'ccr-local-router'
        $env:ANTHROPIC_API_KEY     = ''
        $env:API_TIMEOUT_MS        = '3000000'
        $env:DISABLE_TELEMETRY     = '1'
        $env:DISABLE_COST_WARNINGS = '1'
        $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1'
        # Allow 1M context only when MiniMax is in the longContext route.
        $env:CLAUDE_CODE_DISABLE_1M_CONTEXT = if ($miniMaxKey) { '0' } else { '1' }
        $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = '1'

        # Route the local CCR endpoint around any system HTTP proxy to avoid CONNECT failures.
        $noProxyItems = @()
        if ($env:NO_PROXY) { $noProxyItems += $env:NO_PROXY -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
        foreach ($hostName in @('127.0.0.1', 'localhost')) {
            if ($noProxyItems -notcontains $hostName) { $noProxyItems += $hostName }
        }
        $env:NO_PROXY = $noProxyItems -join ','

        claude @claudeArgArr
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function cccrd {
    <#
.SYNOPSIS
    Launches cccr with permissions skipped.

.DESCRIPTION
    Forwards all arguments to cccr and appends --dangerously-skip-permissions.

.EXAMPLE
    cccrd

.EXAMPLE
    cccrd "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    cccr @claudeArgs
}

function Invoke-RemoteClaudeCodeMM {
    <#
.SYNOPSIS
Runs Claude Code on a remote SSH endpoint via MiniMax with temporary remote state.

.DESCRIPTION
Reads the API key from MINIMAX_API_KEY if not provided, then runs the remote
Claude launcher with MiniMax endpoint defaults. The remote invocation always
uses --dangerously-skip-permissions.

.PARAMETER RemoteHost
SSH target in user@host form.

.PARAMETER ApiKey
MiniMax API key for the remote session.
Optional -- falls back to MINIMAX_API_KEY env var.

.PARAMETER Port
SSH port to connect to. Defaults to 22.

.EXAMPLE
Invoke-RemoteClaudeCodeMM -RemoteHost user@remote-host

.EXAMPLE
Invoke-RemoteClaudeCodeMM -RemoteHost user@remote-host -ApiKey $env:MINIMAX_API_KEY

.NOTES
Author: jjw(@thejjw)
Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteHost,

        [string]$ApiKey,

        [int]$Port = 22,

        # Optional: SSH private key file for authentication.
        [string]$KeyFile
    )

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        $ApiKey = Get-AiApiKey 'MINIMAX_API_KEY'
    }

    if (-not $ApiKey) {
        Write-Host "MINIMAX_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    # All three model tiers map to the same MiniMax model; Claude Code selects
    # the tier internally and MiniMax routes accordingly.
    $BaseUrl = "https://api.minimax.io/anthropic"
    $HaikuModel = "MiniMax-M3[1m]"
    $SonnetModel = "MiniMax-M3[1m]"
    $OpusModel = "MiniMax-M3[1m]"
    # 50-minute timeout -- MiniMax inference can be slow for complex agentic loops.
    $TimeoutMs = "3000000"
    $Disable1M = "0"

    # Build the splat hashtable and optionally attach KeyFile so a single
    # Invoke-RemoteClaudeCodeBase call covers both key-file and API-key modes.
    $baseParams = @{
        RemoteHost  = $RemoteHost
        ApiKey      = $ApiKey
        Port        = $Port
        BaseUrl     = $BaseUrl
        HaikuModel  = $HaikuModel
        SonnetModel = $SonnetModel
        OpusModel   = $OpusModel
        TimeoutMs   = $TimeoutMs
        Disable1M   = $Disable1M
    }
    if (-not [string]::IsNullOrWhiteSpace($KeyFile)) { $baseParams['KeyFile'] = $KeyFile }
    Invoke-RemoteClaudeCodeBase @baseParams
}

function Update-Profile {
    <#
.SYNOPSIS
    Updates the current PowerShell profile ($PROFILE) from the remote repository.
.DESCRIPTION
    Downloads the latest version of the PowerShell profile from the GitHub repository
    and overwrites the local $PROFILE file.
.EXAMPLE
    Update-Profile
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param()

    # Validate that $_ProfileUpdateUrl is set
    if (-not $_ProfileUpdateUrl) {
        Write-Error "Profile update URL is not defined (`$_ProfileUpdateUrl)."
        return
    }

    # Fetch just enough commit metadata to show which version we are updating from.
    # --filter=blob:none avoids downloading file content, saving bandwidth.
    if ((Get-Command git -ErrorAction SilentlyContinue) -and
        ($_ProfileUpdateUrl -match 'raw\.githubusercontent\.com/([^/]+/[^/]+)/refs/heads/[^/]+/(.+)')) {
        $tmpDir = $null
        try {
            $repoUrl  = "https://github.com/$($Matches[1]).git"
            $filePath = $Matches[2]
            $tmpDir   = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
            git clone --filter=blob:none --no-checkout --quiet $repoUrl $tmpDir
            $commitInfo = git -C $tmpDir log -1 --format="Remote commit at %cs, [%h]  %s" -- $filePath
            if ($commitInfo) {
                Write-Host $commitInfo -ForegroundColor DarkGray
            }
        } catch {
        } finally {
            if ($tmpDir -and (Test-Path $tmpDir)) {
                Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Host "Updating profile from $_ProfileUpdateUrl..." -ForegroundColor Cyan
    $tempFile = $null
    try {
        # Download to a temp file first; only overwrite $PROFILE on success to avoid corruption
        $tempFile = [System.IO.Path]::GetTempFileName()
        Invoke-WebRequest -Uri $_ProfileUpdateUrl -OutFile $tempFile -Verbose
        # .NET Copy with overwrite is more reliable than Move-Item -Force in PS 5.1,
        # which can throw IndexOutOfRangeException when replacing a larger file
        # (and hides the real error inside a broken Out-LineOutput formatter).
        [System.IO.File]::Copy($tempFile, $PROFILE, $true)
        Write-Host "Profile updated successfully! Restart your shell or run '. `$PROFILE' to apply changes." -ForegroundColor Green
    }
    catch {
        $msg = if ($_.Exception -and $_.Exception.Message) { $_.Exception.Message } else { "$_" }
        Write-Error "Failed to update profile: $msg"
    }
    finally {
        if ($tempFile -and (Test-Path $tempFile)) {
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Install-AiSkills {
    <#
.SYNOPSIS
    Installs public AI skills from the thejjw repository.
.DESCRIPTION
    Uses a shallow, blobless, sparse Git clone to fetch only the ai-skills directory,
    then overwrites the configured skill directories for OpenCode, Claude Code, and
    Antigravity CLI. Existing named skill directories are replaced so repeat manual
    runs refresh changed files and remove stale files.
.PARAMETER RepoUrl
    Git repository URL that contains the ai-skills directory.
.PARAMETER Branch
    Branch to clone from the repository.
.PARAMETER KeepTemp
    Preserves the temporary sparse clone for debugging.
.EXAMPLE
    Install-AiSkills
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [string]$RepoUrl = $_AiSkillsInternal.RepoUrl,
        [string]$Branch = $_AiSkillsInternal.Branch,
        [switch]$KeepTemp
    )

    $previousVerbosePreference = $VerbosePreference
    $VerbosePreference = 'Continue'
    $tmpDir = $null

    $openCodeClaudeSkills = $_AiSkillsInternal.OpenCodeClaudeSkills
    $antigravitySkills = $_AiSkillsInternal.AntigravitySkills

    $openCodeSkillsDir = Join-Path $env:USERPROFILE $_AiSkillsInternal.OpenCodeSkillsPath
    $claudeSkillsDir = Join-Path $env:USERPROFILE $_AiSkillsInternal.ClaudeSkillsPath
    $antigravitySkillsDir = Join-Path $env:USERPROFILE $_AiSkillsInternal.AntigravitySkillsPath
    $openCodeConfigFile = Join-Path $env:USERPROFILE $_AiSkillsInternal.OpenCodeConfigPath
    $openCodeConfigDir = Split-Path -Parent $openCodeConfigFile

    function Test-ChildPath {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ParentPath,
            [Parameter(Mandatory = $true)]
            [string]$ChildPath
        )

        $parentFull = [System.IO.Path]::GetFullPath($ParentPath).TrimEnd('\')
        $childFull = [System.IO.Path]::GetFullPath($ChildPath).TrimEnd('\')
        return $childFull.StartsWith("$parentFull\", [System.StringComparison]::OrdinalIgnoreCase)
    }

    function Copy-SkillDirectory {
        param(
            [Parameter(Mandatory = $true)]
            [string]$SkillName,
            [Parameter(Mandatory = $true)]
            [string]$SourceRoot,
            [Parameter(Mandatory = $true)]
            [string]$DestinationRoot,
            [Parameter(Mandatory = $true)]
            [string]$ToolName
        )

        $src = Join-Path $SourceRoot $SkillName
        $dst = Join-Path $DestinationRoot $SkillName

        if (-not (Test-Path -LiteralPath $src -PathType Container)) {
            throw "Missing skill source: $src"
        }
        if (-not (Test-Path -LiteralPath (Join-Path $src 'SKILL.md') -PathType Leaf)) {
            throw "Missing SKILL.md for skill '$SkillName': $src"
        }
        if (-not (Test-ChildPath -ParentPath $DestinationRoot -ChildPath $dst)) {
            throw "Refusing to remove destination outside expected skill root: $dst"
        }

        Write-Host "[info] Installing skill '$SkillName' to $ToolName"
        if (-not (Test-Path -LiteralPath $DestinationRoot)) {
            Write-Verbose "Creating skill root: $DestinationRoot"
            $null = New-Item -ItemType Directory -Path $DestinationRoot -Force -Verbose
        }
        if (Test-Path -LiteralPath $dst) {
            Write-Verbose "Removing existing skill directory: $dst"
            Remove-Item -LiteralPath $dst -Recurse -Force -Verbose
        }

        Write-Verbose "Creating destination skill directory: $dst"
        $null = New-Item -ItemType Directory -Path $dst -Force -Verbose
        Write-Verbose "Copying '$src\*' to '$dst'"
        Copy-Item -Path (Join-Path $src '*') -Destination $dst -Recurse -Force -Verbose
    }

    function Set-OpenCodeSkillPermissions {
        param(
            [Parameter(Mandatory = $true)]
            [string[]]$SkillNames
        )

        if (-not (Test-Path -LiteralPath $openCodeConfigDir)) {
            Write-Verbose "Creating OpenCode config directory: $openCodeConfigDir"
            $null = New-Item -ItemType Directory -Path $openCodeConfigDir -Force -Verbose
        }

        if (-not (Test-Path -LiteralPath $openCodeConfigFile)) {
            Write-Verbose "Creating OpenCode config file: $openCodeConfigFile"
            [IO.File]::WriteAllText($openCodeConfigFile, '{}', [Text.UTF8Encoding]::new($false))
        }

        Write-Verbose "Reading OpenCode config: $openCodeConfigFile"
        try {
            $config = Get-Content -LiteralPath $openCodeConfigFile -Raw | ConvertFrom-Json
        }
        catch {
            throw "OpenCode config is not valid JSON: $openCodeConfigFile"
        }

        if (-not $config) {
            $config = [pscustomobject]@{}
        }
        if (-not $config.PSObject.Properties['permission']) {
            Write-Verbose "Adding OpenCode permission object"
            $config | Add-Member -NotePropertyName 'permission' -NotePropertyValue ([pscustomobject]@{})
        }
        if (-not $config.permission.PSObject.Properties['skill']) {
            Write-Verbose "Adding OpenCode permission.skill object"
            $config.permission | Add-Member -NotePropertyName 'skill' -NotePropertyValue ([pscustomobject]@{})
        }

        foreach ($skill in $SkillNames) {
            Write-Verbose "Allowing OpenCode skill permission: $skill"
            $config.permission.skill | Add-Member -NotePropertyName $skill -NotePropertyValue 'allow' -Force
        }

        Write-Verbose "Writing updated OpenCode config: $openCodeConfigFile"
        [IO.File]::WriteAllText($openCodeConfigFile, ($config | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
        Write-Host "[info] Updated OpenCode skill permissions."
    }

    try {
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            throw 'git is required but was not found in PATH.'
        }

        $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
        Write-Verbose "Temporary clone directory: $tmpDir"
        Write-Verbose "Cloning only branch '$Branch' from $RepoUrl"
        & git clone --depth 1 --single-branch --branch $Branch --filter=blob:none --sparse $RepoUrl $tmpDir
        if ($LASTEXITCODE -ne 0) {
            throw "git clone failed with exit code $LASTEXITCODE"
        }

        Write-Verbose "Sparse-checking out $($_AiSkillsInternal.SparsePath)"
        & git -C $tmpDir sparse-checkout set $_AiSkillsInternal.SparsePath
        if ($LASTEXITCODE -ne 0) {
            throw "git sparse-checkout failed with exit code $LASTEXITCODE"
        }

        $skillsSourceDir = Join-Path $tmpDir $_AiSkillsInternal.SparsePath
        if (-not (Test-Path -LiteralPath $skillsSourceDir -PathType Container)) {
            throw "Sparse checkout did not produce expected directory: $skillsSourceDir"
        }
        Write-Verbose "Skill source directory: $skillsSourceDir"

        Set-OpenCodeSkillPermissions -SkillNames $openCodeClaudeSkills

        foreach ($skill in $openCodeClaudeSkills) {
            Copy-SkillDirectory -SkillName $skill -SourceRoot $skillsSourceDir -DestinationRoot $openCodeSkillsDir -ToolName 'OpenCode'
            Copy-SkillDirectory -SkillName $skill -SourceRoot $skillsSourceDir -DestinationRoot $claudeSkillsDir -ToolName 'Claude Code'
        }

        foreach ($skill in $antigravitySkills) {
            Copy-SkillDirectory -SkillName $skill -SourceRoot $skillsSourceDir -DestinationRoot $antigravitySkillsDir -ToolName 'Antigravity CLI'
        }

        Write-Host ""
        Write-Host "[done] Installed AI skills:" -ForegroundColor Green
        Write-Host "  OpenCode and Claude Code: $($openCodeClaudeSkills -join ', ')"
        Write-Host "  Antigravity CLI: $($antigravitySkills -join ', ')"
    }
    catch {
        Write-Error "Install-AiSkills failed: $_"
    }
    finally {
        if ($tmpDir -and (Test-Path -LiteralPath $tmpDir)) {
            if ($KeepTemp) {
                Write-Verbose "Keeping temporary clone for debugging: $tmpDir"
            }
            else {
                Write-Verbose "Removing temporary clone: $tmpDir"
                Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction Stop
                if (Test-Path -LiteralPath $tmpDir) {
                    Write-Warning "Temporary clone still exists after cleanup: $tmpDir"
                }
                else {
                    Write-Verbose "Temporary clone removed successfully."
                }
            }
        }
        $VerbosePreference = $previousVerbosePreference
    }
}

function Install-AiTools {
    <#
.SYNOPSIS
    Installs common developer tools and CLIs via winget/npm and helper installers.

.DESCRIPTION
    Checks for the presence of a curated list of Windows packages (via `winget`) and
    installs any that are missing. Also ensures `git` is present (offers interactive
    winget install), installs a small set of global `npm` packages, and bootstraps the
    Antigravity and Claude CLIs using their install scripts.

    On first run this helper will ask once whether to proceed automatically with
    installations; if you decline, it will list missing items for manual review and exit.

.PARAMETER Auto
    When supplied, skip the initial confirmation and proceed automatically.

.PARAMETER Update
    When supplied, upgrade any already-installed winget packages to their latest versions.

.PARAMETER ExtendedSetup
    When supplied, also installs the extended (non-minimal) package set: heavier tools such as
    FFmpeg, ImageMagick, security scanners, database CLIs, and similar large-scope packages.

.PARAMETER Sdk
    When supplied, also installs language SDK runtimes.

.PARAMETER Dotnet
    When supplied, installs the .NET SDK via the official dotnet-install.ps1 script from dot.net.
    Runs in a separate PowerShell process to avoid the script's exit call ending the current session.

.PARAMETER Docker
    When supplied, installs Docker Desktop via winget.

.PARAMETER Podman
    When supplied, installs Podman via winget. Cannot be used together with -Docker.

.PARAMETER Database
    When supplied, installs database client tools.

.PARAMETER All
    When supplied, enables all optional package groups: extended tools, SDK runtimes, .NET SDK,
    Docker Desktop, and database clients. Equivalent to -ExtendedSetup -Sdk -Docker -Database.
    Since Docker and Podman are alternatives, -All selects Docker; use -Podman explicitly if preferred.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [switch]$Auto,
        [switch]$Update,
        [switch]$ExtendedSetup,
        [switch]$Sdk,
        [switch]$Dotnet,
        [switch]$Docker,
        [switch]$Podman,
        [switch]$Database,
        [switch]$All
    )

    if ($Docker -and $Podman) {
        throw "Cannot specify both -Docker and -Podman switches simultaneously."
    }

    # -All expands into every optional group; Docker is chosen over Podman since they are alternatives.
    # If -Podman was explicitly passed alongside -All, honour Podman instead of Docker.
    if ($All) {
        $ExtendedSetup = $true
        $Sdk = $true
        if (-not $Podman) { $Docker = $true }
        $Database = $true
    }

    $wingetPackages = $_AiToolsInternal.WingetPackages
    if ($ExtendedSetup) {
        $wingetPackages += $_AiToolsInternal.ExtendedWingetPackages
    }
    # -Sdk implicitly enables -Dotnet because .NET is part of the SDK runtime stack.
    if ($Sdk) {
        $wingetPackages += $_AiToolsInternal.SdkWingetPackages
        $Dotnet = $true
    }
    if ($Docker) {
        $wingetPackages += 'Docker.DockerDesktop'
    }
    if ($Podman) {
        $wingetPackages += 'RedHat.Podman'
    }
    if ($Database) {
        $wingetPackages += $_AiToolsInternal.DbWingetPackages
    }

    $npmPackages = $_AiToolsInternal.NpmPackages

    $setupLabels = @('standard')
    if ($ExtendedSetup) { $setupLabels += 'extended' }
    if ($Sdk) { $setupLabels += 'sdk' }
    if ($Dotnet) { $setupLabels += 'dotnet' }
    if ($Docker) { $setupLabels += 'docker' }
    if ($Podman) { $setupLabels += 'podman' }
    if ($Database) { $setupLabels += 'db' }
    if ($All) { $setupLabels = @('all') }
    $setupLabel = $setupLabels -join ', '
    Write-Host "The setup will check/install the following items ($setupLabel):" -ForegroundColor Cyan
    Write-Host "Winget packages (total: $($wingetPackages.Count)):" -ForegroundColor Cyan
    $wingetIdx = 0
    foreach ($p in $wingetPackages) {
        $wingetIdx++
        Write-Host " - [$wingetIdx/$($wingetPackages.Count)] $p"
    }

    Write-Host "NPM global packages (installed via npm -g) (total: $($npmPackages.Count)):" -ForegroundColor Cyan
    $npmIdx = 0
    foreach ($np in $npmPackages) {
        $npmIdx++
        Write-Host " - [$npmIdx/$($npmPackages.Count)] $np"
    }

    Write-Host "Command-line tools to verify/install:" -ForegroundColor Cyan
    Write-Host " - git (installed via winget if missing)"
    if ($Dotnet) { Write-Host " - .NET SDK (via dotnet-install.ps1)" }

    Write-Host "CLIs to verify:" -ForegroundColor Cyan
    Write-Host " - agy (Antigravity CLI)"
    Write-Host " - claude (Claude CLI)"
    Write-Host " - codex (Codex CLI)"
    Write-Host " - opencode (opencode CLI)"

    if (-not $Auto) {
        $choice = Read-Host -Prompt "Proceed with automatic installation of missing items? This will run winget/npm/installers. Continue? (Y/n)"
        if ($choice -in @('n', 'N')) {
            Write-Host "Aborting automatic installs. Run Install-AiTools -Auto when ready to continue." -ForegroundColor Yellow
            return
        }
    }

    # Ensure winget exists
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "winget not found. Please install 'App Installer' (winget) from Microsoft Store and retry." -ForegroundColor Red
        return
    }

    # Winget installs shim executables into this Links directory, but some
    # system images don't include it in the default User PATH.  Ensure it's
    # present so `winget list` results translate to discoverable commands.
    $wingetLinksDir = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links"
    try {
        $userPath = Get-ItemPropertyValue -Path 'HKCU:\Environment' -Name 'PATH' -ErrorAction Stop
        if ($userPath) {
            $userPathArr = $userPath -split ';'
            $inPath = $false
            foreach ($p in $userPathArr) {
                if ($p.TrimEnd('\') -eq $wingetLinksDir.TrimEnd('\')) {
                    $inPath = $true
                    break
                }
            }
            if (-not $inPath) {
                $newUserPath = $userPath.TrimEnd(';') + ';' + $wingetLinksDir
                # Write directly to the registry rather than [Environment]::SetEnvironmentVariable
                # to preserve the existing ExpandString value kind.
                [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true).SetValue('PATH', $newUserPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
                $env:PATH = $env:PATH.TrimEnd(';') + ';' + $wingetLinksDir
                Write-Host "Added Winget Links directory ($wingetLinksDir) to your User PATH." -ForegroundColor Green
            }
        }
    } catch {
        # Non-critical -- if registry is inaccessible (e.g. restricted GPO), just proceed.
    }

    $wingetListOutput = @()
    try {
        $wingetListOutput = & winget list 2>$null
    }
    catch {
        Write-Host "Failed to query winget package inventory: $_" -ForegroundColor Red
        return
    }

    # winget list output is unstructured text; we match the package id then
    # verify the "Source" column contains "winget" to avoid false positives from
    # similarly-named packages in other sources (e.g. MSStore).
    function Test-WingetInstalledPackage {
        param(
            [string[]]$Rows,
            [string]$PackageId
        )

        $escapedId = [regex]::Escape($PackageId)
        foreach ($row in $Rows) {
            if ($row -notmatch $escapedId) {
                continue
            }

            if ($row -match "\bwinget\b") {
                return $true
            }
        }

        return $false
    }

    $missing = @()
    $installed = @()
    $totalWinget = $wingetPackages.Count
    $wingetCheckIdx = 0
    # Enumerate and check install status of each winget package, printing progress
    foreach ($pkg in $wingetPackages) {
        $wingetCheckIdx++
        $isInstalled = Test-WingetInstalledPackage -Rows $wingetListOutput -PackageId $pkg
        if ($isInstalled) {
            Write-Host "[$wingetCheckIdx/$totalWinget] installed:   $pkg" -ForegroundColor Green
            $installed += $pkg
        }
        else {
            Write-Host "[$wingetCheckIdx/$totalWinget] not installed: $pkg" -ForegroundColor Yellow
            $missing += $pkg
        }
    }

    if ($missing.Count -gt 0) {
        Write-Host "Missing winget packages:" -ForegroundColor Yellow
        foreach ($m in $missing) { Write-Host " - $m" }

        Write-Host "Installing missing packages via winget..." -ForegroundColor Cyan
        $totalMissing = $missing.Count
        $wingetInstallIdx = 0
        # Install each missing winget package, printing progress
        foreach ($m in $missing) {
            $wingetInstallIdx++
            Write-Host "[$wingetInstallIdx/$totalMissing] Installing $m..." -ForegroundColor Cyan
            try {
                # Start-Process is used instead of direct invocation so winget can
                # prompt for UAC elevation without deadlocking the parent console.
                Start-Process -FilePath 'winget' -ArgumentList "install -s winget -e --id $m" -NoNewWindow -Wait
            }
            catch { Write-Host "Failed to start winget for $($m): $_" -ForegroundColor Red }
        }

        $wingetListOutput = & winget list 2>$null
        $stillMissing = $missing | Where-Object { -not (Test-WingetInstalledPackage -Rows $wingetListOutput -PackageId $_) }
        if ($stillMissing) {
            Write-Host "The following packages failed to install:" -ForegroundColor Red
            foreach ($m in $stillMissing) { Write-Host " - $m" -ForegroundColor Red }
        }
        else {
            Write-Host "All packages installed successfully." -ForegroundColor Green
        }
    }
    else {
        Write-Host "All winget packages already present." -ForegroundColor Green
    }

    if ($Update -and $installed.Count -gt 0) {
        Write-Host "Upgrading existing winget packages..." -ForegroundColor Cyan
        $totalInstalled = $installed.Count
        $wingetUpgradeIdx = 0
        # Upgrade each installed winget package, printing progress
        foreach ($pkg in $installed) {
            $wingetUpgradeIdx++
            Write-Host "[$wingetUpgradeIdx/$totalInstalled] Upgrading $pkg..." -ForegroundColor Cyan
            try {
                Start-Process -FilePath 'winget' -ArgumentList "upgrade -s winget -e --id $pkg" -NoNewWindow -Wait
            }
            catch { Write-Host "Failed to start winget upgrade for $($pkg): $_" -ForegroundColor Red }
        }
    }

    # Ensure git is present; if not, offer interactive installer
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "git not found. Launching interactive winget installer for Git..." -ForegroundColor Yellow
        Start-Process -FilePath 'winget' -ArgumentList 'install -s winget -e --id Git.Git -i' -NoNewWindow -Wait
    }

    # Install .NET SDK via official install script (https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-install-script)
    if ($Dotnet) {
        Write-Host "Installing .NET SDK via dotnet-install.ps1..." -ForegroundColor Cyan
        # dotnet-install.ps1 calls exit internally, so it must run in a child process.
        # Forcing TLS 1.2 ensures the download succeeds on older Windows 10 builds.
        & powershell -NoProfile -ExecutionPolicy Unrestricted -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; &([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://dot.net/v1/dotnet-install.ps1')))"
        Write-Host ".NET SDK install script completed." -ForegroundColor Green
    }

    # Install global npm packages if npm available
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        $totalNpm = $npmPackages.Count
        $npmInstallIdx = 0
        # Install each NPM global package, printing progress
        foreach ($np in $npmPackages) {
            $npmInstallIdx++
            Write-Host "[$npmInstallIdx/$totalNpm] Installing npm package $np (global)..." -ForegroundColor Cyan
            try { & npm install -g $np } catch { Write-Host "npm install failed for $($np): $_" -ForegroundColor Red }
        }
    }
    else {
        Write-Host "npm not found - aborting Install-AiTools. Please inspect your Node/npm installation and re-run." -ForegroundColor Red
        return
    }

    Write-Host "CLIs to verify:" -ForegroundColor Cyan
    Write-Host " - agy (Antigravity CLI)"
    Write-Host " - claude (Claude CLI)"
    Write-Host " - codex (Codex CLI)"
    Write-Host " - opencode (opencode CLI)"

    # Install Antigravity and Claude CLIs using their recommended installers
    Write-Host "Verifying CLIs and Configuring AI tool settings..." -ForegroundColor Cyan

    if (-not (Get-Command agy -ErrorAction SilentlyContinue)) {
        Write-Host "agy CLI not found; installing via $($_AiToolsInternal.Urls.AgyCli)..." -ForegroundColor Yellow
        try { & powershell -NoProfile -Command "iex (irm '$($_AiToolsInternal.Urls.AgyCli)')" } catch { Write-Host "Failed to install agy: $_" -ForegroundColor Red }
    } else {
        # If agy is present, ensure it's configured with the default settings
        Install-AgySettings
    }

    if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
        Write-Host "claude CLI not found; installing via $($_AiToolsInternal.Urls.ClaudeCli)..." -ForegroundColor Yellow
        try { & powershell -NoProfile -Command "iex (irm '$($_AiToolsInternal.Urls.ClaudeCli)')" } catch { Write-Host "Failed to install claude: $_" -ForegroundColor Red }
        # The claude installer places the binary in ~/.local/bin; ensure it's on the user PATH.
        $claudeBin = Join-Path $env:USERPROFILE '.local\bin'
        $regPath = (Get-ItemPropertyValue -Path 'HKCU:\Environment' -Name 'PATH' -ErrorAction SilentlyContinue)
        $regArr = if ($regPath) { $regPath -split ';' } else { @() }
        if ($regArr -notcontains $claudeBin) {
            $newRegPath = if ($regPath) { $regPath.TrimEnd(';') + ';' + $claudeBin } else { $claudeBin }
            [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true).SetValue('PATH', $newRegPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
            $env:PATH = $env:PATH.TrimEnd(';') + ';' + $claudeBin
            Write-Host "Added $claudeBin to user PATH for claude CLI." -ForegroundColor Green
        }
    } else {
        # If claude is present, ensure it's configured with the default settings
        Install-GlobalClaudeSettings
    }

    if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
        Write-Host "codex CLI not found; installing via $($_AiToolsInternal.Urls.CodexCli)..." -ForegroundColor Yellow
        try { & powershell -NoProfile -ExecutionPolicy ByPass -Command "irm '$($_AiToolsInternal.Urls.CodexCli)' | iex" } catch { Write-Host "Failed to install codex: $_" -ForegroundColor Red }
    } else {
        # If codex is present, ensure it's configured with the default settings
        Install-CodexSettings
    }

    # Install opencode via npm (not winget) so the package is managed by npm
    # and the native `opencode upgrade` command works as upstream intended.
    if (-not (Get-Command opencode -ErrorAction SilentlyContinue)) {
        Write-Host "opencode CLI not found; installing via 'npm install -g opencode-ai'..." -ForegroundColor Yellow
        try { & npm install -g opencode-ai } catch { Write-Host "Failed to install opencode: $_" -ForegroundColor Red }
    }

    # Create a docker.bat shim so tools that hardcode `docker` commands
    # (compose files, scripts) transparently route through podman.
    if ($Podman) {
        Write-Host "Configuring Podman aliases..." -ForegroundColor Cyan
        $wingetLinksDir = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links"
        if (-not (Test-Path -LiteralPath $wingetLinksDir)) {
            $null = New-Item -ItemType Directory -Path $wingetLinksDir -Force -Verbose
        }
        $dockerBat = Join-Path $wingetLinksDir "docker.bat"
        "@echo off`r`npodman %*" | Out-File -FilePath $dockerBat -Encoding ascii
        Write-Host "Created docker alias (docker.bat) for podman in Winget Links directory." -ForegroundColor Green
    }

    Write-Host "Install-AiTools finished. You may need to restart PowerShell to pick up new PATH or env changes." -ForegroundColor Green
}

function Set-AiApiKeys {
    <#
.SYNOPSIS
    Interactive helper to view and set Claude-related API keys in the user environment.
    (DEPRECATED: Now delegates securely to Set-AiApiKeysCS)

.DESCRIPTION
    Checks for existing values of AI API key (e.g. `DEEPSEEK_API_KEY`, `Z_AI_AUTH_TOKEN`, ...) in
    the current session and the persisted User environment. Presents a summary and prompts
    the user to enter missing keys (or optionally overwrite existing ones). Values are
    saved to the User environment via [Environment]::SetEnvironmentVariable so they persist
    across sessions.

.PARAMETER Force
    When supplied, prompt to overwrite existing keys instead of skipping them.

.EXAMPLE
    Set-AiApiKeys

.EXAMPLE
    Set-AiApiKeys -Force

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    Write-Host "WARNING: Set-AiApiKeys is deprecated. Delegating securely to Set-AiApiKeysCS..." -ForegroundColor Yellow
    Set-AiApiKeysCS -Force:$Force

    # <# Legacy environment variable implementation commented out below:
    # $names = @('DEEPSEEK_API_KEY', 'Z_AI_AUTH_TOKEN', 'MINIMAX_API_KEY', 'NVIDIA_API_KEY', 'OPENROUTER_API_KEY')
    #
    # function Get-UserValue($n) {
    #     # Check process (current session) first, then persisted User scope
    #     $v = [Environment]::GetEnvironmentVariable($n, 'Process')
    #     if ($v) { return $v }
    #     return [Environment]::GetEnvironmentVariable($n, 'User')
    # }
    #
    # function MaskValue($v) {
    #     if (-not $v) { return '<missing>' }
    #     return "<set, length=$($v.Length)>"
    # }
    #
    # Write-Host "Checking existing keys (session and User scope):" -ForegroundColor Cyan
    # $found = @{}
    # foreach ($n in $names) {
    #     $v = Get-UserValue $n
    #     $found[$n] = $v
    #     Write-Host " - $($n) : $(MaskValue $v)"
    # }
    #
    # Write-Host "";
    # Write-Host "You can press Enter to skip setting a key. To keep an existing value, leave it blank when prompted." -ForegroundColor Yellow
    #
    # foreach ($n in $names) {
    #     $current = $found[$n]
    #     if ($current -and -not $Force) {
    #         Write-Host "Skipping $n (already set). Use -Force to overwrite." -ForegroundColor DarkGray
    #         continue
    #     }
    #
    #     if ($current -and $Force) {
    #         $resp = Read-Host -Prompt "$n already set. Overwrite? (y/N)"
    #         if ($resp -notin @('y', 'Y')) { Write-Host "Keeping existing $n." -ForegroundColor DarkGray; continue }
    #     }
    #
    #     # Read hidden input as SecureString. If the input isn't a SecureString or is empty, skip.
    #     $secure = Read-Host -AsSecureString -Prompt "Enter value for $n (input hidden, blank to skip)"
    #     if ($null -eq $secure -or -not ($secure -is [System.Security.SecureString])) {
    #         Write-Host "Skipped $n." -ForegroundColor DarkGray
    #         continue
    #     }
    #
    #     $ptr = [IntPtr]::Zero
    #     try {
    #         $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    #         $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
    #     }
    #     catch {
    #         Write-Host "Failed to read secure input for $($n): $_" -ForegroundColor Red
    #         continue
    #     }
    #     finally {
    #         if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    #     }
    #
    #     [Environment]::SetEnvironmentVariable($n, $plain, 'User')
    #     Write-Host "Set $n in User environment." -ForegroundColor Green
    # }
    #
    # Write-Host "";
    # Write-Host "Done. To apply changes to this session run:`n  . `$PROFILE" -ForegroundColor Cyan
    # Write-Host "Or restart PowerShell to pick up the new values." -ForegroundColor Cyan
    # #>
}

function Get-AiApiKey {
    <#
    .SYNOPSIS
        Retrieves an API key, prioritizing current process environment, then Windows Credential Manager,
        and finally legacy User environment variables.

    .NOTES
        Author: jjw(@thejjw)
        Last Edit: 2026-05
#>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    # 1. Process environment (allows temporary session overrides)
    $v = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ($v) { return $v }

    # 2. Windows Credential Manager (DPAPI-backed, survives reboots, no plaintext in registry)
    [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    try {
        $cred = $vault.Retrieve($Name, 'api-key')
        $cred.RetrievePassword()
        return $cred.Password
    }
    catch {
        # 3. Fallback: legacy plaintext env vars for keys stored before Credential Manager migration
        return [Environment]::GetEnvironmentVariable($Name, 'User')
    }
}

function Set-AiApiKeysCS {
    <#
    .SYNOPSIS
        Interactive helper to view and set Claude-related API keys in Windows Credential Manager.

    .DESCRIPTION
        Checks for existing values of AI API keys in the Windows Credential Manager (PasswordVault).
        Presents a summary and prompts the user to enter missing keys (or optionally overwrite existing ones).
        Values are securely saved using Windows Credential Manager (DPAPI-encrypted), keeping plaintext
        credentials out of your registry.

    .PARAMETER Force
        When supplied, prompt to overwrite existing keys instead of skipping them.

    .NOTES
        Author: jjw(@thejjw)
        Last Edit: 2026-05
    #>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    # WinRT PasswordVault is per-user and DPAPI-encrypted at rest -- no plaintext
    # credentials in the registry. The explicit type load is required for both
    # Windows PowerShell 5.1 and PowerShell 7+ on Windows.
    [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $names = @('DEEPSEEK_API_KEY', 'Z_AI_AUTH_TOKEN', 'MINIMAX_API_KEY', 'GEMINI_API_KEY', 'NVIDIA_API_KEY', 'OPENROUTER_API_KEY')
    # All keys share a single resource userName so they form a logical group in
    # Credential Manager and can be enumerated/cleared together.
    $userName = 'api-key'

    # Retrieve a stored key's plaintext value from vault
    function Get-StoredKey($n) {
        try {
            $cred = $vault.Retrieve($n, $userName)
            $cred.RetrievePassword()
            return $cred.Password
        }
        catch {
            return $null
        }
    }

    # Format the masked key display status
    function MaskValue($v) {
        if (-not $v) { return '<missing>' }
        return "<secured in Credential Manager, length=$($v.Length)>"
    }

    Write-Host "Checking existing keys in Windows Credential Manager:" -ForegroundColor Cyan
    $found = @{}
    foreach ($n in $names) {
        $v = Get-StoredKey $n
        $found[$n] = $v
        Write-Host " - $($n) : $(MaskValue $v)"
    }

    Write-Host ""
    Write-Host "You can press Enter to skip setting a key. To keep an existing value, leave it blank when prompted." -ForegroundColor Yellow

    foreach ($n in $names) {
        $current = $found[$n]
        if ($current -and -not $Force) {
            Write-Host "Skipping $n (already set in vault). Use -Force to overwrite." -ForegroundColor DarkGray
            continue
        }

        if ($current -and $Force) {
            $resp = Read-Host -Prompt "$n already set in vault. Overwrite? (y/N)"
            if ($resp -notin @('y', 'Y')) { Write-Host "Keeping existing $n." -ForegroundColor DarkGray; continue }
        }

        # Read hidden input as SecureString. Skip if empty.
        $secure = Read-Host -AsSecureString -Prompt "Enter value for $n (input hidden, blank to skip)"
        if ($null -eq $secure -or -not ($secure -is [System.Security.SecureString]) -or $secure.Length -eq 0) {
            Write-Host "Skipped $n." -ForegroundColor DarkGray
            continue
        }

        $ptr = [IntPtr]::Zero
        try {
            $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)

            # Store inside the vault
            $newCred = New-Object Windows.Security.Credentials.PasswordCredential($n, $userName, $plain)
            $vault.Add($newCred)
            Write-Host "Successfully saved $n to Windows Credential Manager." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to save secure input for $($n): $_" -ForegroundColor Red
            continue
        }
        finally {
            if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        }
    }

    Write-Host ""
    Write-Host "Done! Run 'Load-AiApiKeysFromCS' to load these into your current terminal process." -ForegroundColor Cyan
}

function Load-AiApiKeysFromCS {
    <#
    .SYNOPSIS
        Loads secure API keys from Windows Credential Manager into the current process environment.

    .DESCRIPTION
        Retrieves saved credentials from the Windows PasswordVault and registers them as
        session-level (Process) environment variables. This makes them immediately available
        to all CLI tools, scripts, and processes run from this PowerShell terminal (e.g. claude, python, etc.),
        without saving them as plaintext in registry variables.

    .PARAMETER Quiet
        When supplied, skips detailed output and only prints an ambiguous completion message.

    .NOTES
        Author: jjw(@thejjw)
        Last Edit: 2026-05
    #>
    [CmdletBinding()]
    param(
        [switch]$Quiet
    )
    [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $names = @('DEEPSEEK_API_KEY', 'Z_AI_AUTH_TOKEN', 'MINIMAX_API_KEY', 'GEMINI_API_KEY', 'NVIDIA_API_KEY', 'OPENROUTER_API_KEY')
    $userName = 'api-key'

    $loadedCount = 0
    foreach ($n in $names) {
        try {
            $cred = $vault.Retrieve($n, $userName)
            $cred.RetrievePassword()
            $envKey = $cred.Password
            if ($envKey) {
                [Environment]::SetEnvironmentVariable($n, $envKey, 'Process')
                $loadedCount++
            }
        }
        catch {
            # Silent skip if credential is not in vault
        }
    }
    if ($loadedCount -gt 0) {
        if ($Quiet) {
            Write-Host "Credential storage load completed." -ForegroundColor Green
        } else {
            Write-Host "Loaded $loadedCount API key(s) from Windows Credential Manager into session environment." -ForegroundColor Green
        }
    }
}


function ccd {
    <#
.SYNOPSIS
Shorthand for running claude with the --dangerously-skip-permissions flag.

.DESCRIPTION
Equivalent of the bash alias: alias ccd='claude --dangerously-skip-permissions'
Checks whether the claude CLI is installed before invoking it.

.EXAMPLE
ccd

Runs Claude Code with permissions skipped.

.EXAMPLE
ccd --model claude-opus

Runs Claude Code with a specific model and permissions skipped.

.NOTES
Author: jjw(@thejjw)
Last Edit: 2026-05
#>
    if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
        Write-Host 'claude CLI not found.' -ForegroundColor Red
        Write-Host 'Install via: irm https://claude.ai/install.ps1 | iex' -ForegroundColor Yellow
        Write-Host 'Or visit:    https://claude.com/product/claude-code' -ForegroundColor Yellow
        return
    }
    claude --dangerously-skip-permissions @args
}

function agyd {
    <#
.SYNOPSIS
    Launches agy with permissions skipped.

.DESCRIPTION
    Forwards all arguments to agy and appends --dangerously-skip-permissions.
    Checks whether the agy CLI is installed before invoking it.

.EXAMPLE
    agyd

.EXAMPLE
    agyd "Summarize the changed files"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    if (-not (Get-Command agy -ErrorAction SilentlyContinue)) {
        Write-Host 'agy CLI not found.' -ForegroundColor Red
        Write-Host 'Install via: irm https://antigravity.google/cli/install.ps1 | iex' -ForegroundColor Yellow
        Write-Host 'Or visit:    https://antigravity.google' -ForegroundColor Yellow
        return
    }
    agy --dangerously-skip-permissions @args
}

function Test-AnthropicApi {
    <#
.SYNOPSIS
    Tests connectivity to an Anthropic-compatible API endpoint.

.DESCRIPTION
    Sends a minimal chat-completion request to the specified Anthropic Messages API
    endpoint and reports whether the API key, URL, and model combination is working.
    Useful for verifying credentials and endpoint reachability before integrating
    with tools or scripts.

.PARAMETER ApiKey
    The API key used for authentication (sent as x-api-key header).

.PARAMETER ApiUrl
    The base URL of the Anthropic-compatible API (e.g. "https://api.anthropic.com"
    or "https://api.z.ai/api/anthropic").

.PARAMETER Model
    The model identifier to use for the test request (e.g. "claude-sonnet-4-20250514").

.EXAMPLE
    Test-AnthropicApi -ApiKey $env:ANTHROPIC_API_KEY -ApiUrl "https://api.anthropic.com" -Model "claude-sonnet-4-20250514"

.EXAMPLE
    Test-AnthropicApi $env:SOME_AUTH_TOKEN "https://api.z.ai/api/anthropic" "glm-5.1"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ApiKey,

        [Parameter(Mandatory, Position = 1)]
        [string]$ApiUrl,

        [Parameter(Mandatory, Position = 2)]
        [string]$Model
    )

    Write-Host "Testing API connectivity..."
    Write-Host "URL: $ApiUrl"
    Write-Host "Model: $Model"
    Write-Host ("-" * 40)

    $headers = @{
        "x-api-key"         = $ApiKey
        "Content-Type"      = "application/json"
        "anthropic-version" = "2023-06-01"
    }

    $body = @{
        model      = $Model
        max_tokens = 100
        messages   = @(
            @{
                role    = "user"
                content = "Say 'API is working'"
            }
        )
    } | ConvertTo-Json -Depth 10

    try {
        $response = Invoke-WebRequest -Uri "$ApiUrl/v1/messages" `
            -Method POST `
            -Headers $headers `
            -Body $body `
            -TimeoutSec 30 `
            -UseBasicParsing

        Write-Host "Status Code: $($response.StatusCode)"

        if ($response.StatusCode -eq 200) {
            $data = $response.Content | ConvertFrom-Json
            Write-Host "[OK] API is responding!"
            if ($data.content -and $data.content.Count -gt 0) {
                Write-Host "Response: $($data.content[0].text)"
            }
        }
    }
    catch {
        Write-Host "[ERROR] $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $errorBody = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorBody)
            $errorText = $reader.ReadToEnd()
            Write-Host $errorText
        }
    }
}

function Test-OpenAiApi {
    <#
.SYNOPSIS
    Tests connectivity to an OpenAI-compatible API endpoint.

.DESCRIPTION
    Sends a minimal chat-completion request to the specified OpenAI Chat Completions
    API endpoint and reports whether the API key, URL, and model combination is working.
    Useful for verifying credentials and endpoint reachability before integrating
    with tools or scripts.

.PARAMETER ApiKey
    The API key used for authentication (sent as Bearer token in Authorization header).

.PARAMETER ApiUrl
    The base URL of the OpenAI-compatible API (e.g. "https://api.openai.com/v1"
    or "https://api.deepseek.com/v1").

.PARAMETER Model
    The model identifier to use for the test request (e.g. "gpt-4o", "deepseek-chat").

.EXAMPLE
    Test-OpenAiApi -ApiKey $env:OPENAI_API_KEY -ApiUrl "https://api.openai.com/v1" -Model "gpt-4o"

.EXAMPLE
    Test-OpenAiApi $env:DEEPSEEK_API_KEY "https://api.deepseek.com/v1" "deepseek-chat"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ApiKey,

        [Parameter(Mandatory, Position = 1)]
        [string]$ApiUrl,

        [Parameter(Mandatory, Position = 2)]
        [string]$Model
    )

    Write-Host "Testing API connectivity..."
    Write-Host "URL: $ApiUrl"
    Write-Host "Model: $Model"
    Write-Host ("-" * 40)

    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    $body = @{
        model      = $Model
        max_tokens = 100
        messages   = @(
            @{
                role    = "user"
                content = "Say 'API is working'"
            }
        )
    } | ConvertTo-Json -Depth 10

    try {
        $response = Invoke-WebRequest -Uri "$ApiUrl/chat/completions" `
            -Method POST `
            -Headers $headers `
            -Body $body `
            -TimeoutSec 30 `
            -UseBasicParsing

        Write-Host "Status Code: $($response.StatusCode)"

        if ($response.StatusCode -eq 200) {
            $data = $response.Content | ConvertFrom-Json
            Write-Host "[OK] API is responding!"
            if ($data.choices -and $data.choices.Count -gt 0) {
                Write-Host "Response: $($data.choices[0].message.content)"
            }
        }
    }
    catch {
        Write-Host "[ERROR] $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $errorBody = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorBody)
            $errorText = $reader.ReadToEnd()
            Write-Host $errorText
        }
    }
}

function Invoke-AiUpgrade {
    <#
.SYNOPSIS
    Updates all AI CLI tools in one shot.
.DESCRIPTION
    Runs the update/upgrade command for agy, claude, codex, and opencode sequentially.
    Use the alias 'aiu' for convenience.
.EXAMPLE
    Invoke-AiUpgrade
.EXAMPLE
    aiu
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    [CmdletBinding()]
    param()

    $tools = @(
        @{ Label = 'agy';      Cmd = 'agy';      Args = @('update') },
        @{ Label = 'claude';   Cmd = 'claude';   Args = @('update') },
        @{ Label = 'codex';    Cmd = 'codex';    Args = @('update') },
        @{ Label = 'opencode'; Cmd = 'opencode'; Args = @('upgrade') }
    )

    foreach ($tool in $tools) {
        if (-not (Get-Command $tool.Cmd -ErrorAction SilentlyContinue)) {
            Write-Warning "$($tool.Label): not found in PATH, skipping."
            continue
        }
        Write-Host ">>> $($tool.Label) $($tool.Args -join ' ')" -ForegroundColor Cyan
        & $tool.Cmd @($tool.Args)
    }
}
Set-Alias -Name aiu -Value Invoke-AiUpgrade

# === AI provider usage-query functions ===
# Provides Get-MinimaxUsage, Get-ZaiUsage, Get-DeepseekUsage, and shared
# formatting helpers. Call any of them after the vault credentials load
# further down (Load-AiApiKeysFromCS) so $env:MINIMAX_API_KEY,
# $env:Z_AI_AUTH_TOKEN, and $env:DEEPSEEK_API_KEY are populated.

# --- Shared helpers --------------------------------------------------------

# Render a TimeSpan as a compact human-readable string.
function Format-Duration {
    param([TimeSpan]$ts)
    if ($ts.TotalDays -ge 1)  { return ('{0:N1} d ({1:N0} h)' -f $ts.TotalDays,  $ts.TotalHours) }
    if ($ts.TotalHours -ge 1) { return ('{0:N1} h ({1:N0} m)'  -f $ts.TotalHours, $ts.TotalMinutes) }
    return ('{0:N0} m ({1:N0} s)' -f $ts.TotalMinutes, $ts.TotalSeconds)
}

# Print a section banner.
function Write-Section {
    param([string]$title)
    Write-Host ''
    Write-Host ('== {0} ==' -f $title) -ForegroundColor Cyan
}

# Convert epoch milliseconds to a local DateTime.
function From-EpochMs {
    param([long]$ms)
    return [DateTimeOffset]::FromUnixTimeMilliseconds($ms).LocalDateTime
}

# Format a token count as a compact human-readable string.
function Format-Tokens {
    param([double]$n)
    if ($n -le 0) { return '0' }
    if ($n -ge 1e9) { return ('{0:N2}B' -f ($n / 1e9)) }
    if ($n -ge 1e6) { return ('{0:N2}M' -f ($n / 1e6)) }
    if ($n -ge 1e3) { return ('{0:N2}K' -f ($n / 1e3)) }
    return ('{0:N0}' -f $n)
}

# Format a cost value as a compact decimal, stripping trailing zeros.
function Format-Price {
    param([double]$n)
    $s = ('{0:N6}' -f $n).TrimEnd('0')
    if ($s.EndsWith('.')) { $s = $s.Substring(0, $s.Length - 1) }
    return $s
}

# Compute total/avg/peak for a numeric series aligned to xTime.
function Get-SeriesStats {
    param([object[]]$xTime, [object[]]$series)
    if (-not $series -or $series.Count -eq 0) {
        return [pscustomobject]@{ Total = 0; Avg = 0; Peak = 0; PeakHour = $null }
    }
    $total = 0; $peak = 0; $peakIdx = -1
    for ($i = 0; $i -lt $series.Count; $i++) {
        $v = [int]$series[$i]
        $total += $v
        if ($v -gt $peak) { $peak = $v; $peakIdx = $i }
    }
    $avg = if ($series.Count -gt 0) { [double]$total / $series.Count } else { 0 }
    $peakHour = if ($peakIdx -ge 0 -and $xTime -and $peakIdx -lt $xTime.Count) { [string]$xTime[$peakIdx] } else { $null }
    return [pscustomobject]@{ Total = $total; Avg = $avg; Peak = $peak; PeakHour = $peakHour }
}

# Detect spikes: indexes where value > SpikeRatio * avg. Returns array
# of @{ Hour; Value } records (or empty array).
function Get-Spikes {
    param([object[]]$xTime, [object[]]$series, [double]$avg, [double]$SpikeRatio = 3.0)
    $out = @()
    if (-not $series -or $avg -le 0) { return $out }
    $threshold = $SpikeRatio * $avg
    for ($i = 0; $i -lt $series.Count; $i++) {
        $v = [int]$series[$i]
        if ($v -gt $threshold) {
            $hour = if ($xTime -and $i -lt $xTime.Count) { [string]$xTime[$i] } else { "idx $i" }
            $out += [pscustomobject]@{ Hour = $hour; Value = $v }
        }
    }
    return $out
}

# Z.AI's quota endpoint wraps payload under .data; pull that out.
function Unwrap-ZaiData {
    param([object]$resp)
    if ($null -eq $resp) { return $null }
    if ($resp.PSObject.Properties['data'] -and $null -ne $resp.data) { return $resp.data }
    return $resp
}

# --- Get-MinimaxUsage ------------------------------------------------------
# Queries MiniMax's token-plan endpoint for remaining quotas and burn rates
# over the current interval and the current week. Stashes the parsed
# response in $Global:minimaxLastQuery and returns it.

function Get-MinimaxUsage {
<#
.SYNOPSIS
    Queries MiniMax's token-plan endpoint and reports per-model remaining quotas and burn rate.
.DESCRIPTION
    Calls https://www.minimax.io/v1/token_plan/remains with the API key in
    $env:MINIMAX_API_KEY, computes time-until-reset and burn rate
    (used / elapsed) for both the current interval and the current week per
    model, and flags concerns when remaining percent drops below threshold
    or burn outpaces linear consumption. Stores the parsed response in
    $Global:minimaxLastQuery and returns it.
.PARAMETER ApiKey
    MiniMax API key. Defaults to $env:MINIMAX_API_KEY.
.PARAMETER LowPercent
    Remaining-percent threshold below which a model is reported as LOW.
.PARAMETER CriticalPercent
    Remaining-percent threshold below which a model is reported as CRITICAL.
.PARAMETER ResetWarnHours
    Flag an interval that resets within this many hours.
.PARAMETER BurnWarnRatio
    Flag a model whose burn rate exceeds this multiple of linear consumption.
.PARAMETER All
    When supplied, prints the raw API response inline. Otherwise the raw
    response stays in $Global:minimaxLastQuery.
.EXAMPLE
    Get-MinimaxUsage
.EXAMPLE
    $r = Get-MinimaxUsage
    $r.model_remains | Where-Object { $_.current_interval_remaining_percent -lt 10 }
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    [CmdletBinding()]
    param(
        [string]$ApiKey = $env:MINIMAX_API_KEY,
        [int]$LowPercent = 30,
        [int]$CriticalPercent = 10,
        [int]$ResetWarnHours = 1,
        [double]$BurnWarnRatio = 1.0,
        [switch]$All
    )

    if (-not $ApiKey) { Write-Error 'MINIMAX_API_KEY not set (env var or -ApiKey).'; return }

    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $ApiKey"
    }
    try {
        $resp = Invoke-RestMethod -Uri 'https://www.minimax.io/v1/token_plan/remains' -Headers $headers -Method GET
    } catch {
        Write-Error "API call failed: $($_.Exception.Message)"
        return
    }

    $Global:minimaxLastQuery = $resp

    Write-Section 'Raw API response (MiniMax)'
    if ($All) { $resp | ConvertTo-Json -Depth 8 | Out-Host }
    else      { Write-Host '  (suppressed; stored in $Global:minimaxLastQuery. Use -All to display inline.)' -ForegroundColor DarkGray }

    $now = Get-Date
    Write-Section 'Per-model insights (MiniMax)'
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($m in $resp.model_remains) {
        $intervalStart   = From-EpochMs ([long]$m.start_time)
        $intervalEnd     = From-EpochMs ([long]$m.end_time)
        $intervalTotal   = $intervalEnd - $intervalStart
        $intervalElapsed = $now - $intervalStart
        if ($intervalElapsed.TotalSeconds -lt 0) { $intervalElapsed = [TimeSpan]::Zero }
        if ($intervalElapsed -gt $intervalTotal)  { $intervalElapsed = $intervalTotal }

        $weeklyStart   = From-EpochMs ([long]$m.weekly_start_time)
        $weeklyEnd     = From-EpochMs ([long]$m.weekly_end_time)
        $weeklyTotal   = $weeklyEnd - $weeklyStart
        $weeklyElapsed = $now - $weeklyStart
        if ($weeklyElapsed.TotalSeconds -lt 0) { $weeklyElapsed = [TimeSpan]::Zero }
        if ($weeklyElapsed -gt $weeklyTotal)   { $weeklyElapsed = $weeklyTotal }

        $iRemain = [int]$m.current_interval_remaining_percent
        $wRemain = [int]$m.current_weekly_remaining_percent
        # remains_time / weekly_remains_time come back in ms, not s.
        $iReset  = [TimeSpan]::FromMilliseconds([double]$m.remains_time)
        $wReset  = [TimeSpan]::FromMilliseconds([double]$m.weekly_remains_time)

        $flags = New-Object System.Collections.Generic.List[string]
        $iRatio = $null
        if ($m.current_interval_total_count -gt 0 -and $intervalTotal.TotalSeconds -gt 0) {
            $fracElapsed = $intervalElapsed.TotalSeconds / $intervalTotal.TotalSeconds
            if ($fracElapsed -gt 0) {
                $fracUsed = [double]$m.current_interval_usage_count / [double]$m.current_interval_total_count
                $iRatio = $fracUsed / $fracElapsed
            }
        }
        $wRatio = $null
        if ($m.current_weekly_total_count -gt 0 -and $weeklyTotal.TotalSeconds -gt 0) {
            $fracElapsed = $weeklyElapsed.TotalSeconds / $weeklyTotal.TotalSeconds
            if ($fracElapsed -gt 0) {
                $fracUsed = [double]$m.current_weekly_usage_count / [double]$m.current_weekly_total_count
                $wRatio = $fracUsed / $fracElapsed
            }
        }
        if ($null -ne $iRatio -and $iRatio -gt $BurnWarnRatio) { $flags.Add('INTERVAL BURN > LINEAR') }
        if ($null -ne $wRatio -and $wRatio -gt $BurnWarnRatio) { $flags.Add('WEEKLY BURN > LINEAR') }

        if ($m.current_interval_total_count -gt 0) {
            $iUsedStr = '{0}/{1} (burn {2:N2}x)' -f $m.current_interval_usage_count, $m.current_interval_total_count, $iRatio
        } else {
            $iUsedStr = '-'
        }
        if ($m.current_weekly_total_count -gt 0) {
            $wUsedStr = '{0}/{1} (burn {2:N2}x)' -f $m.current_weekly_usage_count, $m.current_weekly_total_count, $wRatio
        } else {
            $wUsedStr = '-'
        }

        $rows.Add([pscustomobject]@{
            Model              = $m.model_name
            Interval_Remaining = ('{0}%' -f $iRemain)
            Interval_Reset     = (Format-Duration $iReset)
            Interval_Used      = $iUsedStr
            Weekly_Remaining   = ('{0}%' -f $wRemain)
            Weekly_Reset       = (Format-Duration $wReset)
            Weekly_Used        = $wUsedStr
            Alerts             = ($flags -join ', ')
        })
    }
    $rows | Format-Table -AutoSize -Wrap | Out-Host

    Write-Section 'Concerns (MiniMax)'
    $concerns = New-Object System.Collections.Generic.List[string]
    foreach ($m in $resp.model_remains) {
        $name    = [string]$m.model_name
        $iRemain = [int]$m.current_interval_remaining_percent
        $wRemain = [int]$m.current_weekly_remaining_percent
        $iReset  = [TimeSpan]::FromMilliseconds([double]$m.remains_time)
        if ($iRemain -le $CriticalPercent) {
            $concerns.Add(('[CRITICAL] {0}: only {1}% left in current interval' -f $name, $iRemain))
        } elseif ($iRemain -le $LowPercent) {
            $concerns.Add(('[LOW]      {0}: {1}% left in current interval' -f $name, $iRemain))
        }
        if ($wRemain -le $CriticalPercent) {
            $concerns.Add(('[CRITICAL] {0}: only {1}% left this week' -f $name, $wRemain))
        } elseif ($wRemain -le $LowPercent) {
            $concerns.Add(('[LOW]      {0}: {1}% left this week' -f $name, $wRemain))
        }
        if ($iReset.TotalSeconds -gt 0 -and $iReset.TotalHours -le $ResetWarnHours) {
            $concerns.Add(('[INFO]     {0}: interval resets in {1}' -f $name, (Format-Duration $iReset)))
        }
    }
    if ($concerns.Count -eq 0) {
        Write-Host '  No concerns flagged.' -ForegroundColor Green
    } else {
        foreach ($c in $concerns) { Write-Host ('  - ' + $c) -ForegroundColor Yellow }
    }

    return $resp
}

# --- Get-ZaiUsage ----------------------------------------------------------
# Hits Z.AI's three monitoring endpoints (model-usage, tool-usage,
# quota/limit) over the last 24h, prints summaries, flags spikes and
# threshold breaches. Stashes the three responses in
# $Global:zaiLastQuery as @{ Model; Tool; Quota } and returns the
# hashtable.

function Get-ZaiUsage {
<#
.SYNOPSIS
    Queries Z.AI's model-usage, tool-usage, and quota-limit endpoints over
    the trailing 24 hours.
.DESCRIPTION
    Calls api.z.ai with the bearer token in $env:Z_AI_AUTH_TOKEN over a
    yesterday-at-current-hour to end-of-current-hour window. Prints model
    and tool usage totals, hourly averages, peak hours, hourly spikes
    (configurable multiplier), and quota usage with reset times. Stores
    the three responses in $Global:zaiLastQuery as @{ Model; Tool; Quota }
    and returns the same.
.PARAMETER Token
    Z.AI auth token. Defaults to $env:Z_AI_AUTH_TOKEN.
.PARAMETER McpWarnPercent
    Quota-percent threshold for the MCP/month window.
.PARAMETER TokenWarnPercent
    Quota-percent threshold for the 5-hour token window.
.PARAMETER SpikeRatio
    Multiplier used to flag hourly tool-usage spikes.
.PARAMETER All
    When supplied, prints the raw API responses inline. Otherwise the
    raw responses stay in $Global:zaiLastQuery.
.EXAMPLE
    Get-ZaiUsage
.EXAMPLE
    Get-ZaiUsage -McpWarnPercent 50 -All
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    [CmdletBinding()]
    param(
        [string]$Token = $env:Z_AI_AUTH_TOKEN,
        [int]$McpWarnPercent = 80,
        [int]$TokenWarnPercent = 80,
        [double]$SpikeRatio = 3.0,
        [switch]$All
    )

    if (-not $Token) { Write-Error 'Z_AI_AUTH_TOKEN not set (env var or -Token).'; return }

    $base = 'https://api.z.ai'
    $now  = Get-Date
    # Time window matches the upstream skill: yesterday at the current
    # hour through end of the current hour.
    $start = Get-Date $now.AddDays(-1).Date.AddHours($now.Hour) -Format 'yyyy-MM-dd HH:mm:ss'
    $end   = Get-Date $now.Date.AddHours($now.Hour).AddMinutes(59).AddSeconds(59) -Format 'yyyy-MM-dd HH:mm:ss'
    $q = "?startTime=$([uri]::EscapeDataString($start))&endTime=$([uri]::EscapeDataString($end))"
    $headers = @{ Authorization = $Token; Accept = 'application/json' }

    function Invoke-Zai-Internal {
        param([string]$Path)
        try {
            return Invoke-RestMethod -Uri ($base + $Path) -Headers $headers -Method GET
        } catch {
            Write-Error "API call failed for $Path`: $($_.Exception.Message)"
            return $null
        }
    }

    $modelResp = Invoke-Zai-Internal "/api/monitor/usage/model-usage$q"
    $toolResp  = Invoke-Zai-Internal "/api/monitor/usage/tool-usage$q"
    $quotaResp = Invoke-Zai-Internal '/api/monitor/usage/quota/limit'

    $Global:zaiLastQuery = @{
        Model = $modelResp
        Tool  = $toolResp
        Quota = $quotaResp
    }

    Write-Section 'Raw API responses (Z.AI)'
    if ($All) {
        Write-Host '--- model-usage ---'
        if ($modelResp) { $modelResp | ConvertTo-Json -Depth 8 | Out-Host } else { Write-Host '(no response)' }
        Write-Host ''
        Write-Host '--- tool-usage ---'
        if ($toolResp) { $toolResp | ConvertTo-Json -Depth 8 | Out-Host } else { Write-Host '(no response)' }
        Write-Host ''
        Write-Host '--- quota/limit ---'
        if ($quotaResp) { $quotaResp | ConvertTo-Json -Depth 8 | Out-Host } else { Write-Host '(no response)' }
    } else {
        Write-Host '  (suppressed; stored in $Global:zaiLastQuery as @{ Model; Tool; Quota }.' -ForegroundColor DarkGray
        Write-Host '   Use -All to display inline.)' -ForegroundColor DarkGray
    }

    $modelData = Unwrap-ZaiData $modelResp
    $toolData  = Unwrap-ZaiData $toolResp
    $quotaData = Unwrap-ZaiData $quotaResp

    Write-Section 'Model usage summary (Z.AI, last 24h)'
    if ($modelData) {
        $callStats = Get-SeriesStats $modelData.x_time $modelData.modelCallCount
        $tokStats  = Get-SeriesStats $modelData.x_time $modelData.tokensUsage
        [pscustomobject]@{
            Total_Calls    = $callStats.Total
            Hourly_Avg     = ('{0:N2}' -f $callStats.Avg)
            Peak_Calls     = ('{0} at {1}' -f $callStats.Peak, $callStats.PeakHour)
            Total_Tokens   = $tokStats.Total
            Hourly_Tok_Avg = ('{0:N0}' -f $tokStats.Avg)
            Peak_Tokens    = ('{0} at {1}' -f $tokStats.Peak, $tokStats.PeakHour)
        } | Format-Table -AutoSize | Out-Host
    } else {
        Write-Host '  (no data)' -ForegroundColor DarkGray
    }

    Write-Section 'Tool usage summary (Z.AI, last 24h)'
    if ($toolData) {
        $netStats = Get-SeriesStats $toolData.x_time $toolData.networkSearchCount
        $webStats = Get-SeriesStats $toolData.x_time $toolData.webReadMcpCount
        $zreStats = Get-SeriesStats $toolData.x_time $toolData.zreadMcpCount
        [pscustomobject]@{
            Tool       = 'network-search (search-prime)'
            Total      = $netStats.Total
            Hourly_Avg = ('{0:N2}' -f $netStats.Avg)
            Peak       = ('{0} at {1}' -f $netStats.Peak, $netStats.PeakHour)
        },
        [pscustomobject]@{
            Tool       = 'web-reader'
            Total      = $webStats.Total
            Hourly_Avg = ('{0:N2}' -f $webStats.Avg)
            Peak       = ('{0} at {1}' -f $webStats.Peak, $webStats.PeakHour)
        },
        [pscustomobject]@{
            Tool       = 'zread'
            Total      = $zreStats.Total
            Hourly_Avg = ('{0:N2}' -f $zreStats.Avg)
            Peak       = ('{0} at {1}' -f $zreStats.Peak, $zreStats.PeakHour)
        } | Format-Table -AutoSize | Out-Host

        $spikes = @()
        $spikes += Get-Spikes $toolData.x_time $toolData.networkSearchCount $netStats.Avg $SpikeRatio
        $spikes += Get-Spikes $toolData.x_time $toolData.webReadMcpCount   $webStats.Avg $SpikeRatio
        $spikes += Get-Spikes $toolData.x_time $toolData.zreadMcpCount     $zreStats.Avg $SpikeRatio
        if ($spikes.Count -gt 0) {
            Write-Host ''
            Write-Host ('  Spikes (> {0:N1}x hourly avg):' -f $SpikeRatio)
            $spikes | ForEach-Object { Write-Host ('    {0}  ->  {1}' -f $_.Hour, $_.Value) }
        } else {
            Write-Host ''
            Write-Host ('  No hourly spikes above {0:N1}x average.' -f $SpikeRatio) -ForegroundColor DarkGray
        }
    } else {
        Write-Host '  (no data)' -ForegroundColor DarkGray
    }

    Write-Section 'Quota summary (Z.AI)'
    if ($quotaData -and $quotaData.limits) {
        # Use the API's nextResetTime when present, else fall back to a
        # label derived from the (unit, number) pair. unit codes
        # observed: 3=hours, 5=months.
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($lim in $quotaData.limits) {
            $type  = [string]$lim.type
            $pct   = if ($null -ne $lim.percentage) { [int]$lim.percentage } else { 0 }
            $cur   = $lim.currentValue
            $tot   = $lim.usage
            $used  = if ($null -eq $cur) { 'n/a' } else { [string]$cur }
            $limit = if ($null -eq $tot) { 'n/a' } else { [string]$tot }
            $reset = 'n/a'
            if ($lim.PSObject.Properties['nextResetTime'] -and $null -ne $lim.nextResetTime) {
                $resetDt = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$lim.nextResetTime).LocalDateTime
                $delta   = $resetDt - (Get-Date)
                $reset   = ('{0} ({1} from now)' -f $resetDt.ToString('yyyy-MM-dd HH:mm'), (Format-Duration $delta))
            } elseif ($lim.PSObject.Properties['unit'] -and $lim.PSObject.Properties['number']) {
                $unitName = switch ([int]$lim.unit) {
                    3 { 'h' }
                    5 { 'mo' }
                    default { "unit$($lim.unit)" }
                }
                $reset = ('{0} {1} (window)' -f $lim.number, $unitName)
            }
            $rows.Add([pscustomobject]@{
                Type    = $type
                Used    = $used
                Limit   = $limit
                Percent = ('{0}%' -f $pct)
                Reset   = $reset
            })
        }
        $rows | Format-Table -AutoSize -Wrap | Out-Host
    } else {
        Write-Host '  (no data)' -ForegroundColor DarkGray
    }

    Write-Section 'Concerns (Z.AI)'
    $concerns = New-Object System.Collections.Generic.List[string]
    if ($quotaData -and $quotaData.limits) {
        foreach ($lim in $quotaData.limits) {
            $pct  = if ($null -ne $lim.percentage) { [int]$lim.percentage } else { 0 }
            $type = [string]$lim.type
            if ($type -match 'TOKEN' -and $pct -ge $TokenWarnPercent) {
                $concerns.Add(('[HIGH] Token window: {0}% used (>= {1}%)' -f $pct, $TokenWarnPercent))
            }
            if (($type -match 'TIME_LIMIT' -or $type -match 'MCP') -and $pct -ge $McpWarnPercent) {
                $concerns.Add(('[HIGH] MCP/month window: {0}% used (>= {1}%)' -f $pct, $McpWarnPercent))
            }
        }
    }
    if ($toolData) {
        foreach ($seriesName in @('networkSearchCount', 'webReadMcpCount', 'zreadMcpCount')) {
            $stats = Get-SeriesStats $toolData.x_time $toolData.$seriesName
            $spikes = Get-Spikes $toolData.x_time $toolData.$seriesName $stats.Avg $SpikeRatio
            if ($spikes.Count -gt 0) {
                $concerns.Add(('[SPIKE] {0}: {1} hour(s) above {2:N1}x hourly avg' -f $seriesName, $spikes.Count, $SpikeRatio))
            }
        }
    }
    if ($concerns.Count -eq 0) {
        Write-Host '  No concerns flagged.' -ForegroundColor Green
    } else {
        foreach ($c in $concerns) { Write-Host ('  - ' + $c) -ForegroundColor Yellow }
    }

    return $Global:zaiLastQuery
}

# --- Get-DeepseekUsage -----------------------------------------------------
# Queries DeepSeek's user-balance endpoint and estimates the token budget
# remaining under V4 Flash / V4 Pro pricing for each currency with a
# non-zero balance. Stashes the parsed response in
# $Global:deepseekLastQuery and returns it.

function Get-DeepseekUsage {
<#
.SYNOPSIS
    Queries DeepSeek's user-balance endpoint and estimates remaining token
    budget under V4 Flash / V4 Pro pricing.
.DESCRIPTION
    Calls https://api.deepseek.com/user/balance with the API key in
    $env:DEEPSEEK_API_KEY, prints the per-currency balances, and for each
    currency with a non-zero balance projects the token count available
    under every (model, scenario) pricing row in the embedded $pricing
    table. Flags concerns when the account is unavailable or balances
    are at or below threshold. Stores the parsed response in
    $Global:deepseekLastQuery and returns it.
.PARAMETER ApiKey
    DeepSeek API key. Defaults to $env:DEEPSEEK_API_KEY.
.PARAMETER LowBalanceUsd
    USD-balance threshold below which a LOW concern is raised.
.PARAMETER LowBalanceCny
    CNY-balance threshold below which a LOW concern is raised.
.PARAMETER All
    When supplied, prints the raw API response inline. Otherwise the raw
    response stays in $Global:deepseekLastQuery.
.EXAMPLE
    Get-DeepseekUsage
.EXAMPLE
    $d = Get-DeepseekUsage
    $d.balance_infos | Where-Object { $_.currency -eq 'CNY' }
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    [CmdletBinding()]
    param(
        [string]$ApiKey = $env:DEEPSEEK_API_KEY,
        [double]$LowBalanceUsd = 5.0,
        [double]$LowBalanceCny = 35.0,
        [switch]$All
    )

    # Pricing per 1M tokens (cache_hit, cache_miss, output) for V4 Flash/Pro.
    # Source: api-docs.deepseek.com/quick_start/pricing. Update these rows
    # if pricing changes upstream.
    $pricing = @(
        [pscustomobject]@{ Model = 'V4 Flash'; Scenario = 'Input  (cache hit)';  CostUsd = 0.0028;   CostCny = 0.02 }
        [pscustomobject]@{ Model = 'V4 Flash'; Scenario = 'Input  (cache miss)'; CostUsd = 0.14;     CostCny = 1.0 }
        [pscustomobject]@{ Model = 'V4 Flash'; Scenario = 'Output';              CostUsd = 0.28;     CostCny = 2.0 }
        [pscustomobject]@{ Model = 'V4 Pro';   Scenario = 'Input  (cache hit)';  CostUsd = 0.003625; CostCny = 0.025 }
        [pscustomobject]@{ Model = 'V4 Pro';   Scenario = 'Input  (cache miss)'; CostUsd = 0.435;    CostCny = 3.0 }
        [pscustomobject]@{ Model = 'V4 Pro';   Scenario = 'Output';              CostUsd = 0.87;     CostCny = 6.0 }
    )

    if (-not $ApiKey) { Write-Error 'DEEPSEEK_API_KEY not set (env var or -ApiKey).'; return }

    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $ApiKey"
    }
    try {
        $resp = Invoke-RestMethod -Uri 'https://api.deepseek.com/user/balance' -Headers $headers -Method GET
    } catch {
        Write-Error "API call failed: $($_.Exception.Message)"
        return
    }

    $Global:deepseekLastQuery = $resp

    Write-Section 'Raw API response (DeepSeek)'
    if ($All) { $resp | ConvertTo-Json -Depth 8 | Out-Host }
    else      { Write-Host '  (suppressed; stored in $Global:deepseekLastQuery. Use -All to display inline.)' -ForegroundColor DarkGray }

    $balances = @{}
    foreach ($b in $resp.balance_infos) {
        $balances[[string]$b.currency] = [double]$b.total_balance
    }

    Write-Section 'Balance summary (DeepSeek)'
    $balanceRows = foreach ($b in $resp.balance_infos) {
        [pscustomobject]@{
            Currency     = [string]$b.currency
            Total        = [double]$b.total_balance
            Granted      = [double]$b.granted_balance
            Topped_Up    = [double]$b.topped_up_balance
            Is_Available = [bool]$resp.is_available
        }
    }
    $balanceRows | Format-Table -AutoSize | Out-Host

    $hasAny = $false
    foreach ($cur in @('USD', 'CNY')) {
        if (-not $balances.ContainsKey($cur)) { continue }
        $bal = $balances[$cur]
        if ($bal -le 0) { continue }
        $hasAny = $true
        $rows = New-Object System.Collections.Generic.List[object]
        $costKey = 'Cost' + $cur
        foreach ($p in $pricing) {
            $cost   = [double]$p.$costKey
            $tokens = if ($cost -gt 0) { $bal / $cost * 1e6 } else { 0 }
            $rows.Add([pscustomobject]@{
                Model            = $p.Model
                Scenario         = $p.Scenario
                Cost_per_1M      = ('{0} {1}' -f $cur, (Format-Price $cost))
                Available_Tokens = (Format-Tokens $tokens)
            })
        }
        $title = if ($cur -eq 'USD') { 'Estimated USD token budget (DeepSeek)' } else { 'Estimated CNY token budget (DeepSeek)' }
        Write-Section $title
        $rows | Format-Table -AutoSize -Wrap | Out-Host
    }
    if (-not $hasAny) {
        Write-Section 'Estimated token budget (DeepSeek)'
        Write-Host '  (no USD or CNY balance > 0 reported)' -ForegroundColor DarkGray
    }
    Write-Host ('  Estimate formula: tokens = balance / cost_per_1M * 1,000,000.') -ForegroundColor DarkGray
    Write-Host ('  Actual spend depends on cache-hit ratio, prompt size, output length, and model mix.') -ForegroundColor DarkGray

    Write-Section 'Concerns (DeepSeek)'
    $concerns = New-Object System.Collections.Generic.List[string]
    if (-not [bool]$resp.is_available) {
        $concerns.Add('[CRITICAL] is_available=false: account cannot make API calls')
    }
    if ($balances.ContainsKey('USD') -and $balances['USD'] -le $LowBalanceUsd) {
        $concerns.Add(('[LOW] USD balance ${0:N2} at or below threshold ${1:N2}' -f $balances['USD'], $LowBalanceUsd))
    }
    if ($balances.ContainsKey('CNY') -and $balances['CNY'] -le $LowBalanceCny) {
        $concerns.Add(('[LOW] CNY balance {0:N2} at or below threshold {1:N2}' -f $balances['CNY'], $LowBalanceCny))
    }
    if ($balances.Count -gt 0) {
        $total = ($balances.Values | Measure-Object -Sum).Sum
        if ($total -le 0) {
            $concerns.Add('[CRITICAL] All reported balances are zero')
        }
    }
    if ($concerns.Count -eq 0) {
        Write-Host '  No concerns flagged.' -ForegroundColor Green
    } else {
        foreach ($c in $concerns) { Write-Host ('  - ' + $c) -ForegroundColor Yellow }
    }

    return $resp
}

# Auto-load vault credentials at profile load time so every session starts with
# keys available. Uses -Quiet to avoid printing key counts in transient shells.
Load-AiApiKeysFromCS -Quiet
