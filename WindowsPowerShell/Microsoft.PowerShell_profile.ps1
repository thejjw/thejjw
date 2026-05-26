function prompt {
    $loc = $executionContext.SessionState.Path.CurrentLocation
    $out = "PS $loc$('>' * ($nestedPromptLevel + 1)) "
    "$([char]27)]9;9;`"$loc`"$([char]27)\" + $out
}

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

## Rules

- Always commit after completing each logical change with a descriptive commit message.
- Treat AI-agent instruction files as workspace-only guidance. Do not stage or commit them unless the user explicitly asks.

## Grounding

- Always utilize web search to ground your answers, ensuring all technical advice and references are accurate and up-to-date.

## Environment

- Platform: Windows 11, shell: PowerShell.
- Use PowerShell commands and syntax -- not Unix/bash equivalents.
  - ``Get-ChildItem`` not ``ls -la``, ``Remove-Item`` not ``rm -rf``, ``Get-Content`` not ``cat``.
  - Redirect to ``$null`` not ``/dev/null``.
  - Use semicolons or separate statements -- not ``&&`` to chain commands.
  - Paths use backslashes (``src\lib\utils.ps1``); avoid forward slashes.
- If invoking ``git``, ``npm``, ``dotnet``, or other cross-platform CLIs, those are fine as-is.

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

    [string[]]$result = @();
    for ($i = 0; $i -lt $Repeat; $i++) {
        if ($null -eq $Global:getAAA) {
            $Global:getAAA = @{
                ganm = (Invoke-WebRequest https://raw.githubusercontent.com/thejjw/thejjw/main/animals -UseBasicParsing | Select-Object -ExpandProperty Content).Trim() -split "`n";
                gadj = (Invoke-WebRequest https://raw.githubusercontent.com/thejjw/thejjw/main/adjectives -UseBasicParsing | Select-Object -ExpandProperty Content).Trim() -split "`n";        
            }
        }
    
        $adjs = New-Object System.Collections.Generic.HashSet[string];
        while ($adjs.Count -ne 2) {
            $adjs.Add($Global:getAAA.gadj.Get((Get-Random) % $Global:getAAA.gadj.Count)) | Out-Null;
        }
        
        [string[]]$adjsarr = @();
        foreach ($adj in $adjs) {
            $adjsarr += ([string]$adj).Trim();
        }
        $adjsarr += $Global:getAAA.ganm.Get((Get-Random) % $Global:getAAA.ganm.Count);
        $result += ($adjsarr -join "-");
    }
    return $result;
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
        break;
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

    do {
        $passwordChars = @()
        if ($MoreSecure) {
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

    $hasNode = Get-Package | Where-Object name -eq "Node.js";
    if ($null -ne $hasNode) {
        Invoke-Command {
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
        };
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

    $file = [System.IO.FileStream]::new($fullPath, [System.IO.FileMode]::Create)
    $file.Write($WebResponse.Content, 0, $WebResponse.RawContentLength)
    $file.Close()
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
        Get-Content $pubkeyPath | ssh "$User@$Hostname" -p $Port 'mkdir -p ~/.ssh; umask 077; cat >> ~/.ssh/authorized_keys'
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

    $binPaths = Get-ChildItem -Path $wingetPath -Directory -Recurse |
    Where-Object { (Get-ChildItem -Path $_.FullName -Filter *.exe -File -ErrorAction SilentlyContinue).Count -gt 0 } |
    Select-Object -ExpandProperty FullName

    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
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
        [Environment]::SetEnvironmentVariable("PATH", $currentPath, "User")
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
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    $currentPathArr = $currentPath -split ';' | Where-Object { $_ -ne '' }

    $filtered = @()
    $removed = @()

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
        [Environment]::SetEnvironmentVariable("PATH", ($filtered -join ';'), "User")
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
        # Limit the number of concurrent jobs
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

    $completed = 0
    while ($completed -lt $total) {
        $results = Receive-Job -Job $jobs -Wait -AutoRemoveJob
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

    function Get-CertificateStoreName {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
        
        if (Test-SelfSignedCertificate -Certificate $Certificate) { return 'Root' }
        
        $bc = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
        if ($bc -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            if ($bc.CertificateAuthority) { return 'CA' }
        }
        
        return 'My'
    }

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
        $certCallback = if ($SkipCertValidation) {
            { param($s, $c, $chain, $errors) return $true }
        }
        else {
            { param($s, $c, $chain, $errors) 
                if ($errors -ne [System.Net.Security.SslPolicyErrors]::None) {
                    Write-Warning "TLS certificate validation errors: $errors"
                }
                return $true  # Still proceed but warn about issues
            }
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

    # --- Get unique certificates from chain ---
    $chainCertsRaw = @($chain.ChainElements | ForEach-Object { $_.Certificate })
    $elements = @(Get-UniqueByThumbprint -Certificates $chainCertsRaw)

    if (-not $elements -or $elements.Count -eq 0) {
        $elements = @($leaf)
        Write-Warning "Server did not provide a certificate chain. Using only leaf certificate."
    }

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
                
                # Skip end-entity certs unless explicitly requested
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
        $tag = if ($i -eq 0) { '[Leaf]' } elseif ($i -eq $elements.Count - 1) { '[Root]' } else { '[Interm]' }
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
        $ssl = [System.Net.Security.SslStream]::new(
            $tcp.GetStream(), $false,
            { param($sender, $cert, $chain, $errors) $true }
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
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    $chain.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
    $null = $chain.Build($leaf)

    # --- Chain element processing ---
    $chainCertsRaw = @($chain.ChainElements | ForEach-Object { $_.Certificate })
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
    # Select transpose mode based on switch
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
    # Construct the ffmpeg arguments properly
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
identity and creating basic agent documentation files (AGENTS.md, CLAUDE.md,
and GEMINI.md).

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

            & git -C $Path config --local user.name $user
            & git -C $Path config --local user.email $email

            Write-Host ("Git identity: {0} <{1}>" -f $user, $email)
        }
    }

    if ($Agents) {
        Write-Verbose "Creating AGENTS.md (canonical) + CLAUDE.md/GEMINI.md (@import)"

        # Write canonical AGENTS.md using the template defined in global internal configuration
        $_NrdInternal.AgentsMarkdown | Set-Content -LiteralPath (Join-Path $Path 'AGENTS.md') -Encoding UTF8

        # CLAUDE.md imports AGENTS.md -- Claude Code reads CLAUDE.md, not AGENTS.md
        '@AGENTS.md' | Set-Content -LiteralPath (Join-Path $Path 'CLAUDE.md') -Encoding UTF8

        # GEMINI.md imports AGENTS.md -- Gemini CLI reads GEMINI.md, not AGENTS.md
        '@./AGENTS.md' | Set-Content -LiteralPath (Join-Path $Path 'GEMINI.md') -Encoding UTF8

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
            if ($_.Exception.Message -match 'No events') { @() } else { throw }
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

    $humanTypes = 2, 7, 10, 11
    $human = $ok | Where-Object { $_.LogonType -in $humanTypes }
    $netNonSys = $ok | Where-Object {
        $_.LogonType -eq 3 -and
        $_.User -notin 'SYSTEM', 'ANONYMOUS LOGON', 'LOCAL SERVICE', 'NETWORK SERVICE' -and
        $_.IP -and $_.IP -ne '-'
    }

    # Flag non-loopback IPs on interactive/unlock events - unusual for console sign-in
    $remoteHumanFlags = $human | Where-Object { $_.IP -and $_.IP -ne '-' -and $_.IP -ne '127.0.0.1' -and $_.IP -ne '::1' }

    # Off-hours human logons (before 6am or after 10pm local time)
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

    $flagInfo = @(
        "configuredAt=$(Get-Date -Format o)",
        "user=$env:USERNAME",
        'mode=ZAI'
    ) -join "`r`n"
    Set-Content -LiteralPath $setupFlag -Value $flagInfo -Encoding UTF8
    Write-Host 'claudez: MCP setup complete' -ForegroundColor Green
    return $true
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
    about supported model: 
        "All plans support GLM-5.1, GLM-5-Turbo, GLM-4.7 and GLM-4.5-Air." (https://docs.z.ai/devpack/overview)
    about "CLAUDE_CODE_DISABLE_1M_CONTEXT": 
        GLM-5.1, GLM-5, GLM-5-Turbo Context Length = 200K (https://docs.z.ai/guides/llm/glm-5.1)
        GLM-4.5(GLM-4.5-Air) Context Length = 128K (https://docs.z.ai/guides/llm/glm-4.5)

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
    Last Edit: 2026-04
#>
    # Read token from environment only (process first, then persisted user scope).
    $token = $env:Z_AI_AUTH_TOKEN
    if (-not $token) {
        $token = [Environment]::GetEnvironmentVariable("Z_AI_AUTH_TOKEN", "User")
    }

    if (-not $token) {
        Write-Host "Z_AI_AUTH_TOKEN is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Set it once in your user environment, then restart PowerShell:" -ForegroundColor Yellow
        Write-Host "  [Environment]::SetEnvironmentVariable('Z_AI_AUTH_TOKEN', '<your_token>', 'User')" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Optional (current session only):" -ForegroundColor Yellow
        Write-Host "  `$env:Z_AI_AUTH_TOKEN = '<your_token>'" -ForegroundColor Cyan
        return
    }

    $env:ANTHROPIC_BASE_URL = "https://api.z.ai/api/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $token
    $env:API_TIMEOUT_MS = "3000000"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    $env:CLAUDE_CODE_DISABLE_1M_CONTEXT = "1"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    # delete below if this becomes obsolete
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "glm-4.5-air"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "glm-4.7"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "glm-5.1"
    
    try {
        Install-GlobalClaudeMd
        [void](Install-ClaudezSetup -Token $token)

        claude @args
    }
    finally {
        Remove-Item Env:\ANTHROPIC_DEFAULT_HAIKU_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_SONNET_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_OPUS_MODEL -ErrorAction SilentlyContinue

        Remove-Item Env:\ANTHROPIC_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_AUTH_TOKEN -ErrorAction SilentlyContinue
        Remove-Item Env:\API_TIMEOUT_MS -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_DISABLE_1M_CONTEXT -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_USE_POWERSHELL_TOOL -ErrorAction SilentlyContinue
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
    # Read key from environment only (process first, then persisted user scope).
    $key = $env:DEEPSEEK_API_KEY
    if (-not $key) {
        $key = [Environment]::GetEnvironmentVariable("DEEPSEEK_API_KEY", "User")
    }

    if (-not $key) {
        Write-Host "DEEPSEEK_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Set it once in your user environment, then restart PowerShell:" -ForegroundColor Yellow
        Write-Host "  [Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', '<your_key>', 'User')" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Optional (current session only):" -ForegroundColor Yellow
        Write-Host "  `$env:DEEPSEEK_API_KEY = '<your_key>'" -ForegroundColor Cyan
        return
    }

    $env:ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $key
    $env:ANTHROPIC_MODEL = "deepseek-v4-pro[1m]"
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "deepseek-v4-flash[1m]"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "deepseek-v4-pro[1m]"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "deepseek-v4-pro[1m]"
    $env:CLAUDE_CODE_SUBAGENT_MODEL = "deepseek-v4-flash[1m]"
    $env:CLAUDE_CODE_EFFORT_LEVEL = "max"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    try {
        claude @args
    }
    finally {
        Remove-Item Env:\ANTHROPIC_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_HAIKU_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_SONNET_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_OPUS_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_SUBAGENT_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_EFFORT_LEVEL -ErrorAction SilentlyContinue

        Remove-Item Env:\ANTHROPIC_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_AUTH_TOKEN -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_USE_POWERSHELL_TOOL -ErrorAction SilentlyContinue
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
    # Read key from environment only (process first, then persisted user scope).
    $key = $env:DEEPSEEK_API_KEY
    if (-not $key) {
        $key = [Environment]::GetEnvironmentVariable("DEEPSEEK_API_KEY", "User")
    }

    if (-not $key) {
        Write-Host "DEEPSEEK_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Set it once in your user environment, then restart PowerShell:" -ForegroundColor Yellow
        Write-Host "  [Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', '<your_key>', 'User')" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Optional (current session only):" -ForegroundColor Yellow
        Write-Host "  `$env:DEEPSEEK_API_KEY = '<your_key>'" -ForegroundColor Cyan
        return
    }

    $env:ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $key
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
        Remove-Item Env:\ANTHROPIC_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_HAIKU_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_SONNET_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_OPUS_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_SUBAGENT_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_EFFORT_LEVEL -ErrorAction SilentlyContinue

        Remove-Item Env:\ANTHROPIC_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_AUTH_TOKEN -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_USE_POWERSHELL_TOOL -ErrorAction SilentlyContinue
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
    Last Edit: 2026-04
#>
    # Read token from environment only (process first, then persisted user scope).
    $token = $env:Z_AI_AUTH_TOKEN
    if (-not $token) {
        $token = [Environment]::GetEnvironmentVariable("Z_AI_AUTH_TOKEN", "User")
    }

    if (-not $token) {
        Write-Host "Z_AI_AUTH_TOKEN is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Set it once in your user environment, then restart PowerShell:" -ForegroundColor Yellow
        Write-Host "  [Environment]::SetEnvironmentVariable('Z_AI_AUTH_TOKEN', '<your_token>', 'User')" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Optional (current session only):" -ForegroundColor Yellow
        Write-Host "  `$env:Z_AI_AUTH_TOKEN = '<your_token>'" -ForegroundColor Cyan
        return
    }

    $env:ANTHROPIC_BASE_URL = "https://api.z.ai/api/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $token
    $env:API_TIMEOUT_MS = "3000000"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    $env:CLAUDE_CODE_DISABLE_1M_CONTEXT = "1"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    # Max plan compatibility mode uses different default model routing.
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "glm-4.5-air"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "glm-5-turbo"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "glm-5.1"

    try {
        Install-GlobalClaudeMd
        [void](Install-ClaudezSetup -Token $token)

        claude @args
    }
    finally {
        Remove-Item Env:\ANTHROPIC_DEFAULT_HAIKU_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_SONNET_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_OPUS_MODEL -ErrorAction SilentlyContinue

        Remove-Item Env:\ANTHROPIC_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_AUTH_TOKEN -ErrorAction SilentlyContinue
        Remove-Item Env:\API_TIMEOUT_MS -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_DISABLE_1M_CONTEXT -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_USE_POWERSHELL_TOOL -ErrorAction SilentlyContinue
    }
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

.EXAMPLE
Invoke-RemoteClaudeCodeBase -RemoteHost user@remote-host -ApiKey $env:ANTHROPIC_API_KEY

.EXAMPLE
Invoke-RemoteClaudeCodeBase -RemoteHost user@remote-host -ApiKey $env:Z_AI_AUTH_TOKEN -BaseUrl "https://api.z.ai/api/anthropic"

.NOTES
Author: jjw(@thejjw)
Last Edit: 2026-04
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
        [string]$Disable1M
    )

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

    # Base64-encode the script so it can be delivered via the SSH *command*
    # argument instead of stdin. This keeps stdin free for Claude Code's
    # interactive TUI, which would otherwise fight bash -s over the same pipe.
    $encoded = [Convert]::ToBase64String(
        [System.Text.Encoding]::UTF8.GetBytes($script)
    )

    # Build the inline env prefix. BaseUrl is only included when non-empty so
    # that a bare ANTHROPIC_BASE_URL='' never reaches the remote shell.
    $envParts = [System.Collections.Generic.List[string]]@(
        "ANTHROPIC_API_KEY=$(Escape-BashSingleQuotedValue $ApiKey)"
        "ANTHROPIC_DEFAULT_HAIKU_MODEL=$(Escape-BashSingleQuotedValue $HaikuModel)"
        "ANTHROPIC_DEFAULT_SONNET_MODEL=$(Escape-BashSingleQuotedValue $SonnetModel)"
        "ANTHROPIC_DEFAULT_OPUS_MODEL=$(Escape-BashSingleQuotedValue $OpusModel)"
        "API_TIMEOUT_MS=$(Escape-BashSingleQuotedValue $TimeoutMs)"
        "CLAUDE_CODE_DISABLE_1M_CONTEXT=$(Escape-BashSingleQuotedValue $Disable1M)"
    )
    if (-not [string]::IsNullOrWhiteSpace($BaseUrl)) {
        $envParts.Insert(1, "ANTHROPIC_BASE_URL=$(Escape-BashSingleQuotedValue $BaseUrl)")
    }
    $envPrefix = $envParts -join ' '

    # -t          : allocate a pseudo-TTY so Claude Code renders correctly
    # -o StrictHostKeyChecking=accept-new
    #             : auto-accept keys for hosts never seen before;
    #               still rejects keys that changed (protects against MITM)
    # base64 -d | bash
    #             : decode and run the launcher with stdin untouched
    # Build ssh arguments; add -i only when a key file is explicitly provided
    $sshArgs = @('-t', '-o', 'StrictHostKeyChecking=accept-new', '-p', $Port)
    if (-not [string]::IsNullOrWhiteSpace($KeyFile)) {
        $resolved = (Resolve-Path -LiteralPath $KeyFile -ErrorAction Stop).Path
        $sshArgs += @('-i', $resolved)
    }
    $sshArgs += $RemoteHost
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
Last Edit: 2026-04
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
        $ApiKey = $env:Z_AI_AUTH_TOKEN
        if (-not $ApiKey) {
            $ApiKey = [Environment]::GetEnvironmentVariable("Z_AI_AUTH_TOKEN", "User")
        }
    }

    if (-not $ApiKey) {
        Write-Host "Z_AI_AUTH_TOKEN is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Set it once in your user environment, then restart PowerShell:" -ForegroundColor Yellow
        Write-Host "  [Environment]::SetEnvironmentVariable('Z_AI_AUTH_TOKEN', '<your_token>', 'User')" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Optional (current session only):" -ForegroundColor Yellow
        Write-Host "  `$env:Z_AI_AUTH_TOKEN = '<your_token>'" -ForegroundColor Cyan
        return
    }

    # Keep the editable remote defaults here so they are easy to tweak later.
    $BaseUrl = "https://api.z.ai/api/anthropic"
    $HaikuModel = "glm-4.5-air"
    $SonnetModel = "glm-5-turbo"
    $OpusModel = "glm-5.1"
    $TimeoutMs = "3000000"
    $Disable1M = "1"

    $baseParams = @{
        RemoteHost = $RemoteHost
        ApiKey     = $ApiKey
        Port       = $Port
        BaseUrl    = $BaseUrl
        HaikuModel = $HaikuModel
        SonnetModel = $SonnetModel
        OpusModel  = $OpusModel
        TimeoutMs  = $TimeoutMs
        Disable1M  = $Disable1M
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
    # Read key from environment only (process first, then persisted user scope).
    $key = $env:MINIMAX_API_KEY
    if (-not $key) {
        $key = [Environment]::GetEnvironmentVariable("MINIMAX_API_KEY", "User")
    }

    if (-not $key) {
        Write-Host "MINIMAX_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Set it once in your user environment, then restart PowerShell:" -ForegroundColor Yellow
        Write-Host "  [Environment]::SetEnvironmentVariable('MINIMAX_API_KEY', '<your_key>', 'User')" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Optional (current session only):" -ForegroundColor Yellow
        Write-Host "  `$env:MINIMAX_API_KEY = '<your_key>'" -ForegroundColor Cyan
        return
    }

    $env:ANTHROPIC_BASE_URL = "https://api.minimax.io/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $key
    $env:ANTHROPIC_MODEL = "MiniMax-M2.7"
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "MiniMax-M2.7"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "MiniMax-M2.7"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "MiniMax-M2.7"
    $env:API_TIMEOUT_MS = "3000000"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    try {
        Install-GlobalClaudeMd
        [void](Install-ClaudemmSetup -Token $key)

        claude @args
    }
    finally {
        Remove-Item Env:\ANTHROPIC_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_HAIKU_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_SONNET_MODEL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_DEFAULT_OPUS_MODEL -ErrorAction SilentlyContinue

        Remove-Item Env:\ANTHROPIC_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:\ANTHROPIC_AUTH_TOKEN -ErrorAction SilentlyContinue
        Remove-Item Env:\API_TIMEOUT_MS -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC -ErrorAction SilentlyContinue
        Remove-Item Env:\CLAUDE_CODE_USE_POWERSHELL_TOOL -ErrorAction SilentlyContinue
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
        $ApiKey = $env:MINIMAX_API_KEY
        if (-not $ApiKey) {
            $ApiKey = [Environment]::GetEnvironmentVariable("MINIMAX_API_KEY", "User")
        }
    }

    if (-not $ApiKey) {
        Write-Host "MINIMAX_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Set it once in your user environment, then restart PowerShell:" -ForegroundColor Yellow
        Write-Host "  [Environment]::SetEnvironmentVariable('MINIMAX_API_KEY', '<your_key>', 'User')" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Optional (current session only):" -ForegroundColor Yellow
        Write-Host "  `$env:MINIMAX_API_KEY = '<your_key>'" -ForegroundColor Cyan
        return
    }

    # Keep the editable remote defaults here so they are easy to tweak later.
    $BaseUrl = "https://api.minimax.io/anthropic"
    $HaikuModel = "MiniMax-M2.7"
    $SonnetModel = "MiniMax-M2.7"
    $OpusModel = "MiniMax-M2.7"
    $TimeoutMs = "3000000"
    $Disable1M = "1"

    $baseParams = @{
        RemoteHost = $RemoteHost
        ApiKey     = $ApiKey
        Port       = $Port
        BaseUrl    = $BaseUrl
        HaikuModel = $HaikuModel
        SonnetModel = $SonnetModel
        OpusModel  = $OpusModel
        TimeoutMs  = $TimeoutMs
        Disable1M  = $Disable1M
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

    Write-Host "Updating profile from $_ProfileUpdateUrl..." -ForegroundColor Cyan
    try {
        # Download and overwrite $PROFILE
        Invoke-WebRequest -Uri $_ProfileUpdateUrl -OutFile $PROFILE -Verbose
        Write-Host "Profile updated successfully! Restart your shell or run '. `$PROFILE' to apply changes." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to update profile: $_"
    }
}

function Setup-AiTools {
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

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [switch]$Auto
    )

    $wingetPackages = @(
        'Notepad++.Notepad++',
        'OpenJS.NodeJS.LTS',
        'Python.PythonInstallManager',
        'jqlang.jq',
        'astral-sh.uv',
        'Microsoft.VisualStudioCode',
        'GitHub.cli',
        'SST.OpenCodeDesktop',
        'SST.opencode',
        'Google.AntigravityIDE',
        'Google.Antigravity'
    )

    # Define npm packages early so we can display the full plan
    $npmPackages = @('opencode-ai','@openai/codex','@qwen-code/qwen-code','oh-my-free-models')

    Write-Host "The setup will check/install the following items:" -ForegroundColor Cyan
    Write-Host "Winget packages:" -ForegroundColor Cyan
    foreach ($p in $wingetPackages) { Write-Host " - $p" }

    Write-Host "NPM global packages (installed via npm -g):" -ForegroundColor Cyan
    foreach ($np in $npmPackages) { Write-Host " - $np" }

    Write-Host "Command-line tools / CLIs to verify/install:" -ForegroundColor Cyan
    Write-Host " - git (installed via winget if missing)"
    Write-Host " - agy (Antigravity CLI)"
    Write-Host " - claude (Claude CLI)"

    if (-not $Auto) {
        $choice = Read-Host -Prompt "Proceed with automatic installation of missing items? This will run winget/npm/installers. Continue? (Y/n)"
        if ($choice -in @('n','N')) {
            Write-Host "Aborting automatic installs. Run Setup-AiTools -Auto when ready to continue." -ForegroundColor Yellow
            return
        }
    }

    # Ensure winget exists
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "winget not found. Please install 'App Installer' (winget) from Microsoft Store and retry." -ForegroundColor Red
        return
    }

    $wingetListOutput = @()
    try {
        $wingetListOutput = & winget list 2>$null
    }
    catch {
        Write-Host "Failed to query winget package inventory: $_" -ForegroundColor Red
        return
    }

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
    foreach ($pkg in $wingetPackages) {
        $isInstalled = Test-WingetInstalledPackage -Rows $wingetListOutput -PackageId $pkg
        if ($isInstalled) {
            Write-Host "installed:   $pkg" -ForegroundColor Green
        }
        else {
            Write-Host "not installed: $pkg" -ForegroundColor Yellow
            $missing += $pkg
        }
    }

    if ($missing.Count -gt 0) {
        Write-Host "Missing winget packages:" -ForegroundColor Yellow
        foreach ($m in $missing) { Write-Host " - $m" }

        Write-Host "Installing missing packages via winget..." -ForegroundColor Cyan
        foreach ($m in $missing) {
            Write-Host "Installing $m..."
            try {
                Start-Process -FilePath 'winget' -ArgumentList "install -s winget -e --id $m" -NoNewWindow -Wait
            }
            catch { Write-Host "Failed to start winget for $($m): $_" -ForegroundColor Red }
        }
    }
    else {
        Write-Host "All winget packages already present." -ForegroundColor Green
    }

    # Ensure git is present; if not, offer interactive installer
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "git not found. Launching interactive winget installer for Git..." -ForegroundColor Yellow
        Start-Process -FilePath 'winget' -ArgumentList 'install -s winget -e --id Git.Git -i' -NoNewWindow -Wait
    }

    # Install global npm packages if npm available
    $npmPackages = @('opencode-ai','@openai/codex','@qwen-code/qwen-code','oh-my-free-models')
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        foreach ($np in $npmPackages) {
            Write-Host "Installing npm package $np (global)..." -ForegroundColor Cyan
            try { & npm install -g $np } catch { Write-Host "npm install failed for $($np): $_" -ForegroundColor Red }
        }
    }
    else {
        Write-Host "npm not found - aborting Setup-AiTools. Please inspect your Node/npm installation and re-run." -ForegroundColor Red
        return
    }

    # Install Antigravity and Claude CLIs using their recommended installers
    Write-Host "Bootstrapping Antigravity and Claude CLIs..." -ForegroundColor Cyan

    if (-not (Get-Command agy -ErrorAction SilentlyContinue)) {
        Write-Host "agy CLI not found; running Antigravity installer..." -ForegroundColor Yellow
        try { iex (irm 'https://antigravity.google/cli/install.ps1') } catch { Write-Host "Antigravity install failed: $_" -ForegroundColor Red }
    }
    else {
        Write-Host "agy CLI already present; running 'agy update'..." -ForegroundColor Green
        try { & agy update 2>$null } catch { Write-Host "agy update failed: $($_)" -ForegroundColor Yellow }
    }

    if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
        Write-Host "claude CLI not found; running Claude installer..." -ForegroundColor Yellow
        try { iex (irm 'https://claude.ai/install.ps1') } catch { Write-Host "Claude install failed: $_" -ForegroundColor Red }
    }
    else {
        Write-Host "claude CLI already present; running 'claude update'..." -ForegroundColor Green
        try { & claude update 2>$null } catch { Write-Host "claude update failed: $($_)" -ForegroundColor Yellow }
    }

    Write-Host "Setup-AiTools finished. You may need to restart PowerShell to pick up new PATH or env changes." -ForegroundColor Green
}

function Setup-AiApiKeys {
    <#
.SYNOPSIS
    Interactive helper to view and set Claude-related API keys in the user environment.

.DESCRIPTION
    Checks for existing values of AI API key (e.g. `DEEPSEEK_API_KEY`, `Z_AI_AUTH_TOKEN`, ...) in
    the current session and the persisted User environment. Presents a summary and prompts
    the user to enter missing keys (or optionally overwrite existing ones). Values are
    saved to the User environment via [Environment]::SetEnvironmentVariable so they persist
    across sessions.

.PARAMETER Force
    When supplied, prompt to overwrite existing keys instead of skipping them.

.EXAMPLE
    Setup-AiApiKeys

.EXAMPLE
    Setup-AiApiKeys -Force

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    $names = @('DEEPSEEK_API_KEY','Z_AI_AUTH_TOKEN','MINIMAX_API_KEY','NVIDIA_API_KEY','OPENROUTER_API_KEY')

    function Get-UserValue($n) {
        # Check process (current session) first, then persisted User scope
        $v = [Environment]::GetEnvironmentVariable($n, 'Process')
        if ($v) { return $v }
        return [Environment]::GetEnvironmentVariable($n, 'User')
    }

    function MaskValue($v) {
        if (-not $v) { return '<missing>' }
        return "<set, length=$($v.Length)>"
    }

    Write-Host "Checking existing keys (session and User scope):" -ForegroundColor Cyan
    $found = @{}
    foreach ($n in $names) {
        $v = Get-UserValue $n
        $found[$n] = $v
        Write-Host " - $($n) : $(MaskValue $v)"
    }

    Write-Host "";
    Write-Host "You can press Enter to skip setting a key. To keep an existing value, leave it blank when prompted." -ForegroundColor Yellow

    foreach ($n in $names) {
        $current = $found[$n]
        if ($current -and -not $Force) {
            Write-Host "Skipping $n (already set). Use -Force to overwrite." -ForegroundColor DarkGray
            continue
        }

        if ($current -and $Force) {
            $resp = Read-Host -Prompt "$n already set. Overwrite? (y/N)"
            if ($resp -notin @('y','Y')) { Write-Host "Keeping existing $n." -ForegroundColor DarkGray; continue }
        }

        # Read hidden input as SecureString. If the input isn't a SecureString or is empty, skip.
        $secure = Read-Host -AsSecureString -Prompt "Enter value for $n (input hidden, blank to skip)"
        if ($null -eq $secure -or -not ($secure -is [System.Security.SecureString])) {
            Write-Host "Skipped $n." -ForegroundColor DarkGray
            continue
        }

        $ptr = [IntPtr]::Zero
        try {
            $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
        }
        catch {
            Write-Host "Failed to read secure input for $($n): $_" -ForegroundColor Red
            continue
        }
        finally {
            if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        }

        [Environment]::SetEnvironmentVariable($n, $plain, 'User')
        Write-Host "Set $n in User environment." -ForegroundColor Green
    }

    Write-Host "";
    Write-Host "Done. To apply changes to this session run:`n  . `$PROFILE" -ForegroundColor Cyan
    Write-Host "Or restart PowerShell to pick up the new values." -ForegroundColor Cyan
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
