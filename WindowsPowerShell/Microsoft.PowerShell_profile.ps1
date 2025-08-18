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
        [Parameter(Mandatory=$true)]
        [string[]]
        $TargetProcesses
    )

    if($null -eq $Global:hasEWSType) {
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
        if($null -eq $Global:getAAA) {
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
        [Parameter(Mandatory=$true)]
        [string]
        $DomainOrIp,
        # key if not already set
        [Parameter(Mandatory=$false)]
        [string]
        $WhoisKisaApiKey = $Global:WhoisKisaApiKey
    )

    if($null -eq $WhoisKisaApiKey) {
        Write-Host 'Whois API key from KISA(후이즈검색.한국) not set. Please configure either -WhoisKisaApiKey parameter or $Global:WhoisKisaApiKey. Exiting...';
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
    if ($IncludeUpper)  { $charPool += $upper;  $required += $upper  }
    if ($IncludeLower)  { $charPool += $lower;  $required += $lower  }
    if ($IncludeDigit)  { $charPool += $digits; $required += $digits }
    if ($IncludeSpecial){ $charPool += $special; $required += $special}

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
            } else {
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
        } else {
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

const nodeCrypto = require('crypto');
global.crypto = {
    getRandomValues: function(buffer) { return nodeCrypto.randomFillSync(buffer);}
};

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
    } else {
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
    param (
        [Parameter(Mandatory=$true)]
        [string]$User,

        [Parameter(Mandatory=$true)]
        [string]$Hostname,

        [int]$Port = 22
    )
    # Prefer common public key filenames. This avoids false negatives when
    # ssh-keygen creates id_ed25519.pub (the modern default) instead of id_rsa.pub.
    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }

    $candidates = @('id_ed25519.pub','id_rsa.pub','id_ecdsa.pub','id_dsa.pub')
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

        # Prefer explicit path to ssh-keygen if available
        $sshCmd = (Get-Command ssh-keygen -ErrorAction SilentlyContinue)?.Source
        if (-not $sshCmd) { $sshCmd = 'ssh-keygen' }

        $sshArgs = @('-t','ed25519','-f',$privateKey,'-N','')
        try {
            $output = & $sshCmd @sshArgs 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "ssh-keygen failed (exit=$LASTEXITCODE): $([string]::Join("`n", $output))"
            }
        } catch {
            Write-Warning "Exception while running ssh-keygen: $_"
        }
    }

    if (Test-Path $pubkeyPath) {
        Write-Host "Sending public key $pubkeyPath to ${User}@${Hostname}:${Port} ..." -ForegroundColor Cyan
        # Ensure remote .ssh exists and append the public key; set umask to keep permissions strict.
        Get-Content $pubkeyPath | ssh "$User@$Hostname" -p $Port 'mkdir -p ~/.ssh; umask 077; cat >> ~/.ssh/authorized_keys'
        Write-Host " Public key installed on $Hostname" -ForegroundColor Green
    } else {
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
    } else {
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
    ✔ Removed the following winget directories from your user PATH:
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
        } else {
            $filtered += $p
        }
    }

    if ($removed.Count -eq 0) {
        Write-Host "No winget paths found in user PATH. Nothing to remove."
    } else {
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
    } else {
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
        [Parameter(Mandatory=$true)]
        [string]$AdapterName,
        [switch]$FullyRandom
    )

    # Generate MAC address
    if ($FullyRandom) {
        $octets = @(for ($i = 0; $i -lt 6; $i++) { (Get-Random -Minimum 0 -Maximum 256).ToString("x2") })
    } else {
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
        [Parameter(Mandatory=$true)]
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
                    [PSCustomObject]@{Status="Success"; Path=$imgPath}
                } else {
                    [PSCustomObject]@{Status="Fail"; Path=$imgPath}
                }
            } catch {
                [PSCustomObject]@{Status="Error"; Path=$imgPath; Message=$_}
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
                Write-Host ("[{0}] Converted [{1}] ({2}/{3}, {4}%) ({5} sec elapsed)" -f (Get-Date), $result.Path, $completed, $total, $pct, [math]::Round($elapsed.TotalSeconds,2))
            } elseif ($result.Status -eq "Fail") {
                Write-Warning "Conversion failed for $($result.Path)"
            } elseif ($result.Status -eq "Error") {
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
            } else {
                Write-Warning "Conversion failed for $($image.FullName)"
            }
        } catch {
            Write-Warning "Error converting $($image.FullName): $_"
        }
        $i++
        $pct = [math]::Round($i * 100 / $total, 2)
        $elapsed = (Get-Date) - $startTime
        Write-Host ("[{0}] Converted {1} of {2} images ({3}%) ({4} sec elapsed)" -f (Get-Date), $i, $total, $pct, [math]::Round($elapsed.TotalSeconds,2))
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
            } else {
                Write-Warning "Conversion failed for $($image.FullName)"
            }
        } catch {
            Write-Warning "Error converting $($image.FullName): $_"
        }
        $i++
        $pct = [math]::Round($i * 100 / $total, 2)
        $elapsed = (Get-Date) - $startTime
        Write-Host ("[{0}] Converted {1} of {2} images ({3}%) ({4} sec elapsed)" -f (Get-Date), $i, $total, $pct, [math]::Round($elapsed.TotalSeconds,2))
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
        [Parameter(Mandatory=$true)]
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

        [ValidateSet('Root','Intermediate','Leaf','All')]
        [string] $WhatToInstall = 'Root',

        [ValidateSet('X509Store','Certutil')]
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
        $thumb = $Certificate.Thumbprint -replace '\s',''
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
            } else {
                Write-Verbose $stdout.Trim()
            }
        } finally {
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
            { param($s,$c,$chain,$errors) return $true }
        } else {
            { param($s,$c,$chain,$errors) 
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
    } else {
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
    function Get-Intermediates { param($e) if ($e.Count -gt 2) { $e[1..($e.Count-2)] } else { @() } }

    # --- Select certificates to work with ---
    $toInstall = switch ($WhatToInstall) {
        'Root'         { @(Get-RootCert $elements) | Where-Object { $_ } }
        'Intermediate' { @(Get-Intermediates $elements) | Where-Object { $_ } }
        'Leaf'         { @($leaf) | Where-Object { $_ } }
        'All'          { $elements | Where-Object { $_ } }
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
            } else {
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
            } else {
                # Need to save to temp for certutil
                $tempDir = if (-not (Test-Path $OutDir)) {
                    $null = New-Item -ItemType Directory -Path $OutDir -Force
                    $OutDir
                } else { $OutDir }
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
                Subject = $cert.Subject
                Thumbprint = $cert.Thumbprint -replace '\s',''
                Type = $type
                Path = $path
                Store = $store
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
                $tag = if ($i -eq 0) {'[Leaf]'} elseif ($i -eq $elements.Count-1) {'[Root]'} else {'[Interm]'}
                Write-Host ("  ${tag} ${elements[$i].Subject} [${elements[$i].Thumbprint}]")
            }
            return $plan
        }

        # Install using certutil
        foreach ($item in $plan | Where-Object { $_.Store }) {
            try {
                Invoke-CertutilAddStore -StoreName $item.Store -CertificatePath $item.Path -MachineStore:$MachineStore
                Write-Host ("Installed via certutil: {0} -> {1}" -f (Split-Path -Leaf $item.Path), $item.Store)
            } catch {
                Write-Warning "Failed to install $($item.Path) into store $($item.Store): $($_.Exception.Message)"
            }
        }
    } else {
        # Install using X509Store method
        if ($WhatIfOnly) {
            Write-Host "`nWhatIfOnly specified: no installation attempted (X509Store method)."
        } else {
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
                    } else {
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
        $tag = if ($i -eq 0) {'[Leaf]'} elseif ($i -eq $elements.Count-1) {'[Root]'} else {'[Interm]'}
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
    function Get-Intermediates { param($e) if ($e.Count -gt 2) { $e[1..($e.Count-2)] } else { @() } }

    # --- Certificate selection and filtering ---
    $toExport = switch ($WhatToExport) {
        'Root'         { @(Get-RootCert $elements) | Where-Object { $_ } }
        'Intermediate' { @(Get-Intermediates $elements) | Where-Object { $_ } }
        'Leaf'         { @($leaf) | Where-Object { $_ } }
        'All'          { $elements | Where-Object { $_ } }
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
            -IsLastInChain ($i -eq $elements.Count-1)
        $tag = if ($i -eq 0) {'[Leaf]'} elseif ($i -eq $elements.Count-1) {'[Root]'} else {'[Intermediate]'}
        Write-Host "  ${tag} [${type}] $($cert.Subject) [$($cert.Thumbprint)]"
    }
    
    # --- Return certificate objects for further processing ---
    return [PSCustomObject]@{
        LeafCertificate = $leaf
        CertificateChain = $elements
        ExportedCertificates = $toExport
        OutputDirectory = if (-not $NoExport) { $OutDir } else { $null }
        TargetHost = $TargetHost
        TargetPort = $TargetPort
        SNIHost = $SNIHost
    }
}
