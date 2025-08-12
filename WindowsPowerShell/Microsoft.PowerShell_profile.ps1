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

    $pubkeyPath = "$env:USERPROFILE\.ssh\id_rsa.pub"
    if (-not (Test-Path $pubkeyPath)) {
        Write-Host "SSH key not found. Generating one now..." -ForegroundColor Yellow
        ssh-keygen
    }

    if (Test-Path $pubkeyPath) {
        Write-Host "Sending public key to ${User}@${Hostname}:${Port} ..." -ForegroundColor Cyan
        Get-Content $pubkeyPath | ssh "$User@$Hostname" -p $Port 'mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys'
        Write-Host " Public key installed on $Hostname" -ForegroundColor Green
    } else {
        Write-Warning " Could not locate or generate SSH public key."
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

function Install-ServerCertificateTrust {
<#
.SYNOPSIS
Connects to an HTTPS server, retrieves its certificate chain, and installs selected certificates into Windows trust stores.

.DESCRIPTION
Useful for trusting dev servers, internal hosts, or self-signed certs so that browsers and clients stop complaining. By default, installs into CurrentUser; use -MachineStore for system-wide trust with elevation. You can choose to install Root, Intermediate, Leaf, or all certificates.

.PARAMETER Url
The full HTTPS URL of the server (e.g. https://localhost:8443).

.PARAMETER WhatToInstall
Selects certificate level: 'Root', 'Intermediate', 'Leaf', or 'All'.

.PARAMETER MachineStore
If set, installs to LocalMachine stores (requires admin).

.PARAMETER SaveToFiles
If set, exports selected certificates to disk for inspection.

.PARAMETER OutDir
Folder where exported certificates go. Defaults to '.\certs'.

.PARAMETER SNIHost
Optional override for the hostname sent during TLS handshake.

.EXAMPLE
Install-ServerCertificateTrust -Url https://dev.local -WhatToInstall All -MachineStore

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

        [switch] $MachineStore,
        [switch] $SaveToFiles,
        [string] $OutDir = (Join-Path $PWD 'certs'),
        [string] $SNIHost
    )

    # --- Select store location ---
    $storeLocation = if ($MachineStore) {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "Must run PowerShell as Administrator to use -MachineStore."
        }
        'LocalMachine'
    } else {
        'CurrentUser'
    }

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
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.Connect($targetHost, $targetPort)
        $ssl = [System.Net.Security.SslStream]::new(
            $tcp.GetStream(), $false,
            { param($sender, $cert, $chain, $errors) $true }
        )
        $ssl.AuthenticateAsClient($SNIHost)
        $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
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
    $chain.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
    $null = $chain.Build($leaf)

    # --- Unique and fallback ---
    function Get-UniqueByThumbprint {
        param([System.Collections.IEnumerable] $certs)
        $certList = @($certs)
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($c in $certList) {
            if ($null -ne $c -and $seen.Add($c.Thumbprint)) { $c }
        }
    }
    $chainCertsRaw = @($chain.ChainElements | ForEach-Object { $_.Certificate })
    $elements = @(Get-UniqueByThumbprint $chainCertsRaw)

    if (-not $elements -or $elements.Count -eq 0) {
        $elements = @($leaf)
        Write-Warning "Server did not provide a certificate chain. Using only leaf certificate."
    }

    # --- Helpers ---
    function Get-RootCert { param($e) if ($e.Count -gt 0) { $e[-1] } }
    function Get-Intermediates { param($e) if ($e.Count -gt 2) { $e[1..($e.Count-2)] } else { @() } }
    function Is-SelfSigned($c) { return ($c.Subject -eq $c.Issuer) }
    function Get-StoreName($c) {
        if (Is-SelfSigned $c) { return 'Root' }
        $bc = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
        if ($bc -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            if ($bc.CertificateAuthority) { return 'CA' }
        }
        return 'My'
    }

    # --- Selection ---
    $toInstall = switch ($WhatToInstall) {
        'Root'         { @(Get-RootCert $elements) | Where-Object { $_ } }
        'Intermediate' { @(Get-Intermediates $elements) | Where-Object { $_ } }
        'Leaf'         { @($leaf) | Where-Object { $_ } }
        'All'          { $elements | Where-Object { $_ } }
    }

    if (-not $toInstall -or $toInstall.Count -eq 0) {
        throw "No certificates selected for '${WhatToInstall}'."
    }

    # --- Optional export ---
    if ($SaveToFiles) {
        if (-not (Test-Path $OutDir)) { $null = New-Item -ItemType Directory -Path $OutDir }
        foreach ($cert in $toInstall) {
            $safeName = ($cert.Subject -replace '[^\w\.-]+','_')
            $filePath = Join-Path $OutDir ("${safeName}-${cert.Thumbprint}.cer")
            [IO.File]::WriteAllBytes($filePath, $cert.Export('Cert'))
            Write-Verbose "Exported: ${filePath}"
        }
    }

    # --- Install certs ---
    foreach ($cert in $toInstall) {
        if ($WhatToInstall -eq 'Leaf' -and -not (Is-SelfSigned $cert)) {
            Write-Warning "Skipping non-self-signed leaf certificate. Install its issuer instead."
            continue
        }

        $storeName = Get-StoreName $cert
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
        $store.Open('ReadWrite')
        try {
            $existing = $store.Certificates.Find('FindByThumbprint', $cert.Thumbprint, $false)
            if ($existing.Count -eq 0) {
                $store.Add($cert)
                Write-Host ("Installed: ${cert.Subject} => ${storeLocation}\${storeName}")
            } else {
                Write-Host ("Already present: ${cert.Subject} in ${storeLocation}\${storeName}")
            }
        }
        finally {
            $store.Close()
        }
    }

    # --- Summary ---
    Write-Host ""
    Write-Host "Leaf:   ${leaf.Subject} [${leaf.Thumbprint}]"
    Write-Host "Chain:"
    for ($i = 0; $i -lt $elements.Count; $i++) {
        $tag = if ($i -eq 0) {'[Leaf]'} elseif ($i -eq $elements.Count-1) {'[Root]'} else {'[Interm]'}
        Write-Host ("  ${tag} ${elements[$i].Subject} [${elements[$i].Thumbprint}]")
    }
}

function Install-SiteCertificatesViaCertutil {
<#
.SYNOPSIS
Fetches, exports, classifies, and optionally installs certificates from a TLS server using certutil.

.DESCRIPTION
This function connects to a remote HTTPS server (given by host/port or URL),
retrieves its TLS certificate chain, exports each certificate to a .cer file, and
installs them silently into Windows certificate stores using `certutil`.

Supports:
- Root certificates → Root store
- Intermediate CAs → CA store
- End-Entity server cert → Personal (My) store (optional)

Can run interactively or non-interactively with full control via parameters.

.PARAMETER Host
The target hostname (e.g. www.example.com) to connect via TLS. Required if using host:port mode.

.PARAMETER Port
The TLS port on the host. Defaults to 443.

.PARAMETER Url
An HTTPS URL. If provided, host and port are extracted from this.

.PARAMETER OutputDir
Directory to save exported .cer files. Defaults to TEMP\SiteCerts.

.PARAMETER MachineStore
Use LocalMachine store instead of CurrentUser. Requires admin rights.

.PARAMETER InstallEndEntity
Also installs the server certificate (end-entity) into the Personal (My) store.

.PARAMETER Force
Overwrites existing .cer files in OutputDir.

.PARAMETER WhatIfOnly
Fetch and export certificates, but skip installation steps.

.PARAMETER SkipCertValidation
Skip certificate validation during TLS connection (allows self-signed/invalid certs).

.EXAMPLE
Install-SiteCertificatesViaCertutil -Host "example.com" -Verbose

Fetches and installs certificates from example.com into CurrentUser stores.

.EXAMPLE
Install-SiteCertificatesViaCertutil -Url "https://api.example.com" -OutputDir "C:\apiCerts" -MachineStore -InstallEndEntity

Fetches via HTTPS, saves to C:\apiCerts, and installs all certificates to LocalMachine stores.

.EXAMPLE
Install-SiteCertificatesViaCertutil -Host "example.com" -WhatIfOnly

Simulates operation: exports but skips installation.

.NOTES
- Requires certutil.exe to be available.
- Installation into LocalMachine stores needs admin privileges.
- Skips revocation checks to improve reliability in offline or private network scenarios.
- certutil will silently deduplicate duplicate certificates during install.

Author: jjw(@thejjw)
Last Edit: Aug 2025 (Fixed version)

.LINK
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='HostPort')]
        [string] $Host,

        [Parameter(ParameterSetName='HostPort')]
        [int] $Port = 443,

        [Parameter(Mandatory=$true, ParameterSetName='Url')]
        [Uri] $Url,

        [string] $OutputDir = (Join-Path $env:TEMP "SiteCerts"),

        [switch] $MachineStore,          # Use LocalMachine store (requires admin)
        [switch] $InstallEndEntity,      # Also install the server (end-entity) cert into 'My'
        [switch] $Force,                 # Overwrite existing exported files
        [switch] $WhatIfOnly,            # Do not install; just fetch/export and show plan
        [switch] $SkipCertValidation     # Skip certificate validation during TLS connection
    )

    begin {
        function New-SafeFileName {
            param([string]$s)
            $invalid = [IO.Path]::GetInvalidFileNameChars() -join ''
            $regex = "[{0}]" -f [Regex]::Escape($invalid)
            return ([Regex]::Replace($s, $regex, '_'))
        }

        function Get-CertutilPath {
            $p = Join-Path $env:SystemRoot 'System32\certutil.exe'
            if (Test-Path $p) { return $p }
            $p2 = Join-Path $env:windir 'Sysnative\certutil.exe'
            if (Test-Path $p2) { return $p2 }
            throw "certutil.exe not found."
        }

        function Escape-CertutilArgument {
            param([string]$Argument)
            if ($Argument -match '\s') {
                return "`"$Argument`""
            }
            return $Argument
        }

        function Test-IsAdministrator {
            $currentPrincipal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }

        function Invoke-CertutilAddStore {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory=$true)][string]$StoreName,
                [Parameter(Mandatory=$true)][string]$CerPath,
                [switch]$Machine
            )
            $certutil = Get-CertutilPath
            $args = @()
            if (-not $Machine) { $args += '-user' }
            $args += '-addstore'
            $args += $StoreName
            $args += $CerPath

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
                    throw "certutil failed (exit $($p.ExitCode)) for $CerPath to $StoreName. Error: $stderr`nOutput: $stdout"
                } else {
                    Write-Verbose $stdout.Trim()
                }
            } finally {
                if ($p) { $p.Dispose() }
            }
        }

        function Save-CertAsCer {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory=$true)]
                [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

                [Parameter(Mandatory=$true)]
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

            $thumb = $Certificate.Thumbprint -replace '\s',''
            $fileBase = "{0}__{1}" -f (New-SafeFileName $cn), $thumb
            $path = Join-Path $Directory ($fileBase + '.cer')

            if ((-not $Overwrite) -and (Test-Path -LiteralPath $path)) {
                return $path
            }

            $bytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            [IO.File]::WriteAllBytes($path, $bytes)
            return $path
        }

        function Classify-Cert {
            [CmdletBinding()]
            param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

            $isSelfSigned = $Certificate.Subject -eq $Certificate.Issuer
            $isCA = $false
            foreach ($ext in $Certificate.Extensions) {
                if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
                    $isCA = $ext.CertificateAuthority
                }
            }

            # Note: This classification assumes standard PKI structures.
            # Self-signed certificates in private PKI may need manual review.
            if ($isCA -and $isSelfSigned) { return 'Root' }
            if ($isCA -and -not $isSelfSigned) { return 'CA' }
            return 'EndEntity'
        }
    }

    process {
        # Check admin privileges if MachineStore is requested
        if ($MachineStore -and -not (Test-IsAdministrator)) {
            throw "MachineStore requires administrative privileges. Please run as administrator."
        }

        if ($PSCmdlet.ParameterSetName -eq 'Url') {
            if (-not $Url) { throw "Url is required." }
            if ($Url.Scheme -ne 'https') { throw "Only https URLs are supported for TLS certificate retrieval." }
            $Host = $Url.Host
            $Port = if ($Url.Port -gt 0) { $Url.Port } else { 443 }
        }

        Write-Verbose "Target: $Host:$Port"
        if (-not (Test-Path -LiteralPath $OutputDir)) {
            [void](New-Item -ItemType Directory -Path $OutputDir -Force)
        }

        # 1) Open TLS and capture server certificate with better error handling
        $tcp = $null
        $ssl = $null
        $serverCert = $null
        
        try {
            Write-Verbose "Connecting to $Host:$Port..."
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.ReceiveTimeout = 10000
            $tcp.SendTimeout = 10000
            
            try {
                $tcp.Connect($Host, $Port)
            } catch [System.Net.Sockets.SocketException] {
                throw "Failed to connect to ${Host}:${Port}. Check hostname and port availability. Error: $($_.Exception.Message)"
            } catch {
                throw "Network connection failed to ${Host}:${Port}. Error: $($_.Exception.Message)"
            }

            # Configure certificate validation callback
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

            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $certCallback)
            
            try {
                $ssl.AuthenticateAsClient($Host)
            } catch [System.Security.Authentication.AuthenticationException] {
                throw "TLS authentication failed for ${Host}:${Port}. Error: $($_.Exception.Message)"
            } catch {
                throw "TLS handshake failed for ${Host}:${Port}. Error: $($_.Exception.Message)"
            }

            $serverCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            Write-Verbose "Successfully retrieved server certificate: $($serverCert.Subject)"
            
        } finally {
            if ($ssl) { 
                try { $ssl.Close() } catch { }
                $ssl.Dispose() 
            }
            if ($tcp) { 
                try { $tcp.Close() } catch { }
                $tcp.Dispose() 
            }
        }

        if (-not $serverCert) {
            throw "Failed to retrieve server certificate from $Host:$Port"
        }

        # 2) Build chain (allow AIA/HTTP retrieval, skip revocation) with validation warning
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EndCertificateOnly
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(20)
        $chain.ChainPolicy.VerificationFlags = `
            [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreCertificateAuthorityRevocationUnknown `
            -bor [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreCtlSignerRevocationUnknown `
            -bor [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreEndRevocationUnknown `
            -bor [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreRootRevocationUnknown

        $buildResult = $chain.Build($serverCert)
        if (-not $buildResult) {
            Write-Warning "Certificate chain building incomplete. Some intermediate certificates may be missing. Chain status: $($chain.ChainStatus | ForEach-Object { $_.Status })"
        }

        # Aggregate unique certs (end-entity + intermediates + maybe root)
        $certs = @()
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($elem in $chain.ChainElements) {
            $c = $elem.Certificate
            $id = $c.Thumbprint -replace '\s',''
            if ($seen.Add($id)) { $certs += $c }
        }

        try {
            $chain.Dispose()
        } catch { }

        if (-not $certs -or $certs.Count -eq 0) {
            throw "No certificates were obtained from $Host:$Port."
        }

        Write-Verbose ("Discovered {0} certificate(s) in chain." -f $certs.Count)

        # 3) Export and decide store per cert
        $plan = @()  # objects: @{ Path=; Store=; Type=; Subject= }
        foreach ($c in $certs) {
            $type = Classify-Cert -Certificate $c
            $path = Save-CertAsCer -Certificate $c -Directory $OutputDir -Overwrite:$Force
            $subject = $c.Subject

            $store = switch ($type) {
                'Root' { 'Root' }
                'CA' { 'CA' }
                'EndEntity' {
                    if ($InstallEndEntity) { 'My' } else { $null }
                }
                default { $null }
            }

            $plan += [pscustomobject]@{
                Subject = $subject
                Thumbprint = $c.Thumbprint -replace '\s',''
                Type = $type
                Path = $path
                Store = $store
            }
        }

        # 4) Present plan and optionally install
        Write-Host "Exported certificates to: $OutputDir"
        foreach ($item in $plan) {
            $storeLabel = if ($item.Store) { $item.Store } else { '(skip install)' }
            Write-Host (" - {0} [{1}] -> {2}" -f $item.Subject, $item.Type, $storeLabel)
        }

        if ($WhatIfOnly) {
            Write-Host "WhatIfOnly specified: no installation attempted."
            return $plan
        }

        foreach ($item in $plan | Where-Object { $_.Store }) {
            try {
                Invoke-CertutilAddStore -StoreName $item.Store -CerPath $item.Path -Machine:$MachineStore
                Write-Host ("Installed: {0} -> {1}" -f (Split-Path -Leaf $item.Path), $item.Store)
            } catch {
                throw "Failed to install $($item.Path) into store $($item.Store): $($_.Exception.Message)"
            }
        }

        return $plan
    }
}
