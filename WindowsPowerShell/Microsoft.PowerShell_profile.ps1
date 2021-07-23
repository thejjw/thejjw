
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
    Depends on availability of following resources:
        https://assets.gfycat.com/animals
        https://assets.gfycat.com/adjectives
    Tested under Windows Powershell
    Caution: Does not check for duplicate adjectives as of now. NOT FOR PRODUCTION USE.
    In case of error running its host script, try: 
    Set-ExecutionPolicy Bypass -Scope Process -Force; . .\Get-AAAFunc.ps1
.EXAMPLE
    PS C:\> Get-AAA
    snoopy-spiffy-squeaker
.INPUTS
    none
.OUTPUTS
    string of adjective-adjective-animal format
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-05

    Tip: you can add the function declaration to $PROFILE then call it on future shell sessions with ease
#>
    param (
    )
    if($null -eq $Global:getAAA) {
        $Global:getAAA = @{
            ganm = (Invoke-WebRequest https://assets.gfycat.com/animals -UseBasicParsing | Select-Object -ExpandProperty Content).Trim() -split "`n";
            gadj = (Invoke-WebRequest https://assets.gfycat.com/adjectives -UseBasicParsing | Select-Object -ExpandProperty Content).Trim() -split "`n";        
        }
    }
    Write-Output ( -join ($Global:getAAA.gadj.Get((Get-Random) % $Global:getAAA.gadj.Count), "-", $Global:getAAA.gadj.Get((Get-Random) % $Global:getAAA.gadj.Count), "-", $Global:getAAA.ganm.Get((Get-Random) % $Global:getAAA.ganm.Count)));
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


function Clear-JBEvalProductRegistry {
<#
.SYNOPSIS
    Cleans up registry related to evaluation license for a given JetBrains product 
.EXAMPLE
    Clear-JBEvalProductRegistry -Product 'PyCharm'
.INPUTS
    JetBrains product name (that has set evaluation license on the pc for the current user)
.OUTPUTS
    Nothing (will print some processing information though)
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-07
    Tested with Windows Powershell. Should work with pwsh.
#>
    param (
        # product name (ex: 'pycharm', 'clion', ...)
        [Parameter(Mandatory)]
        [string]
        $Product
    )
    
    $reg = 'HKCU:\SOFTWARE\JavaSoft\Prefs\jetbrains\';

    $sub1 = Get-ChildItem $reg;
    if($null -eq $sub1) {
        Write-Output "INFO: no subregistry under $reg, exiting..";
        return;
    } else {
        $productsub = $sub1 | Select-String $product;
        if($null -eq $productsub) {
            Write-Output "INFO: no subregistry for $product, exiting..";
            return;
        } elseif ($productsub.Length -ne 1) {
            Write-Output "INFO: ambiguous subregistries found for $product (type 1), exiting..";
            return;
        } else {
            $sub2 = Get-ChildItem Registry::$productsub;
            if($sub2.Length -ne 1) {
                Write-Output "INFO: ambiguous subregistries found for $product (type 2), exiting..";
                return;
            } else {
                $sub3 = Get-ChildItem Registry::$sub2;
                if($null -eq $sub3) {
                    Write-Output "INFO: no subregistry found for $product (depth 2), exiting..";
                    return;
                } else {
                    $evals = $sub3 | Select-Object -ExpandProperty Name | Select-String evlsprt;
                    if($null -eq $evals) {
                        Write-Output "INFO: no evaluation related registry found for $product, exiting..";
                        return;
                    } elseif ($evals.Length -eq 1) {
                        Remove-Item Registry::$evals -Recurse;
                        Write-Output "INFO: 1 evaluation registry deleted for $product, exiting..";
                        return;
                    } else {
                        foreach ($e in $evals) {
                            $l = $e.Line;
                            Write-Output "INFO: deleting evaluation registry..: $l"
                            Remove-Item Registry::$l -Recurse;
                        }
                        Write-Output "INFO: evaluation registries deleted for $product, exiting..";
                        return;
                    }
                }
            }
        }
    }

    Write-Output "INFO: EvalProductRegistry for $Product has finished processing";
}

function Clear-JBEvalProductFiles {
<#
.SYNOPSIS
    Cleans up flies related to evaluation license for a given JetBrains product 
.EXAMPLE
    Clear-JBEvalProductFiles -Product 'PyCharm'
.INPUTS
    JetBrains product name (that has set evaluation license on the pc for the current user)
.OUTPUTS
    Nothing (will print some processing information though)
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-07
    Tested with Windows Powershell. Should work with pwsh.
#>
    param (
        # product name (ex: 'pycharm', 'clion', ...)
        [Parameter(Mandatory)]
        [string]
        $Product
    )

    $jbpath = $env:APPDATA + '\JetBrains';
    $alldir = Get-ChildItem $jbpath -Directory;
    $productdir = $alldir | Where-Object -Property Name -Like "$Product*";
    if($null -eq $productdir) {
        Write-Output "INFO: no dir found for $Product, exiting...";
        return;
    } elseif ($productdir.Length -ne 1) {
        Write-Output "INFO: several dir found for $Product at $jbpath. Clean up old dir and run again. exiting...";
        return;
    } else {
        Push-Location $productdir.FullName;

        # remove eval dir
        $eval = Get-Item "eval" -ErrorAction SilentlyContinue;
        if($null -eq $eval) {
            Write-Output "INFO: No 'eval' dir found for $productdir.";
        } else {
            Write-Output "INFO: Removing $eval.";
            Remove-Item $eval -Recurse;
        }

        # access other.xml and delete evlsprt line
        $optionsother = Get-Item "options\other.xml";
        if($null -eq $optionsother) {
            Write-Output "INFO: No other.xml found for $productdir.";
        } else {
            Write-Output "INFO: searching for evlsprt lines in other.xml and removing.."
            (Get-Content $optionsother) | 
            ForEach-Object {
                $_ -ireplace ".+evlsprt.+","";
            } | Set-Content $optionsother;
        }

        Pop-Location;
        Write-Output "INFO: EvalProductFiles for $Product has finished processng";
    }
}

function Clear-JBTrial {
<#
.SYNOPSIS
    Cleans up all information related to evaluation license for a given JetBrains product 
.EXAMPLE
    Clear-JBTrial -Product 'PyCharm'
.INPUTS
    JetBrains product name (that has set evaluation license on the pc for the current user)
.OUTPUTS
    Nothing (will print some processing information though)
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-07
    Tested with Windows Powershell. Should work with pwsh.
    Dependent on Clear-JBEvalProductRegistry and Clear-JBEvalProductFiles
#>
    param (
        # product name (ex: 'pycharm', 'clion', ...)
        [Parameter(Mandatory)]
        [string]
        $Product
    )

    if(((Get-ChildItem Function: | Select-Object -ExpandProperty Name) -notcontains 'Clear-JBEvalProductFiles') -or `
    ((Get-ChildItem Function: | Select-Object -ExpandProperty Name) -notcontains 'Clear-JBEvalProductRegistry')) {
        Write-Host 'Clear-JBEvalProductFiles and/or Clear-JBEvalProductRegistry not available. exiting...';
        break;
    }

    Clear-JBEvalProductFiles -Product $Product;
    Clear-JBEvalProductRegistry -Product $Product;
}

function Clear-AllJBTrial {
<#
.SYNOPSIS
    Cleans up all information related to evaluation license for all known JetBrains product 
.EXAMPLE
    Clear-JBAllTrial 
.INPUTS
    Nothing
.OUTPUTS
    Nothing (will print some processing information though)
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-07
    Tested with Windows Powershell. Should work with pwsh.
    Dependent on Clear-JBTrial, Clear-JBEvalProductRegistry and Clear-JBEvalProductFiles
    Edit allproducts list in script to update list of JetBrains products
#>
    if(((Get-ChildItem Function: | Select-Object -ExpandProperty Name) -notcontains 'Clear-JBEvalProductFiles') -or `
    ((Get-ChildItem Function: | Select-Object -ExpandProperty Name) -notcontains 'Clear-JBEvalProductRegistry') -or `
    ((Get-ChildItem Function: | Select-Object -ExpandProperty Name) -notcontains 'Clear-JBTrial')) {
        Write-Host 'Clear-JBTrial, Clear-JBEvalProductFiles and/or Clear-JBEvalProductRegistry not available. exiting...';
        break;
    }

    $allproducts = @('IntelliJ', 'WebStorm', 'DataGrip', 'PhpStorm', 'CLion', 'PyCharm', 'GoLand', 'RubyMine', 'Rider', 'Resharper');
    foreach ($product in $allproducts) {
        Clear-JBTrial -Product $product;
    }
}

function Get-NewPassword {
<#
.SYNOPSIS
    Generates random password
.DESCRIPTION
    Utilizes node.js CLI to invoke password generator logic used by Firefox.
    Will NOT run without node.js runtime installed
.EXAMPLE
    PS C:\> Get-NewPassword
    uafF7MdSYftgh4N
    Generates password of default length(15)
.EXAMPLE    
    PS C:\> Get-NewPassword 8
    or
    PS C:\> Get-NewPassword -Length 8
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
        https://github.com/mozilla/gecko-dev/blob/master/toolkit/components/passwordmgr/PasswordGenerator.jsm
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
