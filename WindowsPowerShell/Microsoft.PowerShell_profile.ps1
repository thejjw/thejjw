
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
    Set-Variable -Name queryurl -Value "https://whois.kisa.or.kr/openapi/whois.jsp?query=$DomainOrIp&key=$WhoisKisaApiKey&answer=json" -Option Constant;
    return (Invoke-WebRequest -Uri $queryurl -UseBasicParsing | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty whois);
}