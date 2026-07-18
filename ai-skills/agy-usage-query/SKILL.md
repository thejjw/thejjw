---
name: agy-usage-query
description: Query Antigravity CLI usage quotas (Gemini, Claude, GPT models) from the private Cloud Code Assist endpoint
metadata:
  audience: developers
  workflow: agy-monitoring
---

## What I do

- Extract the active Google OAuth token stored by the Antigravity CLI (`agy`) inside the system keyring.
- Query Google Cloud Code Assist private endpoint (`cloudcode-pa.googleapis.com`) to retrieve real-time quota buckets.
- Display the remaining percentage and reset times for all available models (Gemini Flash, Pro, etc.).

## When to use me

Use this skill when the user wants to check their Antigravity CLI model quotas, check rate limits, or verify remaining request percentages.

## Usage

### Windows (PowerShell)

Use the **PowerShell** tool to run this block. It extracts the `gemini:antigravity` generic credential using a Win32 `CredRead` DLL import, reads the default project ID, and queries the user quota:

```powershell
$code = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class CredentialHelper {
    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredRead(string target, uint type, int reserved, out IntPtr credentialPtr);
    
    [DllImport("advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
    public static extern void CredFree(IntPtr credentialPtr);
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
    
    public static string GetSecret(string target) {
        IntPtr credPtr;
        if (CredRead(target, 1, 0, out credPtr)) {
            try {
                CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
                if (cred.CredentialBlobSize > 0) {
                    byte[] blob = new byte[cred.CredentialBlobSize];
                    Marshal.Copy(cred.CredentialBlob, blob, 0, (int)cred.CredentialBlobSize);
                    return Encoding.UTF8.GetString(blob);
                }
            } finally {
                CredFree(credPtr);
            }
        }
        return null;
    }
}
"@

Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue

# 1. Retrieve the decrypted credentials JSON
$secretRaw = [CredentialHelper]::GetSecret("gemini:antigravity")
if (-not $secretRaw) {
    Write-Error "Failed to retrieve Antigravity credentials from Windows Credential Manager."
    exit 1
}

$secretJson = ConvertFrom-Json $secretRaw
$accessToken = $secretJson.token.access_token

# 2. Read default project ID from config cache
$projectFile = "$env:USERPROFILE\.gemini\antigravity-cli\cache\default_project_id.txt"
$project = "default-cli-project"
if (Test-Path $projectFile) {
    $project = (Get-Content $projectFile).Trim()
}

# 3. Call the retrieveUserQuotaSummary endpoint
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
    "User-Agent"    = "vscode/1.X.X (Antigravity/4.3.0)"
}
$body = @{ "project" = $project } | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary" -Method Post -Headers $headers -Body $body
    
    Write-Host "Antigravity Grouped Quota Status:" -ForegroundColor Cyan
    foreach ($group in $response.groups) {
        Write-Host "  * Group: $($group.displayName)" -ForegroundColor Cyan
        foreach ($bucket in $group.buckets) {
            $percent = [int]($bucket.remainingFraction * 100)
            $color = if ($percent -gt 50) { "Green" } elseif ($percent -gt 20) { "Yellow" } else { "Red" }
            Write-Host "    - $($bucket.displayName) ($($bucket.window)) : " -NoNewline
            Write-Host "$($percent)% remaining" -ForegroundColor $color -NoNewline
            if ($bucket.description) {
                Write-Host " ($($bucket.description))" -ForegroundColor DarkGray
            } else {
                Write-Host " (Quota available)" -ForegroundColor DarkGray
            }
        }
    }
} catch {
    Write-Error "Failed to retrieve quota: $_"
}
```

### macOS (Bash / Zsh)

Extracts the credentials using the native `security` command line tool and queries the quota:

```bash
# 1. Fetch access token from macOS Keychain
secret_json=$(security find-generic-password -s "gemini" -a "antigravity" -w)
if [ -z "$secret_json" ]; then
  echo "Error: Failed to retrieve Antigravity credentials from macOS Keychain."
  exit 1
fi

access_token=$(echo "$secret_json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('token', {}).get('access_token', ''))")

# 2. Read default project ID from config cache
project_file="$HOME/.gemini/antigravity-cli/cache/default_project_id.txt"
project="default-cli-project"
if [ -f "$project_file" ]; then
  project=$(cat "$project_file" | xargs)
fi

# 3. Call the retrieveUserQuotaSummary endpoint
curl -s -X POST \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -H "User-Agent: vscode/1.X.X (Antigravity/4.3.0)" \
  -d "{\"project\": \"$project\"}" \
  https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary | python3 -m json.tool
```

### Linux (Bash / Zsh)

#### Desktop / GUI Environments
Extracts the credentials using the native `secret-tool` (requires `libsecret-tools` package) and queries the quota:

```bash
# 1. Fetch access token from Linux Keyring (Secret Service)
secret_json=$(secret-tool lookup service gemini user antigravity)
if [ -z "$secret_json" ]; then
  echo "Error: Failed to retrieve Antigravity credentials from Linux Keyring."
  exit 1
fi

access_token=$(echo "$secret_json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('token', {}).get('access_token', ''))")

# 2. Read default project ID from config cache
project_file="$HOME/.gemini/antigravity-cli/cache/default_project_id.txt"
project="default-cli-project"
if [ -f "$project_file" ]; then
  project=$(cat "$project_file" | xargs)
fi

# 3. Call the retrieveUserQuotaSummary endpoint
curl -s -X POST \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -H "User-Agent: vscode/1.X.X (Antigravity/4.3.0)" \
  -d "{\"project\": \"$project\"}" \
  https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary | python3 -m json.tool
```

#### Headless / Terminal-Only Environments (WSL, Docker, SSH)
If no graphical keyring daemon (GNOME Keyring / KWallet) is active, the CLI falls back to the standard Unix password manager `pass` (which stores GPG-encrypted credentials). Query the credentials using:

```bash
# 1. Fetch access token from pass backend
secret_json=$(pass show gemini/antigravity)
if [ -z "$secret_json" ]; then
  echo "Error: Failed to retrieve Antigravity credentials from pass."
  exit 1
fi

access_token=$(echo "$secret_json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('token', {}).get('access_token', ''))")

# 2. Read default project ID from config cache
project_file="$HOME/.gemini/antigravity-cli/cache/default_project_id.txt"
project="default-cli-project"
if [ -f "$project_file" ]; then
  project=$(cat "$project_file" | xargs)
fi

# 3. Call the retrieveUserQuotaSummary endpoint
curl -s -X POST \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -H "User-Agent: vscode/1.X.X (Antigravity/4.3.0)" \
  -d "{\"project\": \"$project\"}" \
  https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary | python3 -m json.tool
```

## Response format

The private API response contains an array of quota groups:

```json
{
  "groups": [
    {
      "buckets": [
        {
          "bucketId": "gemini-weekly",
          "displayName": "Weekly Limit",
          "window": "weekly",
          "resetTime": "2026-07-25T01:43:09Z",
          "description": "You have used some of your weekly limit, it will fully refresh in 6 days, 21 hours.",
          "remainingFraction": 0.9634628
        },
        {
          "bucketId": "gemini-5h",
          "displayName": "Five Hour Limit",
          "window": "5h",
          "resetTime": "2026-07-18T06:43:09Z",
          "description": "You have used some of your 5-hour limit, it will fully refresh in 2 hours, 43 minutes.",
          "remainingFraction": 0.6678439
        }
      ],
      "displayName": "Gemini Models",
      "description": "Models within this group: Gemini Flash, Gemini Pro"
    }
  ]
}
```

- **`groups`**: Array of model grouping categories (e.g., Gemini Models, Claude/GPT Models).
- **`displayName`**: Human-readable name of the limit window or group.
- **`remainingFraction`**: A value from `0.0` to `1.0` representing the portion of remaining quota.
- **`resetTime`**: ISO timestamp when the quota window refreshes.
- **`window`**: Duration type (`weekly` or `5h`).

