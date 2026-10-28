#!/bin/bash
# Download GitHub resources with actionable API rate-limit diagnostics.
# 2026.10 @thejjw
set -euo pipefail
insecure=()
output=
url=
while (($#)); do
  case $1 in
    -k|--insecure) insecure=(--insecure); shift ;;
    --output) (($# >= 2)) || { echo 'Missing output path' >&2; exit 2; }; output=$2; shift 2 ;;
    -h|--help) echo 'Usage: github_fetch.sh [-k|--insecure] --output FILE URL'; exit 0 ;;
    -*) echo "Unknown option: $1" >&2; exit 2 ;;
    *) [[ -z $url ]] || { echo 'Only one URL is supported' >&2; exit 2; }; url=$1; shift ;;
  esac
done
[[ -n $output && -n $url ]] || { echo 'Output and URL are required' >&2; exit 2; }
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 2; }
tmp=$(mktemp "${output}.tmp.XXXXXXXX") || exit 1
headers=$(mktemp) || { rm -f -- "$tmp"; exit 1; }
trap 'rm -f -- "$tmp" "$headers"' EXIT
auth=()
if [[ $url == https://api.github.com/* ]]; then
  token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
  [[ -z $token ]] || auth=(-H "Authorization: Bearer $token")
fi
status=$(curl "${insecure[@]}" "${auth[@]}" -sSL --show-error --connect-timeout 15 --max-time 600 -D "$headers" -o "$tmp" -w '%{http_code}' "$url") || exit 1
if [[ $status =~ ^2[0-9][0-9]$ ]]; then
  mv -f -- "$tmp" "$output" || exit 1
  exit 0
fi
if [[ $status == 403 || $status == 429 ]]; then
  if tr -d '\r' < "$headers" | grep -Eiq '^x-ratelimit-remaining:[[:space:]]*0[[:space:]]*$'; then
    reset=$(tr -d '\r' < "$headers" | grep -i '^x-ratelimit-reset:' | tail -1 | cut -d: -f2 | tr -d ' ' || true)
    echo "GitHub API rate limit exceeded. Reset (UTC epoch): ${reset:-unknown}." >&2
    exit 3
  fi
  if grep -Eiq 'secondary rate limit|abuse detection' "$tmp"; then
    retry=$(tr -d '\r' < "$headers" | grep -i '^retry-after:' | tail -1 | cut -d: -f2- | xargs || true)
    echo "GitHub secondary rate limit exceeded. Retry-After: ${retry:-not provided}." >&2
    exit 4
  fi
fi
echo "Download failed: HTTP $status." >&2
head -c 500 "$tmp" >&2
echo >&2
exit 1
