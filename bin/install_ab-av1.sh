#!/bin/bash
# Install the latest x86_64 Linux ab-av1 release and its FFmpeg prerequisites.
# 2025.6-2026.10 @thejjw
set -euo pipefail

fail() { echo "Error: $*" >&2; exit 1; }

[[ "$(uname -m)" == x86_64 ]] || fail "only x86_64 (amd64) is supported."
for tool in curl tar jq sudo; do
  command -v "$tool" >/dev/null || fail "$tool is required. Please install it."
done
if ! command -v unzstd >/dev/null; then
  echo "Installing zstd..."
  sudo apt update && sudo apt install -y zstd
fi

installed=$(command -v ab-av1 || true)
if [[ -n "$installed" ]]; then
  if version=$("$installed" --version 2>&1); then
    echo "Current ab-av1: $version ($installed)"
  else
    echo "Current ab-av1 at $installed failed to run: $version" >&2
  fi
else
  echo "Current ab-av1: not installed"
fi

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

# Check each required build flag independently; a single match is insufficient.
check_ffmpeg() {
  local config flag missing=0
  if ! config=$(ffmpeg -buildconf 2>/dev/null); then
    echo "FFmpeg is missing or could not be run."
    return 1
  fi
  for flag in libsvtav1 libvmaf libopus; do
    if ! grep -Fq -- "--enable-$flag" <<< "$config"; then
      echo "FFmpeg missing: $flag"
      missing=1
    fi
  done
  return "$missing"
}

if check_ffmpeg; then
  echo "FFmpeg supports the required libraries."
else
  echo "Downloading latest FFmpeg x64 build..."
  curl -fSL --show-error --connect-timeout 15 --max-time 600 \
    -o "$tmp/ffmpeg.tar.xz" https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-linux64-gpl.tar.xz || fail "FFmpeg download failed."
  mkdir "$tmp/ffmpeg"
  tar -xJf "$tmp/ffmpeg.tar.xz" --strip-components=2 -C "$tmp/ffmpeg" --wildcards '*/bin/*' || fail "FFmpeg extraction failed."
  sudo cp "$tmp/ffmpeg/"* /usr/local/bin/ || fail "FFmpeg installation failed."
  hash -r
  check_ffmpeg || fail "FFmpeg prerequisite check failed after installation; check PATH."
fi

echo "Checking latest ab-av1 release on GitHub..."
curl -fsSL --show-error --connect-timeout 15 --max-time 60 \
  -o "$tmp/release.json" https://api.github.com/repos/alexheretic/ab-av1/releases/latest || fail "ab-av1 release lookup failed."
tag=$(jq -er '.tag_name | select(type == "string" and length > 0)' "$tmp/release.json") || fail "Invalid release metadata: missing tag."
jq -r '.assets[]? | select(.name | test("-x86_64-unknown-linux-musl\\.tar\\.zst$")) | .browser_download_url // empty' "$tmp/release.json" > "$tmp/assets" || fail "Invalid release asset metadata."
mapfile -t assets < "$tmp/assets"
[[ ${#assets[@]} -eq 1 ]] || fail "Expected exactly one Linux x86_64 musl asset; found ${#assets[@]}."
echo "Target ab-av1 release: $tag (reinstalling if already installed)."
echo "Downloading ab-av1..."
curl -fSL --show-error --connect-timeout 15 --max-time 600 -o "$tmp/ab-av1.tar.zst" "${assets[0]}" || fail "ab-av1 download failed."
mkdir "$tmp/ab-av1"
tar --use-compress-program=unzstd -xf "$tmp/ab-av1.tar.zst" -C "$tmp/ab-av1" || fail "ab-av1 extraction failed."
[[ -f "$tmp/ab-av1/ab-av1" ]] || fail "Archive does not contain ab-av1."
version=$("$tmp/ab-av1/ab-av1" --version 2>&1) || fail "Downloaded ab-av1 failed to run: $version"
[[ "$version" == "ab-av1 ${tag#v}" ]] || fail "Downloaded version '$version' does not match release $tag."
sudo install -m 755 "$tmp/ab-av1/ab-av1" /usr/local/bin/ab-av1 || fail "ab-av1 installation failed."
version=$(/usr/local/bin/ab-av1 --version 2>&1) || fail "Installed ab-av1 failed to run: $version"
[[ "$version" == "ab-av1 ${tag#v}" ]] || fail "Installed version '$version' does not match release $tag."
hash -r
resolved=$(command -v ab-av1 || true)
if [[ -n "$resolved" && "$resolved" != /usr/local/bin/ab-av1 ]]; then
  echo "Warning: PATH resolves ab-av1 to $resolved, which may shadow /usr/local/bin/ab-av1." >&2
fi
echo "Installed and verified $version at /usr/local/bin/ab-av1."
