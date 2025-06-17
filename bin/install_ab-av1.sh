#!/bin/bash
# (linux/deb/ubuntu)(bash) Download and extract latest ffmpeg and ab-av1 release from GitHub, overwriting extraction
# 2025.6 @thejjw

set -e

# Drop execution if not running on x86_64 architecture
if [ "$(uname -m)" != "x86_64" ]; then
  echo "this only supports x86_64 (amd64) architecture."
  exit 1
fi

github_repo="alexheretic/ab-av1"
ext="tar.zst"

# 0. Ensure required tools are installed
if ! command -v curl >/dev/null; then
  echo "curl not found. Please install curl."
  exit 1
fi

if ! command -v tar >/dev/null; then
  echo "tar not found. Please install tar."
  exit 1
fi

if ! command -v unzstd >/dev/null; then
  echo "unzstd (from zstd package) not found. Installing..."
  sudo apt update && sudo apt install -y zstd
fi

# update ffmpeg
# Check if required codecs are present
# "ffmpeg newer than git-2022-02-24 with libsvtav1, libvmaf, libopus enabled."
if ! ffmpeg -buildconf | grep -E "svt_av1|vmaf|opus" > /dev/null; then
    echo "Required codecs not found for ffmpeg"

    echo "downloading latest ffmpeg x64 binary"
    wget -qO- https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-linux64-gpl.tar.xz | sudo tar -xJv --strip-components=2 -C /usr/local/bin --wildcards '*/bin/*'
    echo "ffmpeg binaries extracted to /usr/local/bin/."
else
    echo "FFmpeg already supports the required codecs."
fi

# 1. Get the latest ab-av1 release API URL
api_url="https://api.github.com/repos/$github_repo/releases/latest"

# 2. Fetch the latest release info
release_json=$(curl -sL "$api_url")

# 3. Extract asset download URL (first matching .tar.zst)
asset_url=$(echo "$release_json" | grep 'browser_download_url' | grep "$ext" | head -n1 | cut -d '"' -f4)

if [ -z "$asset_url" ]; then
  echo "No .$ext asset found in the latest release."
  exit 1
fi

# 4. Download and extract ab-av1
echo "downloading latest ab-av1 binary"
wget -qO- $asset_url | sudo tar --use-compress-program=unzstd -xv -C /usr/local/bin --overwrite
echo "ab-av1 binaries extracted to /usr/local/bin/."

echo "done. exiting"
exit 0
