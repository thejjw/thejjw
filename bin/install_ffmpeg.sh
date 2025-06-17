#!/bin/bash
# (linux/deb/ubuntu)(bash) Download and extract latest ffmpeg and ab-av1 release from GitHub, overwriting extraction
# 2025.6 @thejjw

set -e

# Drop execution if not running on x86_64 architecture
if [ "$(uname -m)" != "x86_64" ]; then
  echo "this only supports x86_64 (amd64) architecture."
  exit 1
fi

# update ffmpeg
# Check if required codecs are present
# "ffmpeg newer than git-2022-02-24 with libsvtav1, libvmaf, libopus enabled.(ab-av1)"
# "ffmpeg libjxl|libaom(v5.1+)"
if ! ffmpeg -buildconf | grep -E "jxl|aom|svt_av1|vmaf|opus" > /dev/null; then
    echo "Required codecs not found for ffmpeg"

    echo "downloading latest ffmpeg x64 binary"
    wget -qO- https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-linux64-gpl.tar.xz | sudo tar -xJv --strip-components=2 -C /usr/local/bin --wildcards '*/bin/*'
    echo "ffmpeg binaries extracted to /usr/local/bin/."
else
    echo "FFmpeg already supports the required codecs."
fi

echo "done. exiting"
exit 0
