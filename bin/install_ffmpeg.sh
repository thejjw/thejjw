#!/bin/bash
# (linux/deb/ubuntu)(bash) Download and extract latest ffmpeg release from GitHub, overwriting extraction
# 2025.6-2026.3 @thejjw

set -e

show_help() {
  cat <<'EOF'
Usage: install_ffmpeg.sh [OPTIONS]

Download and extract the latest FFmpeg x64 build to /usr/local/bin.

Options:
  --force       Reinstall FFmpeg even if required codecs are already detected.
  -h, --help    Show this help message and exit.
EOF
}

force_install=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --force)
      force_install=1
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo
      show_help
      exit 1
      ;;
  esac
  shift
done

# Drop execution if not running on x86_64 architecture
if [ "$(uname -m)" != "x86_64" ]; then
  echo "this only supports x86_64 (amd64) architecture."
  exit 1
fi

install_ffmpeg() {
  echo "downloading latest ffmpeg x64 binary"
  wget -qO- https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-linux64-gpl.tar.xz | sudo tar -xJv --strip-components=2 -C /usr/local/bin --wildcards '*/bin/*'
  echo "ffmpeg binaries extracted to /usr/local/bin/."
}

has_required_codecs() {
  # Check required codec support for ab-av1 and jpeg-xl workflows.
  command -v ffmpeg >/dev/null 2>&1 && ffmpeg -buildconf 2>/dev/null | grep -Eq "jxl|aom|svt_av1|vmaf|opus"
}

# update ffmpeg
# Check if required codecs are present
# "ffmpeg newer than git-2022-02-24 with libsvtav1, libvmaf, libopus enabled.(ab-av1)"
# "ffmpeg libjxl|libaom(v5.1+)"
if [ "$force_install" -eq 1 ]; then
  echo "--force specified; reinstalling ffmpeg regardless of current codec support."
  install_ffmpeg
elif ! has_required_codecs; then
  echo "Required codecs not found for ffmpeg"
  install_ffmpeg
else
  echo "FFmpeg already supports the required codecs."
  echo "Tip: run this script with --force to reinstall/update ffmpeg anyway."
fi

echo "done. exiting"
exit 0
