#!/bin/bash

set -e

if ! which apt >/dev/null; then
  echo "apt not found."
  exit 1
fi

PACKAGES="libjxl-tools tmux build-essential nodejs cmatrix fonts-noto-cjk neofetch curl parallel zstd xz-utils webp btop zram-tools"
sudo apt-get update && sudo apt-get install -y $PACKAGES
