#!/bin/bash

set -e

if ! which apt >/dev/null; then
  echo "apt not found."
  exit 1
fi

PACKAGES="libjxl-tools tmux build-essential cmatrix fonts-noto-cjk neofetch curl parallel zstd xz-utils webp btop zram-tools"
sudo apt-get update && sudo apt-get install -y $PACKAGES

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
source ~/.nvm/nvm.sh && nvm install --lts
