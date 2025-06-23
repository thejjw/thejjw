#!/bin/bash

set -e

if ! which apt >/dev/null; then
  echo "apt not found."
  exit 1
fi

PACKAGES="libjxl-tools tmux build-essential nodejs cmatrix fonts-noto-cjk neofetch curl parallel zstd xz-utils"
sudo apt-get update && sudo apt-get install -y $PACKAGES

if ! grep -q 'export PATH="$HOME/bin:$PATH"' "$HOME/.bashrc"; then
  echo 'export PATH="$HOME/bin:$PATH"' >> "$HOME/.bashrc"
  echo "Added ~/bin to PATH in .bashrc"
fi
