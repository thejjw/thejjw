#!/bin/bash

# clone only the bin/ directory
# 2025.6 @thejjw

git clone --filter=blob:none --no-checkout https://github.com/thejjw/thejjw.git
cd thejjw
git sparse-checkout init --cone
git sparse-checkout set bin
git checkout main
chmod +x bin/*
mkdir -pv ~/bin
cp -arv bin/* ~/bin/

if ! grep -q 'export PATH="$HOME/bin:$PATH"' "$HOME/.bashrc"; then
  echo 'export PATH="$HOME/bin:$PATH"' >> "$HOME/.bashrc"
  echo "Added ~/bin to PATH in .bashrc"
fi
