#!/bin/bash

# clone only the bin/ directory
# 2025.6-2026.5 @thejjw

# Exit on any error
set -e

# Use zsh profile on macOS, bash profile elsewhere.
if [[ "$(uname -s)" == "Darwin" ]]; then
  PROFILE="${HOME}/.zshrc"
else
  PROFILE="${HOME}/.bashrc"
fi

pushd ~
git clone --filter=blob:none --no-checkout https://github.com/thejjw/thejjw.git
cd thejjw
git sparse-checkout init --cone
git sparse-checkout set bin
git checkout main
chmod +x bin/*
mkdir -pv ~/bin
cp -Rv bin/* ~/bin/

if ! grep -q 'export PATH="$HOME/bin:$PATH"' "$PROFILE"; then
  echo 'export PATH="$HOME/bin:$PATH"' >> "$PROFILE"
  echo "Added ~/bin to PATH in $PROFILE"
else
  echo "~/bin already in PATH in $PROFILE"
fi

popd
rm -rf ~/thejjw
echo "Installation complete. Please restart your terminal or run 'source $PROFILE' to update your PATH."
