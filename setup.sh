#!/bin/bash

set -e

REPO_URL="https://github.com/Frozenka/GetInfoAD.git"
INSTALL_DIR="/opt/getinfoad"
ALIAS_NAME="getinfoAD"
ALIAS_COMMAND="python3 $INSTALL_DIR/getinfoAD.py -f"
SHELL_CONFIG="$HOME/.bashrc"

# Check if run as root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (sudo)"
  exit 1
fi

# Clone repo
if [ -d "$INSTALL_DIR" ]; then
  echo "📂 Directory already exists: $INSTALL_DIR"
else
  echo "📥 Cloning GetInfoAD into $INSTALL_DIR..."
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

# Make script executable
chmod +x "$INSTALL_DIR/getinfoAD.py"

# Set alias if not already present
if ! grep -q "$ALIAS_COMMAND" "$SHELL_CONFIG"; then
  echo "🔧 Adding alias to $SHELL_CONFIG"
  echo "alias $ALIAS_NAME='$ALIAS_COMMAND'" >> "$SHELL_CONFIG"
fi

# Install Python requirements (if any)
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
  echo "📦 Installing Python requirements..."
  pip3 install -r "$INSTALL_DIR/requirements.txt"
else
  echo "ℹ️ No requirements.txt found, skipping pip install."
fi

# Done
echo "✅ GetInfoAD installed successfully."
echo "➡️ Restart your terminal or run: source $SHELL_CONFIG"
echo "➡️ Then use: $ALIAS_NAME"
