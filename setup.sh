#!/bin/bash

set -e

REPO_URL="https://github.com/Frozenka/GetInfoAD.git"
INSTALL_DIR="/opt/getinfoad"
ALIAS_NAME="getinfoAD"
REAL_USER=${SUDO_USER:-$(whoami)}
SHELL_CONFIG="/home/$REAL_USER/.bashrc"
ALIAS_COMMAND="python3 $INSTALL_DIR/getinfoAD.py "

# Check if run as root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (sudo)"
  exit 1
fi

# Update APT repo
apt update -y

# Ensure pip3 is available even if not in PATH
if ! command -v pip3 &>/dev/null; then
  if [ -f /usr/bin/pip3 ]; then
    ln -sf /usr/bin/pip3 /usr/local/bin/pip3
  elif [ -f /bin/pip3 ]; then
    ln -sf /bin/pip3 /usr/local/bin/pip3
  else
    echo "❌ pip3 not found. Please install python3-pip manually."
    exit 1
  fi
fi

# glow via snap
if ! command -v glow &>/dev/null; then
  echo "✨ Installing glow via snap..."
  snap install glow
fi

# Clone GetInfoAD
if [ -d "$INSTALL_DIR" ]; then
  echo "📂 Directory already exists: $INSTALL_DIR"
else
  echo "📥 Cloning GetInfoAD into $INSTALL_DIR..."
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

# Make main script executable
chmod +x "$INSTALL_DIR/getinfoAD.py"

# Set alias in the user's .bashrc
if ! grep -q "$ALIAS_COMMAND" "$SHELL_CONFIG"; then
  echo "🔧 Adding alias to $SHELL_CONFIG"
  echo "alias $ALIAS_NAME='$ALIAS_COMMAND'" >> "$SHELL_CONFIG"
fi

# Install Python requirements as the real user
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
  echo "📦 Installing Python requirements as $REAL_USER..."
  sudo -u "$REAL_USER" pip3 install -r "$INSTALL_DIR/requirements.txt"
else
  echo "ℹ️ No requirements.txt found, skipping pip install."
fi

# Done
echo "✅ GetInfoAD installed successfully."
echo "➡️ Restart your terminal or run: source $SHELL_CONFIG"
echo "➡️ Then use: $ALIAS_NAME"
echo "ℹ️ Or run manually: python3 $INSTALL_DIR/getinfoAD.py"
