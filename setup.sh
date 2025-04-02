#!/bin/bash

set -e

REPO_URL="https://github.com/Frozenka/GetInfoAD.git"
INSTALL_DIR="/opt/getinfoad"
ALIAS_NAME="getinfoAD"
REAL_USER=$(logname)
SHELL_CONFIG="/home/$REAL_USER/.bashrc"
ALIAS_COMMAND="python3 $INSTALL_DIR/getinfoAD.py "

# Check if run as root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (sudo)"
  exit 1
fi

# Update APT repo
apt update -y

# Dependencies à installer via APT
APT_PKGS=(awk bash python3 python3-pip git)
MISSING_APT_PKGS=()

for pkg in "${APT_PKGS[@]}"; do
  if ! command -v "${pkg%%-*}" &>/dev/null; then
    MISSING_APT_PKGS+=("$pkg")
  fi
done

if [ ${#MISSING_APT_PKGS[@]} -ne 0 ]; then
  echo "➕ Installing APT dependencies: ${MISSING_APT_PKGS[*]}"
  apt install -y "${MISSING_APT_PKGS[@]}"
fi

# pip3 symlink if needed
if ! command -v pip3 &>/dev/null && [ -f /usr/bin/pip3 ]; then
  ln -s /usr/bin/pip3 /usr/local/bin/pip3 || true
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

# Install Python requirements
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
