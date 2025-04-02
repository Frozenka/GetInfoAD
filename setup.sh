#!/bin/bash

set -e

REPO_URL="https://github.com/Frozenka/GetInfoAD.git"
INSTALL_DIR="/opt/getinfoad"
ALIAS_NAME="getinfoAD"
SHELL_CONFIG="/home/$SUDO_USER/.bashrc"
ALIAS_COMMAND="python3 $INSTALL_DIR/getinfoAD.py "

# Check if run as root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (sudo)"
  exit 1
fi

# Update apt repo
apt update -y

# Replace pip3 with correct package name
REQUIRED_PKGS=(glow awk bash python3 python3-pip git)
MISSING_PKGS=()

# Check for missing packages
for pkg in "${REQUIRED_PKGS[@]}"; do
  if ! command -v "${pkg%%-*}" &>/dev/null; then
    MISSING_PKGS+=("$pkg")
  fi
done

# Install missing apt packages
if [ ${#MISSING_PKGS[@]} -ne 0 ]; then
  echo "➕ Installing missing dependencies: ${MISSING_PKGS[*]}"
  for pkg in "${MISSING_PKGS[@]}"; do
    if [ "$pkg" = "glow" ]; then
      echo "✨ Installing glow via snap (not found in apt)..."
      snap install glow
    else
      apt install -y "$pkg"
    fi
  done
fi

# Ensure pip3 is available
if ! command -v pip3 &>/dev/null; then
  echo "🔗 Forcing symlink for pip3..."
  ln -s /usr/bin/pip3 /usr/local/bin/pip3 || true
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
