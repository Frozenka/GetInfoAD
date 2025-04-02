#!/bin/bash

set -e

REPO_URL="https://github.com/Frozenka/GetInfoAD.git"
INSTALL_DIR="/opt/getinfoad"
ALIAS_NAME="getinfoAD"
ALIAS_COMMAND="python3 $INSTALL_DIR/getinfoAD.py"

# Détecter le vrai utilisateur (même si root)
if [ -n "$SUDO_USER" ]; then
  REAL_USER="$SUDO_USER"
else
  REAL_USER="$(logname 2>/dev/null || whoami)"
fi

USER_HOME=$(eval echo "~$REAL_USER")

# Déterminer le shell de l'utilisateur
USER_SHELL=$(getent passwd "$REAL_USER" | cut -d: -f7)
if [[ "$USER_SHELL" == */zsh ]]; then
  SHELL_CONFIG="$USER_HOME/.zshrc"
else
  SHELL_CONFIG="$USER_HOME/.bashrc"
fi

# Vérifier les droits root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (sudo)"
  exit 1
fi

# Cloner le repo
if [ -d "$INSTALL_DIR" ]; then
  echo "📂 Directory already exists: $INSTALL_DIR"
else
  echo "📥 Cloning GetInfoAD into $INSTALL_DIR..."
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

# Rendre le script exécutable
chmod +x "$INSTALL_DIR/getinfoAD.py"

# Créer le fichier de config s’il n'existe pas
if [ ! -f "$SHELL_CONFIG" ]; then
  echo "⚠️ Shell config file not found for $REAL_USER. Creating $SHELL_CONFIG."
  touch "$SHELL_CONFIG"
  chown "$REAL_USER":"$REAL_USER" "$SHELL_CONFIG"
fi

# Ajouter l'alias si pas encore présent
if ! grep -qF "$ALIAS_COMMAND" "$SHELL_CONFIG"; then
  echo "🔧 Adding alias to $SHELL_CONFIG"
  echo "alias $ALIAS_NAME='$ALIAS_COMMAND'" >> "$SHELL_CONFIG"
fi

# Message de fin
echo -e "\\n✅ GetInfoAD installed successfully."
echo "➡️ Run: source $SHELL_CONFIG"
echo "➡️ Then use: $ALIAS_NAME"
echo "ℹ️ Or run manually: $ALIAS_COMMAND"
