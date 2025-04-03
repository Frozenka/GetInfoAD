#!/bin/bash

set -e

REPO_URL="https://github.com/Frozenka/GetInfoAD.git"
INSTALL_DIR="/opt/getinfoad"

# Vérifier les droits root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (sudo)"
  exit 1
fi

# Cloner le dépôt
if [ -d "$INSTALL_DIR" ]; then
  echo "📂 Directory already exists: $INSTALL_DIR"
else
  echo "📥 Cloning GetInfoAD into $INSTALL_DIR..."
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

# Rendre le script exécutable
chmod +x "$INSTALL_DIR/getinfoAD.py"


# Vérifier si l'alias existe déjà
if grep -q "alias getinfoAD=" /opt/my-resources/setup/zsh/aliases; then
  echo "🔄 Alias 'getinfoAD' already exists, updating..."
  sed -i '/alias getinfoAD=/d' /opt/my-resources/setup/zsh/aliases
fi

# Ajouter l'alias dans le fichier d'alias
echo "alias getinfoAD='python3 /opt/getinfoad/getinfoAD.py'" >> /opt/my-resources/setup/zsh/aliases

# Message de fin
echo -e "\\n✅ GetInfoAD installed successfully."
echo "➡️ Run with: getinfoAD"
