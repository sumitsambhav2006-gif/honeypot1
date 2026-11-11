#!/bin/bash
# ==============================================================================
# IHTIP - Automated Honeypot Installation Script (Ubuntu/Debian)
# ==============================================================================
set -e

echo "[*] Initializing Cowrie Honeypot Installation..."

# Verify Root Privileges
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./install.sh)"
  exit 1
fi

# Update Packages
echo "[*] Updating package repositories..."
apt-get update -qq
apt-get install -y -qq git python3 python3-venv python3-pip libssl-dev libffi-dev build-essential authbind iptables-persistent

# Create user cowrie if not exists
if id "cowrie" &>/dev/null; then
    echo "[!] User 'cowrie' already exists."
else
    echo "[*] Creating unprivileged 'cowrie' service user..."
    adduser --disabled-password --gecos "" cowrie
fi

# Switch to cowrie directory
INSTALL_DIR="/home/cowrie/cowrie"
if [ ! -d "$INSTALL_DIR" ]; then
    echo "[*] Cloning official Cowrie Honeypot repository..."
    su - cowrie -c "git clone http://github.com/cowrie/cowrie.git $INSTALL_DIR"
fi

# Setup Virtual Environment
echo "[*] Setting up Python virtual environment for Cowrie..."
su - cowrie -c "cd $INSTALL_DIR && python3 -m venv cowrie-env && source cowrie-env/bin/activate && pip install --upgrade pip && pip install -r requirements.txt"

# Copy Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/../cowrie/cowrie.cfg" ]; then
    echo "[*] Deploying custom cowrie.cfg configuration..."
    cp "$SCRIPT_DIR/../cowrie/cowrie.cfg" "$INSTALL_DIR/etc/cowrie.cfg"
    chown cowrie:cowrie "$INSTALL_DIR/etc/cowrie.cfg"
fi

echo "[+] Cowrie Honeypot installed successfully at $INSTALL_DIR!"
echo "[*] Run ./start.sh to launch the honeypot daemon."

