#!/bin/bash
# ==============================================================================
# IHTIP - Start Cowrie Honeypot Service
# ==============================================================================
INSTALL_DIR="/home/cowrie/cowrie"

if [ ! -d "$INSTALL_DIR" ]; then
    echo "[-] Cowrie directory not found at $INSTALL_DIR. Please run install.sh first."
    exit 1
fi

echo "[*] Starting Cowrie Honeypot Daemon..."
su - cowrie -c "cd $INSTALL_DIR && source cowrie-env/bin/activate && bin/cowrie start"
echo "[+] Cowrie started. Listening on configured ports (Default: 2222)."

