#!/bin/bash
# ==============================================================================
# IHTIP - Stop Cowrie Honeypot Service
# ==============================================================================
INSTALL_DIR="/home/cowrie/cowrie"

if [ ! -d "$INSTALL_DIR" ]; then
    echo "[-] Cowrie directory not found at $INSTALL_DIR."
    exit 1
fi

echo "[*] Stopping Cowrie Honeypot Daemon..."
su - cowrie -c "cd $INSTALL_DIR && bin/cowrie stop"
echo "[+] Cowrie stopped successfully."

