# Cowrie Honeypot Deployment Guide

## 1. Overview
Cowrie is an advanced medium-to-high interaction SSH and Telnet honeypot designed to log brute force attacks and shell interaction performed by adversaries. In the **Intelligent Honeypot & Threat Intelligence Platform (IHTIP)**, Cowrie serves as **Layer 2 (Honeypot Engine)**.

## 2. Hardening & Isolation Principles
- **Never deploy Cowrie directly on your primary administrative SSH port (22)** without re-binding your management SSH to a secure custom port (e.g., 22222) with public-key-only auth.
- Always run Cowrie under a non-root system user (`cowrie`).
- Isolate the honeypot node within a restricted DMZ VLAN or dedicated cloud instance with outbound egress filtering (prevent outbound DDoS or pivoting).

## 3. Ubuntu 22.04 / 24.04 Native Installation
```bash
# 1. Update OS and install dependencies
sudo apt update && sudo apt install -y git python3-virtualenv libssl-dev libffi-dev build-essential authbind

# 2. Create unprivileged cowrie user
sudo adduser --disabled-password --gecos "" cowrie
sudo su - cowrie

# 3. Clone Cowrie repository
git clone http://github.com/cowrie/cowrie.git
cd cowrie

# 4. Set up Python virtual environment
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 5. Copy IHTIP Custom Configuration
cp /path/to/IHTIP/honeypot/cowrie/cowrie.cfg ./etc/cowrie.cfg

# 6. Start Cowrie Honeypot
bin/cowrie start
```

## 4. Port Forwarding (Port 22 -> 2222)
By default, unprivileged users cannot bind to ports below 1024. Use `iptables` or `nftables` to redirect incoming port 22 traffic to Cowrie's port 2222:
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

## 5. Docker Deployment Option
```bash
docker run -d \
  --name cowrie-honeypot \
  -p 2222:2222 \
  -v $(pwd)/logs:/cowrie/cowrie-git/var/log/cowrie \
  cowrie/cowrie:latest
```

## 6. Log Synchronization to IHTIP Collector
The IHTIP collector automatically tails and parses `/var/log/cowrie/cowrie.json`.
Set `COWRIE_LOG_PATH` in `.env` to point to the active Cowrie log location.

