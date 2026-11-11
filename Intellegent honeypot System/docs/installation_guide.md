# Complete Installation & Deployment Guide

## Prerequisites
- Python 3.10+ (Tested on Python 3.11, 3.12, 3.15)
- Git
- (Optional) MySQL 8.0+ or Docker

---

## Fast Start on Windows (Developer / Demonstration Mode)
The platform includes built-in zero-configuration SQLite support and an authentic Cowrie log attack simulator.

### 1. Clone & Enter Project
```powershell
git clone <repo-url>
cd "Intelligent Honeypot System"
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Seed Database & Run Verification Tests
```powershell
python run.py seed
python run.py test
```

### 4. Launch SOC Dashboard & Real-Time Collector
```powershell
python run.py all
```
Open **`http://localhost:5000`** in your browser.
- Default Admin Account: `admin` / `admin123`
- Default Analyst Account: `analyst` / `analyst123`

### 5. Generate Live Simulated Attacks
In a separate terminal, trigger live simulated SSH intrusions:
```powershell
python run.py simulate --count 1
# Or run continuous attacks every 8 seconds:
python run.py simulate --count 0 --interval 8
```
Watch the **Live Attack Radar** and **SOC Dashboard** update in real time!

---

## Production Deployment on Ubuntu Linux (with Real Cowrie Honeypot)

### 1. Deploy Cowrie Honeypot
```bash
sudo ./honeypot/deployment/install.sh
sudo ./honeypot/deployment/start.sh
```

### 2. Configure IHTIP Backend
```bash
cp .env.example .env
nano .env # Set DB_TYPE=mysql, DB_PASSWORD, COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

### 3. Setup Systemd Services
```bash
sudo cp deployment/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie
sudo systemctl enable --now ihtip-collector
sudo systemctl enable --now ihtip-web
```

### 4. Nginx Reverse Proxy
```bash
sudo cp deployment/nginx/nginx.conf /etc/nginx/sites-available/ihtip
sudo ln -s /etc/nginx/sites-available/ihtip /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

