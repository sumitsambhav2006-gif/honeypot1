# IHTIP Production Deployment Guide

## 1. Network Architecture & DMZ Segmentation
In an industry-grade SOC deployment, honeypots must never reside on the internal corporate network.

```
Internet (Untrusted)
       │
       ▼ (Port 22/2222)
┌─────────────────────────────────┐
│ Honeypot Sensor (VLAN 10 / DMZ)  │
│ Cowrie SSH Daemon (Port 2222)   │
└────────────────┬────────────────┘
                 │ One-way Syslog / Log Shipping (Rsyslog or Filebeat)
                 ▼
┌─────────────────────────────────┐
│ Private Core Network (VLAN 20)  │
│ IHTIP Collector & Risk Engine   │
│ MySQL Database Cluster          │
│ Flask REST API Backend          │
│ Nginx Reverse Proxy (HTTPS 443) │
└─────────────────────────────────┘
```

## 2. Hardening Measures
1. **Dedicated Service Accounts:** Run Cowrie under user `cowrie` and Web/Collector under dedicated service accounts without sudo privileges.
2. **Egress Firewall Rules:**
   ```bash
   # Block all outbound TCP SYN packets initiated by the honeypot
   sudo iptables -A OUTPUT -p tcp --syn -j DROP
   ```
3. **Database Security:**
   - Grant least-privilege credentials to the database user:
     ```sql
     CREATE USER 'ihtip_app'@'127.0.0.1' IDENTIFIED BY 'StrongPasswordHere!';
     GRANT SELECT, INSERT, UPDATE ON honeypot_db.* TO 'ihtip_app'@'127.0.0.1';
     FLUSH PRIVILEGES;
     ```
4. **HTTPS Enforcement:** Always place Nginx behind a valid Let's Encrypt or corporate TLS certificate.

