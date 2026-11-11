import sys
import re
import json
import time
import uuid
import socket
import threading
import datetime
from pathlib import Path

import paramiko

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import settings
from config.logging_config import setup_logging

logger = setup_logging("ihtip-ssh-honeypot")

# Thread-safe lock for writing Cowrie-formatted JSON logs
_LOG_LOCK = threading.Lock()

# Passwords that immediately grant deceptive shell access (useful for Hydra / manual demos)
TRAP_PASSWORDS = {
    "root123", "admin123", "toor", "123456", "password", "ubuntu", "kali", "admin", "root"
}

ANSI_ESCAPE_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def write_cowrie_event(event_dict: dict):
    """Appends a Cowrie-compatible JSON event line safely to logs/cowrie.json."""
    log_path = settings.COWRIE_LOG_PATH
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if "timestamp" not in event_dict:
        event_dict["timestamp"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if "honeypot" not in event_dict:
        event_dict["honeypot"] = settings.HONEYPOT_NODE_NAME

    with _LOG_LOCK:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_dict) + "\n")


def load_or_generate_host_key() -> paramiko.RSAKey:
    """Loads persistent RSA host key or generates one so SSH clients don't get MITM warnings."""
    key_path = settings.SSH_HOST_KEY_PATH
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        return paramiko.RSAKey(filename=str(key_path))

    logger.info(f"[*] Generating 2048-bit RSA host key at {key_path}...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(key_path))
    return key


class FakeLinuxShell:
    """Completely sandboxed in-memory Ubuntu 22.04 shell emulator. NEVER executes commands on host OS."""

    def __init__(self, username: str, src_ip: str, src_port: int, session_id: str):
        self.username = username or "root"
        self.src_ip = src_ip
        self.src_port = src_port
        self.session_id = session_id
        self.hostname = "svr01-core-linux"
        self.cwd = "/root" if self.username == "root" else f"/home/{self.username}"
        self.history = []

        # Virtual sandboxed filesystem
        self.files = {
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                "sshd:x:112:65534::/run/sshd:/usr/sbin/nologin\n"
                "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
                "postgres:x:113:119:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n"
            ),
            "/etc/shadow": (
                "root:$6$saltsalt$7vW9X2zK1pQ8...:19650:0:99999:7:::\n"
                "ubuntu:$6$rounds=656000$fakehash...:19650:0:99999:7:::\n"
            ),
            "/etc/issue": "Ubuntu 22.04.3 LTS \\n \\l\n",
            "/etc/os-release": (
                'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
                'NAME="Ubuntu"\n'
                'VERSION_ID="22.04"\n'
                'ID=ubuntu\n'
            ),
            "/proc/cpuinfo": (
                "processor\t: 0\n"
                "model name\t: Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz\n"
                "cpu MHz\t\t: 2300.000\n"
                "cache size\t: 46080 KB\n"
                "processor\t: 1\n"
                "model name\t: Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz\n"
            ),
            "/root/.bash_history": "apt update\nsystemctl status ssh\ncat /var/log/auth.log\n",
            "/root/notes.txt": "DB_BACKUP_SCHEDULE=03:00 UTC\nINTERNAL_PORT=5432\n",
        }
        self.dirs = {
            "/": ["bin", "dev", "etc", "home", "proc", "root", "tmp", "usr", "var"],
            "/root": [".bash_history", "notes.txt", "deploy.sh"],
            "/home": ["ubuntu"],
            "/home/ubuntu": [".bashrc", "app"],
            "/tmp": [".ICE-unix"],
            "/var": ["log", "run", "tmp"],
            "/var/log": ["auth.log", "syslog"],
            "/etc": ["passwd", "shadow", "issue", "os-release", "ssh"],
        }

    def prompt(self) -> str:
        symbol = "#" if self.username == "root" else "$"
        short_cwd = "~" if self.cwd == "/root" and self.username == "root" else self.cwd
        return f"{self.username}@{self.hostname}:{short_cwd}{symbol} "

    def motd(self) -> str:
        return (
            "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)\r\n\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/advantage\r\n\r\n"
            "System information as of " + datetime.datetime.now(datetime.timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y") + "\r\n\r\n"
            "  System load:  0.14              Processes:             118\r\n"
            "  Usage of /:   31.4% of 48.29GB  Users logged in:       1\r\n"
            "  Memory usage: 24%               IPv4 address for eth0: 10.0.4.18\r\n\r\n"
            "Last login: Mon Nov  9 18:12:04 2026 from 198.51.100.42\r\n"
        )

    def _resolve_path(self, target: str) -> str:
        if not target or target == "~":
            return "/root" if self.username == "root" else f"/home/{self.username}"
        if target.startswith("/"):
            raw = target
        else:
            raw = f"{self.cwd.rstrip('/')}/{target}"
        parts = []
        for p in raw.split("/"):
            if p == "" or p == ".":
                continue
            elif p == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(p)
        return "/" + "/".join(parts)

    def execute(self, raw_cmd: str) -> tuple[str, bool]:
        """
        Executes command strictly in the simulated Python environment.
        Returns (output_text, should_exit).
        """
        cmd = ANSI_ESCAPE_RE.sub("", raw_cmd).strip()
        if not cmd:
            return "", False

        self.history.append(cmd)

        # Log command to Cowrie JSON log immediately
        write_cowrie_event({
            "eventid": "cowrie.command.input",
            "message": f"CMD: {cmd}",
            "input": cmd,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "session": self.session_id
        })

        # Handle chained commands separated by ; or &&
        if "&&" in cmd or ";" in cmd:
            outputs = []
            parts = re.split(r'\s*(?:&&|;)\s*', cmd)
            for part in parts:
                if part:
                    out, should_exit = self.execute_single(part)
                    if out:
                        outputs.append(out)
                    if should_exit:
                        return "\r\n".join(outputs), True
            return "\r\n".join(outputs), False

        return self.execute_single(cmd)

    def execute_single(self, cmd: str) -> tuple[str, bool]:
        tokens = cmd.split()
        base = tokens[0].lower()
        args = tokens[1:]

        if base in ("exit", "logout", "quit"):
            return "logout", True

        if base == "whoami":
            return self.username, False

        if base == "id":
            if self.username == "root":
                return "uid=0(root) gid=0(root) groups=0(root)", False
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)", False

        if base == "hostname":
            return self.hostname, False

        if base == "pwd":
            return self.cwd, False

        if base == "uname":
            if "-a" in args:
                return f"Linux {self.hostname} 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 20:49:16 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux", False
            if "-m" in args:
                return "x86_64", False
            return "Linux", False

        if base == "uptime":
            return " 22:05:11 up 47 days, 14:22,  1 user,  load average: 0.14, 0.18, 0.12", False

        if base == "date":
            return datetime.datetime.now(datetime.timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y"), False

        if base == "cd":
            target = args[0] if args else "~"
            resolved = self._resolve_path(target)
            if resolved in self.dirs:
                self.cwd = resolved
                return "", False
            return f"-bash: cd: {target}: No such file or directory", False

        if base in ("ls", "ll", "dir"):
            target_arg = next((a for a in args if not a.startswith("-")), None)
            target_dir = self._resolve_path(target_arg) if target_arg else self.cwd
            items = self.dirs.get(target_dir)
            if items is None:
                return f"ls: cannot access '{target_arg}': No such file or directory", False
            if "-l" in " ".join(args) or "-la" in args or "-al" in args or base == "ll":
                lines = [f"total {len(items) * 4}"]
                for item in items:
                    is_dir = f"{target_dir.rstrip('/')}/{item}" in self.dirs
                    perms = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                    size = "4096" if is_dir else "1024"
                    lines.append(f"{perms} 1 root root {size:>5} Nov  8 14:20 {item}")
                return "\r\n".join(lines), False
            return "  ".join(items), False

        if base == "cat":
            if not args:
                return "", False
            fpath = self._resolve_path(args[0])
            if fpath in self.files:
                return self.files[fpath].replace("\n", "\r\n").rstrip("\r\n"), False
            return f"cat: {args[0]}: No such file or directory", False

        if base in ("ps",):
            return (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
                "root           1  0.0  0.2 167936 11200 ?        Ss   Sep22   0:18 /sbin/init\r\n"
                "root         512  0.0  0.1  15420  6420 ?        Ss   Sep22   0:04 sshd: /usr/sbin/sshd -D\r\n"
                "postgres     891  0.1  1.4 214500 58120 ?        Ss   Sep22   2:11 /usr/lib/postgresql/14/bin/postgres\r\n"
                f"root        4210  0.0  0.1  16840  5120 pts/0    Ss   22:04   0:00 -bash"
            ), False

        if base in ("netstat", "ss"):
            return (
                "Active Internet connections (only servers)\r\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\r\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      512/sshd\r\n"
                "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      891/postgres\r\n"
                f"tcp        0      0 10.0.4.18:22            {self.src_ip}:{self.src_port}    ESTABLISHED 4210/sshd"
            ), False

        if base in ("ifconfig", "ip"):
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                "        inet 10.0.4.18  netmask 255.255.255.0  broadcast 10.0.4.255\r\n"
                "        ether 02:42:ac:11:00:02  txqueuelen 1000  (Ethernet)\r\n"
                "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
                "        inet 127.0.0.1  netmask 255.0.0.0"
            ), False

        if base in ("wget", "curl"):
            url = next((a for a in args if a.startswith("http")), "http://unknown-payload")
            fname = url.split("/")[-1] or "payload.bin"
            # Record file download Cowrie event too
            write_cowrie_event({
                "eventid": "cowrie.session.file_download",
                "url": url,
                "outfile": f"var/lib/cowrie/downloads/{fname}",
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "session": self.session_id
            })
            # Add simulated file into virtual directory
            self.dirs.setdefault(self.cwd, [])
            if fname not in self.dirs[self.cwd]:
                self.dirs[self.cwd].append(fname)
            self.files[f"{self.cwd.rstrip('/')}/{fname}"] = "#!/bin/sh\necho 'simulated malicious payload'\n"
            return f"--2026-11-10 16:35:00--  {url}\r\nConnecting... connected.\r\nHTTP request sent, awaiting response... 200 OK\r\nLength: 48128 (47K)\r\nSaving to: '{fname}'\r\n\r\n{fname}          100%[===================>]  47.00K  --.-KB/s    in 0.02s", False

        if base in ("chmod", "chown", "mkdir", "touch", "rm"):
            if base == "mkdir" and args:
                new_dir = self._resolve_path(args[-1])
                self.dirs[new_dir] = []
                parent = self.cwd
                self.dirs.setdefault(parent, []).append(args[-1])
            return "", False

        if base == "echo":
            return " ".join(args), False

        if base == "sudo":
            if "-l" in args:
                return f"User {self.username} may run the following commands on {self.hostname}:\r\n    (ALL : ALL) NOPASSWD: ALL", False
            return "", False

        if base == "crontab":
            if "-l" in args:
                return f"no crontab for {self.username}", False
            return "", False

        if base == "history":
            return "\r\n".join(f"  {i+1}  {h}" for i, h in enumerate(self.history)), False

        if base == "clear":
            return "\033[2J\033[H", False

        if base == "help":
            return "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\r\nSimulated Linux Environment (IHTIP Honeypot). Try: whoami, id, uname -a, ls -la, cat /etc/passwd, netstat -antp, wget <url>, exit", False

        return f"-bash: {base}: command not found", False


class CowrieSSHInterface(paramiko.ServerInterface):
    """Paramiko SSH2 Server Interface emulating Cowrie SSH authentication & session handling."""

    def __init__(self, src_ip: str, src_port: int, session_id: str):
        self.src_ip = src_ip
        self.src_port = src_port
        self.session_id = session_id
        self.username = "root"
        self.auth_attempts = 0
        self.shell_event = threading.Event()
        self.exec_command = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password,keyboard-interactive"

    def check_auth_password(self, username, password):
        self.username = username
        self.auth_attempts += 1

        # Grant deceptive access if password matches trap list OR on 3rd try in same connection
        if password in TRAP_PASSWORDS or self.auth_attempts >= 3:
            write_cowrie_event({
                "eventid": "cowrie.login.success",
                "message": f"login attempt [{username}/{password}] succeeded",
                "username": username,
                "password": password,
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "session": self.session_id
            })
            logger.info(f"[HONEYPOT] Login SUCCESS: {username}@{self.src_ip} (session={self.session_id})")
            return paramiko.AUTH_SUCCESSFUL

        write_cowrie_event({
            "eventid": "cowrie.login.failed",
            "message": f"login attempt [{username}/{password}] failed",
            "username": username,
            "password": password,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "session": self.session_id
        })
        logger.info(f"[HONEYPOT] Login FAILED: {username}@{self.src_ip} (attempt #{self.auth_attempts})")
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username, submethods):
        self.username = username
        return paramiko.InteractiveQuery("", "", ("Password: ", False))

    def check_auth_interactive_response(self, responses):
        pwd = responses[0] if responses else ""
        return self.check_auth_password(self.username, pwd)

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode("utf-8", errors="ignore")
        self.shell_event.set()
        return True


def handle_ssh_connection(client_sock: socket.socket, client_addr: tuple, host_key: paramiko.RSAKey):
    """Handles a single incoming TCP/SSH client connection."""
    src_ip, src_port = client_addr[0], client_addr[1]
    session_id = uuid.uuid4().hex[:12]
    start_ts = time.time()

    write_cowrie_event({
        "eventid": "cowrie.session.connect",
        "message": f"New connection: {src_ip}:{src_port} (0.0.0.0:{settings.HONEYPOT_PORT}) [session: {session_id}]",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": settings.HONEYPOT_PORT,
        "session": session_id
    })
    logger.info(f"[HONEYPOT] New incoming SSH connection from {src_ip}:{src_port} [session={session_id}]")

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        transport.add_server_key(host_key)

        server = CowrieSSHInterface(src_ip, src_port, session_id)
        transport.start_server(server=server)

        chan = transport.accept(25)
        if chan is None:
            return

        server.shell_event.wait(10)
        shell = FakeLinuxShell(server.username, src_ip, src_port, session_id)

        # Non-interactive single-command exec mode (e.g., ssh root@host "whoami")
        if server.exec_command:
            out, _ = shell.execute(server.exec_command)
            if out:
                chan.sendall((out + "\r\n").encode("utf-8"))
            chan.send_exit_status(0)
            chan.close()
            return

        # Interactive PTY shell mode
        chan.sendall(shell.motd().encode("utf-8"))
        chan.sendall(shell.prompt().encode("utf-8"))

        cmd_buffer = ""
        in_escape = False
        session_done = False
        while not session_done and not chan.closed and transport.is_active():
            data = chan.recv(1024)
            if not data:
                break

            text = data.decode("utf-8", errors="ignore")
            for ch in text:
                if in_escape:
                    if ch.isalpha() or ch == "~":
                        in_escape = False
                    continue
                if ch == "\x1b":  # ESC sequence start (arrow keys, etc.)
                    in_escape = True
                    continue
                if ch == "\x03":  # Ctrl+C
                    cmd_buffer = ""
                    chan.sendall(b"^C\r\n" + shell.prompt().encode("utf-8"))
                elif ch == "\x04":  # Ctrl+D
                    chan.sendall(b"logout\r\n")
                    chan.close()
                    session_done = True
                    break
                elif ch in ("\r", "\n"):
                    chan.sendall(b"\r\n")
                    output, should_exit = shell.execute(cmd_buffer)
                    cmd_buffer = ""
                    if output:
                        chan.sendall((output + "\r\n").encode("utf-8"))
                    if should_exit:
                        chan.close()
                        session_done = True
                        break
                    chan.sendall(shell.prompt().encode("utf-8"))
                elif ch in ("\x7f", "\x08"):  # Backspace / DEL
                    if cmd_buffer:
                        cmd_buffer = cmd_buffer[:-1]
                        chan.sendall(b"\b \b")
                elif ord(ch) >= 32:
                    cmd_buffer += ch
                    chan.sendall(ch.encode("utf-8"))

    except (EOFError, paramiko.SSHException, ConnectionResetError, OSError) as e:
        logger.debug(f"[HONEYPOT] Connection {session_id} ended: {e}")
    except Exception as e:
        logger.error(f"[HONEYPOT] Unexpected handler error for {session_id}: {e}")
    finally:
        duration = max(1, int(time.time() - start_ts))
        if not sys.is_finalizing():
            write_cowrie_event({
                "eventid": "cowrie.session.closed",
                "message": f"Connection lost after {duration} seconds",
                "duration": duration,
                "src_ip": src_ip,
                "src_port": src_port,
                "session": session_id
            })
            logger.info(f"[HONEYPOT] Session {session_id} closed ({duration}s)")
        if transport:
            try:
                transport.close()
            except Exception:
                pass


class RealSSHHoneypotServer:
    """Multi-threaded Real SSH Honeypot Daemon listening on configurable TCP port."""

    def __init__(self, host: str = None, port: int = None):
        self.host = host or settings.HONEYPOT_HOST
        self.port = port or settings.HONEYPOT_PORT
        self.running = False
        self.server_sock = None
        self.host_key = load_or_generate_host_key()

    def start(self):
        self.running = True
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(100)
        self.server_sock.settimeout(1.0)

        logger.info(f"[+] REAL SSH HONEYPOT LISTENING on {self.host}:{self.port} (Banner: OpenSSH 8.9p1 Ubuntu)")

        while self.running:
            try:
                client_sock, client_addr = self.server_sock.accept()
                t = threading.Thread(
                    target=handle_ssh_connection,
                    args=(client_sock, client_addr, self.host_key),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    srv = RealSSHHoneypotServer()
    try:
        srv.start()
    except KeyboardInterrupt:
        srv.stop()
        logger.info("SSH Honeypot server stopped.")
