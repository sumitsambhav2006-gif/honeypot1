#!/usr/bin/env python3
"""
Intelligent Honeypot & Threat Intelligence Platform (IHTIP)
Master Execution Script
"""
import sys
import argparse
import threading
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import settings
from config.logging_config import setup_logging

logger = setup_logging("ihtip-runner")

def start_web():
    """Starts the Flask SOC Dashboard Web Platform."""
    from backend.app import create_app
    app = create_app()
    logger.info(f"[*] Starting IHTIP SOC Dashboard at http://{settings.HOST}:{settings.PORT}")
    app.run(host=settings.HOST, port=settings.PORT, debug=settings.DEBUG, use_reloader=False)

def start_collector():
    """Starts the real-time Cowrie log watcher & ingestion pipeline."""
    from collector.log_watcher import LogWatcher
    logger.info("[*] Starting IHTIP Log Watcher & Event Collector...")
    watcher = LogWatcher()
    watcher.process_file_from_start()
    watcher.tail_forever()

def start_honeypot():
    """Starts the built-in Real Interactive SSH Honeypot Server on port 2222."""
    from honeypot.ssh_server import RealSSHHoneypotServer
    try:
        srv = RealSSHHoneypotServer()
        srv.start()
    except OSError as e:
        logger.warning(f"[!] Could not bind SSH Honeypot on port {settings.HONEYPOT_PORT}: {e} (Continuing with LogWatcher only)")

def start_real_attack(host: str = "127.0.0.1", port: int = None):
    """Runs a real TCP/SSH attack client against the honeypot."""
    from honeypot.simulator.real_attack_demo import run_real_ssh_attack
    run_real_ssh_attack(target_host=host, target_port=port or settings.HONEYPOT_PORT)

def start_simulation(count: int = 1, interval: int = 8):
    """Starts the Cowrie SSH attack simulator."""
    from honeypot.simulator.attack_simulator import simulate_single_attack, run_continuous_simulation
    if count == 1:
        simulate_single_attack()
    else:
        run_continuous_simulation(interval=interval, total_attacks=count)

def run_all(continuous_sim: bool = False):
    """Starts Real SSH Honeypot, Log Collector, and SOC Web Dashboard concurrently."""
    honeypot_thread = threading.Thread(target=start_honeypot, daemon=True)
    honeypot_thread.start()

    collector_thread = threading.Thread(target=start_collector, daemon=True)
    collector_thread.start()

    if continuous_sim:
        sim_thread = threading.Thread(target=lambda: start_simulation(count=0, interval=12), daemon=True)
        sim_thread.start()

    start_web()

def seed_db():
    from database.seed import seed_database
    seed_database()

def run_tests():
    import pytest
    pytest.main(["tests"])

def main():
    parser = argparse.ArgumentParser(description="Intelligent Honeypot & Threat Intelligence Platform (IHTIP)")
    subparsers = parser.add_subparsers(dest="command", help="Operational mode")

    subparsers.add_parser("web", help="Run SOC Web Dashboard")
    subparsers.add_parser("collector", help="Run Log Watcher & Event Collector")
    subparsers.add_parser("honeypot", help="Run Real SSH Honeypot Server (Port 2222)")

    real_atk_parser = subparsers.add_parser("real-attack", help="Launch real TCP/SSH attack demo against honeypot")
    real_atk_parser.add_argument("--host", default="127.0.0.1", help="Target Honeypot IP")
    real_atk_parser.add_argument("--port", type=int, default=settings.HONEYPOT_PORT, help="Target SSH port")
    
    sim_parser = subparsers.add_parser("simulate", help="Run Attack Simulator")
    sim_parser.add_argument("--count", type=int, default=1, help="Number of simulated sessions (0 for continuous)")
    sim_parser.add_argument("--interval", type=int, default=8, help="Seconds between attacks")

    all_parser = subparsers.add_parser("all", help="Run SSH Honeypot + Collector + Web Dashboard together")
    all_parser.add_argument("--simulate", action="store_true", help="Also run continuous attack simulator in background")

    subparsers.add_parser("seed", help="Seed database with initial threat data")
    subparsers.add_parser("test", help="Run automated test suite")

    args = parser.parse_args()

    if args.command == "web":
        start_web()
    elif args.command == "collector":
        start_collector()
    elif args.command == "honeypot":
        start_honeypot()
    elif args.command == "real-attack":
        start_real_attack(host=args.host, port=args.port)
    elif args.command == "simulate":
        start_simulation(count=args.count, interval=args.interval)
    elif args.command == "all":
        run_all(continuous_sim=args.simulate)
    elif args.command == "seed":
        seed_db()
    elif args.command == "test":
        run_tests()
    else:
        # Default behavior: run all
        print("=" * 65)
        print(" Intelligent Honeypot & Threat Intelligence Platform (IHTIP)")
        print(" SOC / Blue Team Defensive Operations")
        print("=" * 65)
        print("Usage:")
        print("  python run.py all          -> Start Real SSH Honeypot (2222) + Collector + SOC Web (5000)")
        print("  python run.py honeypot     -> Start Real SSH Honeypot only (Port 2222)")
        print("  python run.py real-attack  -> Launch real TCP/SSH attack against localhost:2222")
        print("  python run.py web          -> Start SOC Dashboard (port 5000)")
        print("  python run.py collector    -> Start Real-time Cowrie Log Collector")
        print("  python run.py simulate     -> Simulate Cowrie log attacks")
        print("  python run.py test         -> Run automated tests")
        print("  python run.py seed         -> Seed sample threat data")
        print("=" * 65)
        run_all(continuous_sim=False)

if __name__ == "__main__":
    main()

