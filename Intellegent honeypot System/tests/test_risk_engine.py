from analytics.risk_engine import RiskEngine

def test_risk_scoring_low():
    # Only single failed login
    eval_low = RiskEngine.calculate_score(failed_logins=1)
    assert eval_low["risk_score"] == 5
    assert eval_low["severity"] == "Low"

def test_risk_scoring_medium():
    # Multiple usernames + recon
    eval_med = RiskEngine.calculate_score(
        failed_logins=4,
        has_multiple_usernames=True,
        recon_commands_count=1
    )
    # 20 + 10 + 15 = 45
    assert eval_med["risk_score"] == 45
    assert eval_med["severity"] == "Medium"

def test_risk_scoring_high():
    eval_high = RiskEngine.calculate_score(
        failed_logins=5,
        has_multiple_usernames=True,
        file_retrieval_count=1,
        persistence_count=1
    )
    # 25 + 10 + 20 + 20 = 75
    assert eval_high["risk_score"] == 75
    assert eval_high["severity"] == "High"

def test_risk_scoring_critical_capped():
    eval_crit = RiskEngine.calculate_score(
        failed_logins=10,
        has_multiple_usernames=True,
        file_retrieval_count=2,
        destructive_count=2,
        reverse_shell_count=1
    )
    # Sum exceeds 100 -> must cap at 100
    assert eval_crit["risk_score"] == 100
    assert eval_crit["severity"] == "Critical"

