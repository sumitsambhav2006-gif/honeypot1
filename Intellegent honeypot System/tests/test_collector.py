from collector.json_parser import JSONParser
from collector.event_normalizer import EventNormalizer

def test_json_parser_valid():
    line = '{"eventid": "cowrie.session.connect", "src_ip": "192.0.2.1", "session": "s123"}'
    parsed = JSONParser.parse_line(line)
    assert parsed is not None
    assert parsed["eventid"] == "cowrie.session.connect"
    assert parsed["src_ip"] == "192.0.2.1"

def test_json_parser_invalid():
    assert JSONParser.parse_line("NOT_JSON") is None
    assert JSONParser.parse_line("") is None
    assert JSONParser.parse_line('{"incomplete": ') is None

def test_event_normalizer():
    normalizer = EventNormalizer()
    raw_event = {
        "eventid": "cowrie.login.failed",
        "src_ip": "194.26.29.112",
        "username": "root",
        "password": "supersecretpassword",
        "session": "sess_abc",
        "timestamp": "2026-11-08T12:00:00.000000Z"
    }
    normalized = normalizer.normalize(raw_event)
    assert normalized is not None
    assert normalized["event_type"] == "cowrie.login.failed"
    assert normalized["source_ip"] == "194.26.29.112"
    assert normalized["username"] == "root"
    # Ensure plaintext password was redacted
    assert "supersecretpassword" not in normalized["password_masked"]
    assert "[LEN:" in normalized["password_masked"]

def test_event_normalizer_duplicate_detection():
    normalizer = EventNormalizer()
    raw = {
        "eventid": "cowrie.login.failed",
        "src_ip": "194.26.29.112",
        "username": "root",
        "session": "sess_dup",
        "timestamp": "2026-11-08T12:00:00Z"
    }
    first = normalizer.normalize(raw)
    assert first is not None
    second = normalizer.normalize(raw)
    assert second is None  # Dropped duplicate

