"""
Basic tests for IP_Threat_Tracker.
Run with: pytest test_ip_tracker.py -v
"""

import pytest

from threshold import abuse_score_constraints, vt_constraints
from validators import check_ipaddress, is_domain, raise_for_Status, verdict
import logger
from api_clients import score_and_reports


def test_abuse_score_constraints():
    threshold = abuse_score_constraints()
    assert threshold["safe_upper"] == 30
    assert threshold["suspicious_upper"] == 70


def test_vt_constraints():
    threshold = vt_constraints()
    assert threshold["safe_upper"] == 3
    assert threshold["suspicious_upper"] == 7


def test_check_ipaddress_valid():
    result = check_ipaddress("8.8.8.8")
    assert str(result) == "8.8.8.8"


def test_check_ipaddress_invalid():
    result = check_ipaddress("not.an.ip")
    assert "Error" in str(result)


def test_is_domain():
    assert is_domain("example.com") is True
    assert is_domain("8.8.8.8") is False


def test_raise_for_status():
    info = raise_for_Status("127.0.0.1", {})
    assert info["Status"] == "Loopback"

    info = raise_for_Status("192.168.1.1", {})
    assert info["Status"] == "Private"

    info = raise_for_Status("8.8.8.8", {})
    assert info["Status"] == "Public"


def test_verdict_safe():
    info = {"Abuse Score": 0, "Malicious Reports": 0}
    result = verdict([], info)
    assert result["Safety Status"] == "Safe"


def test_verdict_malicious():
    info = {"Abuse Score": 100, "Malicious Reports": 15}
    result = verdict([], info)
    assert result["Safety Status"] == "Malicious"


def test_judgement_public():
    info = {"Status": "Public", "Safety Status": "Safe", "Input": "8.8.8.8"}
    assert logger.judgement(info) == "8.8.8.8 is Safe"


def test_judgement_private():
    info = {"Status": "Private", "Input": "10.0.0.1"}
    assert logger.judgement(info) == "10.0.0.1 is Private"


def test_score_and_reports_invalid_days():
    with pytest.raises(SystemExit):
        score_and_reports("8.8.8.8", [], {}, days="not-a-number")