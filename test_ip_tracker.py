import pytest
from validators import check_ipaddress, convert_to_ip
from api_clients import score_and_reports


def test_check_ipaddress():
    # Valid IPv4 and IPv6 addresses are returned unchanged
    assert str(check_ipaddress("8.8.8.8")) == "8.8.8.8"
    assert str(check_ipaddress("2001:4860:4860::8888")) == "2001:4860:4860::8888"

    # Invalid input returns a descriptive error string instead of raising
    assert check_ipaddress("999.999.999.999") == "Error: 999.999.999.999 is invalid"
    assert check_ipaddress("hello") == "Error: hello is invalid"
    assert check_ipaddress("") == "Error:  is invalid"


def test_convert_to_ip():
    # A real, resolvable domain should return an IP-looking string, not an error
    result = convert_to_ip("google.com")
    assert "invalid" not in result

    # An unresolvable domain returns a descriptive error string
    result = convert_to_ip("this-domain-should-not-exist-abc123xyz.com")
    assert result == "Error: this-domain-should-not-exist-abc123xyz.com is invalid"


def test_score_and_reports():
    all_info = []

    # Out-of-range day counts are rejected before any API call is made
    with pytest.raises(SystemExit, match="number of days must lie in between 0 and 365"):
        score_and_reports("8.8.8.8", all_info, "400")

    # Non-numeric day counts are also rejected
    with pytest.raises(SystemExit, match="days should be an int"):
        score_and_reports("8.8.8.8", all_info, "abc")