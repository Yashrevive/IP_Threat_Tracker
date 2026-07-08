import pytest
from ip_tracker import check_ipaddress, convert_to_ip, score_and_reports


def test_check_ipaddress():
    # Valid IPv4 and IPv6 addresses are returned unchanged
    assert str(check_ipaddress("8.8.8.8")) == "8.8.8.8"
    assert str(check_ipaddress("2001:4860:4860::8888")) == "2001:4860:4860::8888"

    # Invalid input returns a descriptive error string instead of raising
    assert check_ipaddress("999.999.999.999") == "Error: 999.999.999.999 is not a valid IP address"
    assert check_ipaddress("hello") == "Error: hello is not a valid IP address"
    assert check_ipaddress("") == "Error:  is not a valid IP address"


def test_convert_to_ip():
    # A real, resolvable domain should return an IP-looking string, not an error
    result = convert_to_ip("google.com")
    assert "invalid" not in result

    # An unresolvable domain returns a descriptive error string
    result = convert_to_ip("this-domain-should-not-exist-abc123xyz.com")
    assert result == "this-domain-should-not-exist-abc123xyz.com is invalid domain name"


def test_score_and_reports():
    all_info = []

    # Out-of-range day counts are rejected before any API call is made
    assert score_and_reports("8.8.8.8", all_info, "400") == "number of days must lie in between 0 and 365"

    # Non-numeric day counts are also rejected
    assert score_and_reports("8.8.8.8", all_info, "abc") == "number of days must lie in between 0 and 365"