import pytest
from ip_tracker import check_ipaddress


def test_valid_ipv4():
    assert str(check_ipaddress("8.8.8.8")) == "8.8.8.8"


def test_valid_ipv6():
    assert str(check_ipaddress("2001:4860:4860::8888")) == "2001:4860:4860::8888"


def test_invalid_ipv4():
    with pytest.raises(SystemExit):
        check_ipaddress("999.999.999.999")


def test_invalid_string():
    with pytest.raises(SystemExit):
        check_ipaddress("hello")


def test_empty_string():
    with pytest.raises(SystemExit):
        check_ipaddress("")