import pytest
from utils.helpers import validate_target

def test_validate_target_valid_hosts():
    assert validate_target("example.com") == "example.com"
    assert validate_target("sub.domain.example.com") == "sub.domain.example.com"
    assert validate_target("127.0.0.1") == "127.0.0.1"
    assert validate_target("http://example.com") == "http://example.com"
    assert validate_target("https://sub.domain.example.com:8443/path?query=1") == "https://sub.domain.example.com:8443/path?query=1"

def test_validate_target_invalid_hosts():
    with pytest.raises(ValueError):
        validate_target("")
    with pytest.raises(ValueError):
        validate_target("   ")
    with pytest.raises(ValueError):
        validate_target("not a valid host!")
    with pytest.raises(ValueError):
        validate_target("http://invalid_domain#")
    with pytest.raises(ValueError):
        validate_target("http:///path")

def test_validate_target_shell_metacharacters():
    # Shell characters anywhere in the string must be rejected
    with pytest.raises(ValueError, match="Target contains illegal shell characters"):
        validate_target("example.com; ls")
    with pytest.raises(ValueError, match="Target contains illegal shell characters"):
        validate_target("example.com && whoami")
    with pytest.raises(ValueError, match="Target contains illegal shell characters"):
        validate_target("http://example.com/path?param=`id`")
    with pytest.raises(ValueError, match="Target contains illegal shell characters"):
        validate_target("example.com|uname")
    with pytest.raises(ValueError, match="Target contains illegal shell characters"):
        validate_target("example.com$IFS")
    with pytest.raises(ValueError, match="Target contains illegal shell characters"):
        validate_target("example.com>out")
    with pytest.raises(ValueError, match="Target contains illegal shell characters"):
        validate_target("example.com\nnewline")
