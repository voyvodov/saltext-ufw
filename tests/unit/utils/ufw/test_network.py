import re

from saltext.ufw.utils.ufw import network


class TestCompileIPv4Regexp:
    def test_returns_compiled_pattern(self):
        """Test that compile_ipv4_regexp returns a compiled regex pattern"""
        result = network.compile_ipv4_regexp()
        assert isinstance(result, re.Pattern)

    def test_matches_valid_ipv4(self):
        """Test that compiled regex matches valid IPv4 addresses"""
        pattern = network.compile_ipv4_regexp()
        assert pattern.search("192.168.1.1") is not None
        assert pattern.search("10.0.0.1") is not None
        assert pattern.search("172.16.0.1") is not None
        assert pattern.search("255.255.255.255") is not None
        assert pattern.search("0.0.0.0") is not None

    def test_matches_ipv4_in_text(self):
        """Test that regex can find IPv4 in text"""
        pattern = network.compile_ipv4_regexp()
        assert pattern.search("Server IP is 192.168.1.1 here") is not None
        assert pattern.search("Connect to 10.0.0.1:8080") is not None


class TestCompileIPv6Regexp:
    def test_returns_compiled_pattern(self):
        """Test that compile_ipv6_regexp returns a compiled regex pattern"""
        result = network.compile_ipv6_regexp()
        assert isinstance(result, re.Pattern)

    def test_matches_valid_ipv6(self):
        """Test that compiled regex matches valid IPv6 addresses"""
        pattern = network.compile_ipv6_regexp()
        # Various valid IPv6 formats
        assert pattern.search("2001:db8::1") is not None
        assert pattern.search("::1") is not None
        assert pattern.search("fe80::1") is not None
        assert pattern.search("2001:0db8:0000:0000:0000:0000:0000:0001") is not None
        assert pattern.search("::") is not None

    def test_matches_ipv6_in_text(self):
        """Test that regex can find IPv6 in text"""
        pattern = network.compile_ipv6_regexp()
        assert pattern.search("Server IP is 2001:db8::1 here") is not None
        assert pattern.search("Connect to [fe80::1]:8080") is not None

    def test_matches_ipv4_mapped_ipv6(self):
        """Test IPv4-mapped IPv6 addresses"""
        pattern = network.compile_ipv6_regexp()
        assert pattern.search("::ffff:192.168.1.1") is not None


class TestIPv4Regexp:
    def test_ipv4_regexp_is_compiled(self):
        """Test that ipv4_regexp is pre-compiled"""
        assert isinstance(network.ipv4_regexp, re.Pattern)

    def test_matches_various_ipv4(self):
        """Test matching various IPv4 addresses"""
        assert network.ipv4_regexp.search("192.168.0.1") is not None
        assert network.ipv4_regexp.search("10.10.10.10") is not None
        assert network.ipv4_regexp.search("172.31.255.255") is not None
        assert network.ipv4_regexp.search("1.1.1.1") is not None

    def test_does_not_match_invalid_ipv4(self):
        """Test that invalid IPv4 addresses don't match completely"""
        # These might partially match, but not as complete valid IPs
        result = network.ipv4_regexp.match("256.256.256.256")
        # The pattern should not match 256 as a valid octet at the start
        if result:
            # If it matches, it shouldn't be the full invalid IP
            assert result.group() != "256.256.256.256"


class TestIPv6Regexp:
    def test_ipv6_regexp_is_compiled(self):
        """Test that ipv6_regexp is pre-compiled"""
        assert isinstance(network.ipv6_regexp, re.Pattern)

    def test_matches_various_ipv6(self):
        """Test matching various IPv6 addresses"""
        assert network.ipv6_regexp.search("2001:db8::8a2e:370:7334") is not None
        assert network.ipv6_regexp.search("2001:db8::1") is not None
        assert network.ipv6_regexp.search("::1") is not None
        assert network.ipv6_regexp.search("fe80::") is not None
        assert network.ipv6_regexp.search("::") is not None

    def test_matches_compressed_ipv6(self):
        """Test compressed IPv6 notation"""
        assert network.ipv6_regexp.search("2001:db8::1") is not None
        assert network.ipv6_regexp.search("::ffff:192.0.2.1") is not None

    def test_matches_full_ipv6(self):
        """Test full IPv6 notation"""
        full_ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        assert network.ipv6_regexp.search(full_ipv6) is not None


class TestIsStartingByIPv4:
    def test_valid_ipv4_returns_true(self):
        """Test that valid IPv4 addresses return True"""
        assert network.is_starting_by_ipv4("192.168.1.1") is True
        assert network.is_starting_by_ipv4("10.0.0.1") is True
        assert network.is_starting_by_ipv4("172.16.0.1") is True
        assert network.is_starting_by_ipv4("8.8.8.8") is True

    def test_ipv4_with_suffix_returns_true(self):
        """Test IPv4 at start of string with additional text"""
        assert network.is_starting_by_ipv4("192.168.1.1/24") is True
        assert network.is_starting_by_ipv4("10.0.0.1:8080") is True
        assert network.is_starting_by_ipv4("172.16.0.1 server") is True

    def test_ipv4_not_at_start_returns_false(self):
        """Test that IPv4 not at start returns False"""
        assert network.is_starting_by_ipv4("Server at 192.168.1.1") is False
        assert network.is_starting_by_ipv4(" 192.168.1.1") is False

    def test_none_returns_false(self):
        """Test that None returns False"""
        assert network.is_starting_by_ipv4(None) is False

    def test_empty_string_returns_false(self):
        """Test that empty string returns False"""
        assert network.is_starting_by_ipv4("") is False

    def test_invalid_ip_returns_false(self):
        """Test that invalid IP addresses return False"""
        assert network.is_starting_by_ipv4("256.256.256.256") is False
        assert network.is_starting_by_ipv4("not an ip") is False
        assert network.is_starting_by_ipv4("abc.def.ghi.jkl") is False

    def test_ipv6_returns_false(self):
        """Test that IPv6 addresses return False"""
        assert network.is_starting_by_ipv4("2001:db8::1") is False
        assert network.is_starting_by_ipv4("::1") is False

    def test_partial_ipv4_returns_false(self):
        """Test that partial IPv4 returns False"""
        assert network.is_starting_by_ipv4("192.168.1") is False
        assert network.is_starting_by_ipv4("10.0") is False


class TestIsStartingByIPv6:
    def test_valid_ipv6_returns_true(self):
        """Test that valid IPv6 addresses return True"""
        assert network.is_starting_by_ipv6("2001:db8::1") is True
        assert network.is_starting_by_ipv6("::1") is True
        assert network.is_starting_by_ipv6("fe80::1") is True
        assert network.is_starting_by_ipv6("::") is True

    def test_ipv6_with_suffix_returns_true(self):
        """Test IPv6 at start of string with additional text"""
        assert network.is_starting_by_ipv6("2001:db8::1/64") is True
        assert network.is_starting_by_ipv6("fe80::1 interface") is True

    def test_full_ipv6_returns_true(self):
        """Test full IPv6 notation"""
        assert network.is_starting_by_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_ipv4_mapped_ipv6_returns_true(self):
        """Test IPv4-mapped IPv6 addresses"""
        assert network.is_starting_by_ipv6("::ffff:192.168.1.1") is True

    def test_ipv6_not_at_start_returns_false(self):
        """Test that IPv6 not at start returns False"""
        assert network.is_starting_by_ipv6("Server at 2001:db8::1") is False
        assert network.is_starting_by_ipv6(" 2001:db8::1") is False

    def test_none_returns_false(self):
        """Test that None returns False"""
        assert network.is_starting_by_ipv6(None) is False

    def test_empty_string_returns_false(self):
        """Test that empty string returns False"""
        assert network.is_starting_by_ipv6("") is False

    def test_invalid_ipv6_returns_false(self):
        """Test that invalid IPv6 addresses return False"""
        assert network.is_starting_by_ipv6("not an ip") is False
        assert network.is_starting_by_ipv6("gggg::1") is False

    def test_ipv4_returns_false(self):
        """Test that IPv4 addresses return False"""
        assert network.is_starting_by_ipv6("192.168.1.1") is False
        assert network.is_starting_by_ipv6("10.0.0.1") is False

    def test_link_local_ipv6_returns_true(self):
        """Test link-local IPv6 addresses"""
        assert network.is_starting_by_ipv6("fe80::1") is True
        assert network.is_starting_by_ipv6("fe80::") is True
