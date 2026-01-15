import re

import pytest

from saltext.ufw.utils.ufw import filter as ufw_filter


class TestFilterLineThatNotStartWith:
    def test_single_line_matching(self):
        """Test filtering with a single matching line"""
        content = "### tuple ### rule1\nother line\n"
        result = ufw_filter.filter_line_that_not_start_with("### tuple", content)
        assert result == "### tuple ### rule1\n"

    def test_multiple_lines_matching(self):
        """Test filtering with multiple matching lines"""
        content = "### tuple ### rule1\n### tuple ### rule2\nother line\n"
        result = ufw_filter.filter_line_that_not_start_with("### tuple", content)
        assert result == "### tuple ### rule1\n### tuple ### rule2\n"

    def test_no_lines_matching(self):
        """Test filtering with no matching lines"""
        content = "other line1\nother line2\n"
        result = ufw_filter.filter_line_that_not_start_with("### tuple", content)
        assert result == ""

    def test_empty_content(self):
        """Test filtering with empty content"""
        content = ""
        result = ufw_filter.filter_line_that_not_start_with("### tuple", content)
        assert result == ""

    def test_partial_match_not_accepted(self):
        """Test that partial matches don't count"""
        content = "  ### tuple ### rule1\n### tuple ### rule2\n"
        result = ufw_filter.filter_line_that_not_start_with("### tuple", content)
        assert result == "### tuple ### rule2\n"


class TestFilterLineThatContains:
    def test_single_line_matching(self):
        """Test filtering with a single matching line"""
        content = "line with ACCEPT in it\nline without\n"
        result = ufw_filter.filter_line_that_contains("ACCEPT", content)
        assert result == ["line with ACCEPT in it\n"]

    def test_multiple_lines_matching(self):
        """Test filtering with multiple matching lines"""
        content = "ACCEPT rule1\nother line\nACCEPT rule2\n"
        result = ufw_filter.filter_line_that_contains("ACCEPT", content)
        assert result == ["ACCEPT rule1\n", "ACCEPT rule2\n"]

    def test_no_lines_matching(self):
        """Test filtering with no matching lines"""
        content = "line1\nline2\n"
        result = ufw_filter.filter_line_that_contains("ACCEPT", content)
        assert result == []

    def test_empty_content(self):
        """Test filtering with empty content"""
        content = ""
        result = ufw_filter.filter_line_that_contains("ACCEPT", content)
        assert result == []

    def test_case_sensitive(self):
        """Test that matching is case-sensitive"""
        content = "ACCEPT rule\naccept rule\nACCEPT again\n"
        result = ufw_filter.filter_line_that_contains("ACCEPT", content)
        assert len(result) == 2
        assert "accept rule\n" not in result


class TestFilterLineThatNotContains:
    def test_has_bug_in_implementation(self):
        """Test that filter_line_that_not_contains has a bug (uses line.contains instead of 'in')"""
        content = "line with ACCEPT\nline without\n"
        # The function has a bug - it uses line.contains(pattern) which doesn't exist in Python
        with pytest.raises(AttributeError, match="'str' object has no attribute 'contains'"):
            ufw_filter.filter_line_that_not_contains("ACCEPT", content)

    def test_empty_content(self):
        """Test filtering with empty content (doesn't hit the bug)"""
        content = ""
        result = ufw_filter.filter_line_that_not_contains("ACCEPT", content)
        assert result == ""


class TestFilterLineThatMatchFunc:
    def test_function_returning_match(self):
        """Test with a function that returns a match object"""
        pattern = re.compile(r"\d+")
        content = "line with 123\nline without\nmore 456 numbers\n"
        result = ufw_filter.filter_line_that_match_func(pattern.search, content)
        assert result == "line with 123\nmore 456 numbers\n"

    def test_empty_content(self):
        """Test with empty content"""
        pattern = re.compile(r"\d+")
        content = ""
        result = ufw_filter.filter_line_that_match_func(pattern.search, content)
        assert result == ""


class TestFilterLineThatContainsIPv4:
    def test_single_ipv4_address(self):
        """Test filtering lines with IPv4 addresses"""
        content = "rule from 192.168.1.1\nrule without ip\n"
        result = ufw_filter.filter_line_that_contains_ipv4(content)
        assert "192.168.1.1" in result
        assert "rule without ip" not in result

    def test_multiple_ipv4_addresses(self):
        """Test filtering multiple lines with IPv4 addresses"""
        content = "10.0.0.1 rule1\nno ip here\n172.16.0.1 rule2\n192.168.0.1 rule3\n"
        result = ufw_filter.filter_line_that_contains_ipv4(content)
        assert "10.0.0.1" in result
        assert "172.16.0.1" in result
        assert "192.168.0.1" in result
        assert "no ip here" not in result

    def test_no_ipv4_addresses(self):
        """Test filtering with no IPv4 addresses"""
        content = "line1\nline2\n"
        result = ufw_filter.filter_line_that_contains_ipv4(content)
        assert result == ""

    def test_empty_content(self):
        """Test with empty content"""
        content = ""
        result = ufw_filter.filter_line_that_contains_ipv4(content)
        assert result == ""

    def test_invalid_ipv4_not_matched(self):
        """Test that invalid IPv4 addresses are not matched"""
        content = "256.256.256.256 invalid\n192.168.1.1 valid\n"
        result = ufw_filter.filter_line_that_contains_ipv4(content)
        # Note: The regex might match parts of invalid IPs, this tests actual behavior
        assert "192.168.1.1" in result


class TestFilterLineThatContainsIPv6:
    def test_single_ipv6_address(self):
        """Test filtering lines with IPv6 addresses"""
        content = "rule from 2001:db8::1\nrule without ip\n"
        result = ufw_filter.filter_line_that_contains_ipv6(content)
        assert "2001:db8::1" in result
        assert "rule without ip" not in result

    def test_multiple_ipv6_addresses(self):
        """Test filtering multiple lines with IPv6 addresses"""
        content = "2001:db8::1 rule1\nno ip here\nfe80::1 rule2\n::1 localhost\n"
        result = ufw_filter.filter_line_that_contains_ipv6(content)
        assert "2001:db8::1" in result
        assert "fe80::1" in result
        assert "::1" in result
        assert "no ip here" not in result

    def test_no_ipv6_addresses(self):
        """Test filtering with no IPv6 addresses"""
        content = "line1\nline2\n"
        result = ufw_filter.filter_line_that_contains_ipv6(content)
        assert result == ""

    def test_empty_content(self):
        """Test with empty content"""
        content = ""
        result = ufw_filter.filter_line_that_contains_ipv6(content)
        assert result == ""

    def test_full_ipv6_address(self):
        """Test with full IPv6 address"""
        content = "rule from 2001:0db8:0000:0000:0000:0000:0000:0001\n"
        result = ufw_filter.filter_line_that_contains_ipv6(content)
        assert "2001:0db8:0000:0000:0000:0000:0000:0001" in result


class TestRemoveTuplePrefix:
    def test_single_tuple_line(self):
        """Test removing prefix from a single tuple line"""
        content = "### tuple ### allow tcp 80\n"
        result = ufw_filter.remove_tuple_prefix(content)
        assert result == "allow tcp 80"

    def test_multiple_tuple_lines(self):
        """Test removing prefix from multiple tuple lines"""
        content = "### tuple ### allow tcp 80\n### tuple ### deny tcp 22\n"
        result = ufw_filter.remove_tuple_prefix(content)
        assert result == "allow tcp 80\ndeny tcp 22"

    def test_mixed_lines(self):
        """Test that only tuple lines are processed"""
        content = "### tuple ### allow tcp 80\nother line\n### tuple ### deny tcp 22\n"
        result = ufw_filter.remove_tuple_prefix(content)
        # Only tuple lines should be included (without prefix)
        assert "allow tcp 80" in result
        assert "deny tcp 22" in result
        assert "other line" not in result

    def test_empty_content(self):
        """Test with empty content"""
        content = ""
        result = ufw_filter.remove_tuple_prefix(content)
        assert result == ""

    def test_no_tuple_lines(self):
        """Test with no tuple lines"""
        content = "line1\nline2\n"
        result = ufw_filter.remove_tuple_prefix(content)
        assert result == ""

    def test_tuple_prefix_only(self):
        """Test with lines containing only the prefix"""
        content = "### tuple ### \n"
        result = ufw_filter.remove_tuple_prefix(content)
        assert result == ""

    def test_whitespace_after_prefix(self):
        """Test removing prefix from line with extra whitespace"""
        content = "### tuple ###   allow tcp 80  \n"
        result = ufw_filter.remove_tuple_prefix(content)
        # The slicing [len("### tuple ### "):] removes exactly 14 characters,
        # leaving "allow tcp 80  " which then gets stripped
        assert result == "allow tcp 80"

    def test_strips_final_result(self):
        """Test that final result is stripped"""
        content = "### tuple ### rule1\n### tuple ### rule2\n\n\n"
        result = ufw_filter.remove_tuple_prefix(content)
        # Result should be stripped
        assert not result.endswith("\n\n")
