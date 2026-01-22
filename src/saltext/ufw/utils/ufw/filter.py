# Filters are taken from https://github.com/ansible-collections/community.general/blob/main/plugins/modules/ufw.py

from saltext.ufw.utils.ufw.network import ipv4_regexp
from saltext.ufw.utils.ufw.network import ipv6_regexp


def filter_line_that_not_start_with(pattern, content):
    if isinstance(content, list):
        return "".join([line for line in content if not line.startswith(pattern)])
    return "".join([line for line in content.splitlines(True) if line.startswith(pattern)])


def filter_line_that_contains(pattern, content):
    if isinstance(content, list):
        return [line for line in content if pattern in line]
    return [line for line in content.splitlines(True) if pattern in line]


def filter_line_that_not_contains(pattern, content):
    if isinstance(content, list):
        return "".join([line for line in content if not line.contains(pattern)])
    return "".join([line for line in content.splitlines(True) if not line.contains(pattern)])


def filter_line_that_match_func(match_func, content):
    if isinstance(content, list):
        return "".join([line for line in content if match_func(line) is not None])
    return "".join([line for line in content.splitlines(True) if match_func(line) is not None])


def filter_line_that_contains_ipv4(content):
    return filter_line_that_match_func(ipv4_regexp.search, content)


def filter_line_that_contains_ipv6(content):
    return filter_line_that_match_func(ipv6_regexp.search, content)


def remove_tuple_prefix(content):
    return "".join(
        [
            line[len("### tuple ### ") :]
            for line in content.splitlines(True)
            if line.startswith("### tuple ### ")
        ]
    ).strip()
