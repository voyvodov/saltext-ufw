import re

PORT_VALUE_RE = re.compile(r"^\d+(?::\d+)?$")


def compile_ipv4_regexp():
    r = r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    r += r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])"
    return re.compile(r)


def compile_ipv6_regexp():
    """
    validation pattern provided by :
    https://stackoverflow.com/questions/53497/regular-expression-that-matches-
    valid-ipv6-addresses#answer-17871737
    """
    r = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:"
    r += r"|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}"
    r += r"(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4})"
    r += r"{1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]"
    r += r"{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]"
    r += r"{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4})"
    r += r"{0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]"
    r += r"|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}"
    r += r"[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}"
    r += r"[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    return re.compile(r)


ipv4_regexp = compile_ipv4_regexp()
ipv6_regexp = compile_ipv6_regexp()


def is_ipv4(ip):
    """
    Check if the given IP address is a valid IPv4 address.
    """
    if ip is None:
        return False
    return ipv4_regexp.match(ip) is not None


def is_ipv6(ip):
    """
    Check if the given IP address is a valid IPv6 address.
    """
    if ip is None:
        return False
    return ipv6_regexp.match(ip) is not None


def is_port_number(value):
    """
    Check if the given value is a valid port number or port range.

    Valid port number is an integer between 1 and 65535.

    Valid port range is in the format "start:end" where start and end are
    integers between 1 and 65535 and start is less than or equal to end.
    """
    if value is None:
        return False
    if not bool(PORT_VALUE_RE.fullmatch(str(value))):
        return False

    parts = str(value).split(":")
    try:
        if len(parts) == 1:
            port = int(parts[0])
            if 1 <= port <= 65535:
                return True
        elif len(parts) == 2:
            start_port = int(parts[0])
            end_port = int(parts[1])
            if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                return True
    except ValueError:
        pass

    return False
