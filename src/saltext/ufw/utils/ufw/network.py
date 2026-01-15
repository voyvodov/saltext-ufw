import re


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


def is_starting_by_ipv4(ip):
    if ip is None:
        return False
    return ipv4_regexp.match(ip) is not None


def is_starting_by_ipv6(ip):
    if ip is None:
        return False
    return ipv6_regexp.match(ip) is not None
