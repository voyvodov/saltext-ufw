import re

USER_RULES_FILES = [
    "/lib/ufw/user.rules",
    "/lib/ufw/user6.rules",
    "/etc/ufw/user.rules",
    "/etc/ufw/user6.rules",
    "/var/lib/ufw/user.rules",
    "/var/lib/ufw/user6.rules",
]


def get_firewall_rules():
    pat_tuple = re.compile(r"^### tuple ###\s*")
    pat_iface_in = re.compile(r"in_\w+")
    pat_iface_out = re.compile(r"out_\w+")

    data = list_current_rules()

    rules = []

    index = 1
    for orig_line in data:
        line = orig_line
        comment = ""
        # comment= should always be last, so just strip it out
        if " comment=" in orig_line:
            line, hexv = orig_line.split(r" comment=")
            comment = bytes.fromhex(hexv.strip()).decode("utf-8")

        tupl = pat_tuple.sub("", line)
        parts = re.split(r"\s+", tupl.strip())

        if len(parts) < 6 or len(parts) > 9:
            # Skip invalid lines
            continue
        dtype = "in"
        interface_in = ""
        interface_out = ""
        if len(parts) == 7 or len(parts) == 9:
            dtype = parts[-1].split("_")[0]
            if "_" in parts[-1]:
                if (
                    "!" in parts[-1]
                    and pat_iface_in.search(parts[-1])
                    and pat_iface_out.search(parts[-1])
                ):
                    # in_eth0!out_eth1
                    interface_in = parts[-1].split("!")[0].partition("_")[2]
                    interface_out = parts[-1].split("!")[1].partition("_")[2]
                elif parts[-1].startswith("in_"):
                    # in_eth0
                    interface_in = parts[-1].partition("_")[2]
                elif parts[-1].startswith("out_"):
                    # out_eth0
                    interface_out = parts[-1].partition("_")[2]
                else:
                    continue

        try:
            action = parts[0]
            forward = False

            # route rules "route:<action>"
            if ":" in action:
                action = action.split(":")[1]
                forward = True

            rule = {
                "action": action,
                "protocol": parts[1],
                "dport": parts[2],
                "dst": parts[3],
                "sport": parts[4],
                "src": parts[5],
                "direction": dtype,
                "interface_in": "",
                "interface_out": "",
                "dapp": "",
                "sapp": "",
                "forward": forward,
                "comment": comment,
                "logtype": "",
            }
            if len(parts) > 7:
                pat_space = re.compile("%20")
                if parts[6] != "-":
                    rule["dapp"] = pat_space.sub(" ", parts[6])
                if parts[7] != "-":
                    rule["sapp"] = pat_space.sub(" ", parts[7])

            if interface_in != "":
                rule["interface_in"] = interface_in
            if interface_out != "":
                rule["interface_out"] = interface_out
            rule["index"] = index
            index += 1

            rules.append(rule)
        except IndexError:
            return None
    return rules


def list_current_rules():

    pat_tuple = re.compile(r"^### tuple ###\s*")
    lines = []

    for f in USER_RULES_FILES:
        try:
            with open(f, encoding="utf-8") as rf:
                data = rf.read()
        except FileNotFoundError:
            continue

        for line in data.splitlines():
            if pat_tuple.match(line):
                lines.append(line)

    return lines
