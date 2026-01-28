import logging
import re

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError
from salt.modules import cmdmod

from saltext.ufw.utils.ufw import network as netutil

log = logging.getLogger(__name__)


class UFWClient:
    def __init__(self):
        self.ufw_path = "/usr/sbin/ufw"

    def _execute(self, cmd, ignore_errors=False):
        log.debug(f"Executing UFW command: {cmd}")

        out = cmdmod.run_all(
            cmd, python_shell=False, ignore_retcode=ignore_errors, redirect_stderr=False
        )
        if out["retcode"] != 0 and not ignore_errors:
            raise CommandExecutionError(cmd, out)
        return out

    def set_default_policy(self, policy, direction="incoming", dry_run=False):
        """
        Set the default UFW policy.
        """
        cmd = [self.ufw_path]

        if dry_run:
            cmd.append("--dry-run")

        cmd.extend(["default", policy, direction])

        return self._execute(" ".join(cmd))

    def set_logging_level(self, level, dry_run=False):
        """
        Set UFW logging level.
        """
        cmd = [self.ufw_path]

        if dry_run:
            cmd.append("--dry-run")

        cmd.extend(["logging", level])

        return self._execute(" ".join(cmd))

    def enable(self, dry_run=False):
        """
        Enable UFW.
        """
        cmd = [self.ufw_path]
        cmd.append("--force")
        if dry_run:
            cmd.append("--dry-run")
        cmd.append("enable")

        return self._execute(" ".join(cmd))

    def disable(self, dry_run=False):
        """
        Disable UFW.
        """
        cmd = [self.ufw_path]
        if dry_run:
            cmd.append("--dry-run")
        cmd.append("disable")

        return self._execute(" ".join(cmd))

    def reload(self, dry_run=False):
        """
        Reload UFW.
        """
        cmd = [self.ufw_path]
        if dry_run:
            cmd.append("--dry-run")
        cmd.append("reload")

        return self._execute(" ".join(cmd))

    def reset(self, dry_run=False):
        """
        Reset UFW.
        """
        cmd = [self.ufw_path]
        if dry_run:
            cmd.append("--dry-run")
        cmd.append("reset")

        return self._execute(" ".join(cmd))

    def status(self, verbose=False, numbered=False):
        """
        Get UFW status.
        """
        cmd = [self.ufw_path, "status"]
        if verbose and numbered:
            raise SaltInvocationError("Cannot use both 'verbose' and 'numbered' options together.")

        if numbered:
            cmd.append("numbered")
        if verbose:
            cmd.append("verbose")

        return self._execute(" ".join(cmd))

    def update_rule(self, fwrule, dry_run=False):
        """
        Update rules by appending, deleting, or modifying existing rules with fwrule.
        """

        cmd = [self.ufw_path]
        if dry_run:
            cmd.append("--dry-run")

        rule_def = fwrule.build_rule_string()

        cmd.append(rule_def)
        return self._execute(" ".join(cmd))

    def version(self):
        """
        Get UFW version.
        """
        out = self._execute([self.ufw_path, "--version"])
        out = out["stdout"]
        lines = [x for x in out.split("\n") if x.strip() != ""]
        if len(lines) == 0:
            return "Unknown"
        matches = re.search(r"^ufw\s+(\d+)\.(\d+)(?:\.(\d+))?.*$", lines[0])
        if matches is None:
            raise CommandExecutionError(
                "version", {"retcode": 1, "stderr": "Unable to parse UFW version."}
            )

        # Convert version to numbers
        major = int(matches.group(1))
        minor = int(matches.group(2))
        rev = 0
        if matches.group(3) is not None:
            rev = int(matches.group(3))

        return major, minor, rev


class FirewallRule:  # pylint: disable=too-many-instance-attributes
    """
    Represents a UFW firewall rule.
    """

    def __init__(
        self,
        action,
        protocol,
        dport="any",
        dst="0.0.0.0/0",
        sport="any",
        src="0.0.0.0/0",
        direction="in",
        forward=False,
        comment="",
    ):
        self.delete = False
        self.dst = dst
        self.src = src
        self.dport = ""
        self.sport = ""
        self.protocol = ""
        self.position = 0
        self.dapp = ""
        self.sapp = ""
        self.forward = forward
        self.interface_in = ""
        self.interface_out = ""
        self.direction = ""
        self.logtype = ""
        self.comment = ""
        self.protocol = protocol

        self.set_action(action)
        self.set_direction(direction)
        self.set_port(dport, "dst")
        self.set_port(sport, "src")
        self.set_comment(comment)

    def set_action(self, action):
        """Sets action of the rule

        action
            The action of the rule, either 'allow', 'deny', 'reject' or 'limit'.
        """
        # Split the action as we can also have log info appended
        tmp = action.lower().split("_")
        self.action = tmp[0]

        if len(tmp) > 1:
            self.set_logtype(tmp[1])

    def set_logtype(self, logtype):
        """Sets logtype of the rule

        logtype
            The log type, either 'log' or 'log-all'.
        """
        if not logtype:
            return

        if logtype.lower() == "log-all" or logtype.lower() == "log":
            self.logtype = logtype.lower()

    def set_port(self, port, loc="dst"):
        """
        Sets port for source or destination

        This function will check if the port is a valid port number/range or
        application name.

        port
            The port number, port range or application name.
        loc
            The location of the port, either 'src' or 'dst'.
        """

        if port == "any" or port is None:
            return

        is_app = False

        if loc == "src":
            if netutil.is_port_number(port):
                self.sport = str(port)
                self.sapp = ""
            else:
                self.sport = ""
                self.sapp = port
                is_app = True
        else:
            if netutil.is_port_number(port):
                self.dport = str(port)
                self.dapp = ""
            else:
                self.dport = ""
                self.dapp = port
                is_app = True

        if is_app:
            self.protocol = "any"  # Reset protocol if application is set

    def set_comment(self, comment):
        """Sets comment of the rule

        comment
            The comment string.
        """
        if comment is not None:
            self.comment = comment

    def set_direction(self, direction):
        """Sets direction of the rule

        direction
            The direction of the rule, either 'in', 'out' or 'forward'.
        """
        if direction in ["in", "out"]:
            self.direction = direction
        elif direction == "forward":
            self.forward = True
            self.direction = "in"

    def set_interface(self, if_direction, name):
        """
        Sets interface for in or out direction

        if_direction
            The direction of the interface, either 'in' or 'out'.

        name
            The name of the interface.

        """

        if ":" in str(name):
            raise ValueError("Cannot use interface aliases")

        if len(str(name)) == 0:
            raise ValueError("Interface name cannot be empty")

        if len(str(name)) > 15:
            raise ValueError("Interface name too long")

        if if_direction == "in":
            self.interface_in = name
        else:
            self.interface_out = name

    def build_rule_string(self):
        """Builds the rule string for ufw command"""
        parts = []

        if self.forward:
            parts.append("route")
        else:
            parts.append("rule")

        # Do we want to delete or add the rule
        if self.delete:
            parts.append("delete")

        # Check if we want to insert, prepend or append
        if self.position > 0:
            if self.delete:
                parts.append(f"{self.position}")
                # When deleting, just the position number is needed
                return " ".join(parts)

            parts.append(f"insert {self.position}")
        elif self.position == -1:
            parts.append("prepend")
        # If position is 0, we do not add any argument (append by default)

        parts.append(f"{self.action}")

        if self.interface_in:
            parts.append(f"in on {self.interface_in}")

        if self.interface_out:
            parts.append(f"out on {self.interface_out}")

        if self.logtype:
            parts.append(f"{self.logtype}")

        if self.protocol:
            if self.dapp == "" and self.sapp == "":
                # Only add protocol if no application is specified
                parts.append(f"proto {self.protocol}")

        parts.append(f"from {self.src}")
        if self.sport != "" and self.sapp == "":
            parts.append(f"port {self.sport}")
        if self.sapp != "":
            parts.append(f"app {self.sapp}")

        parts.append(f"to {self.dst}")
        if self.dport != "" and self.dapp == "":
            parts.append(f"port {self.dport}")
        if self.dapp != "":
            parts.append(f"app {self.dapp}")

        if self.comment != "":
            parts.append(f'comment "{self.comment}"')

        return " ".join(parts)

    def validate(self):
        """Validates the rule parameters"""
        valid_actions = ["allow", "deny", "reject", "limit"]
        valid_directions = ["in", "out"]

        if self.action not in valid_actions:
            raise ValueError(f"Invalid action: {self.action}")

        if not self.forward and self.direction not in valid_directions:
            raise ValueError(f"Invalid direction: {self.direction}")

        if not netutil.is_port_number(self.sport) and self.sport != "":
            raise ValueError(f"Invalid source port: {self.sport}")

        if not netutil.is_port_number(self.dport) and self.dport != "":
            raise ValueError(f"Invalid destination port: {self.dport}")

        if not netutil.is_ipv4(self.src) and not netutil.is_ipv6(self.src):
            raise ValueError(f"Invalid source IP address: {self.src}")

        if not netutil.is_ipv4(self.dst) and not netutil.is_ipv6(self.dst):
            raise ValueError(f"Invalid destination IP address: {self.dst}")

        if isinstance(self.position, int):
            if self.position < -1:
                raise ValueError(f"Invalid position: {self.position}")
        else:
            raise ValueError(f"Invalid position: {self.position}")


def rules_match(x, y):  # pylint: disable=too-many-return-statements
    """
    Compares two FirewallRule objects

    Return codes:

    - ``0`` - match
    - ``1`` - no match
    - ``-1`` - match all but action, log-type and/or comment
    """
    if x.dport != y.dport:
        return 1
    if x.sport != y.sport:
        return 1
    if x.protocol != y.protocol:
        return 1
    if x.dst != y.dst:
        return 1
    if x.src != y.src:
        return 1
    if x.dapp.lower() != y.dapp.lower():
        return 1
    if x.sapp.lower() != y.sapp.lower():
        return 1
    if x.interface_in != y.interface_in:
        return 1
    if x.interface_out != y.interface_out:
        return 1
    if x.direction != y.direction:
        return 1
    if x.forward != y.forward:
        return 1
    if x.action == y.action and x.logtype == y.logtype and x.comment == y.comment:
        return 0

    log.debug("Action, logtype or comment mismatch")
    return -1


def get_client():
    """
    Get an instance of the UFWClient.
    """
    return UFWClient()
