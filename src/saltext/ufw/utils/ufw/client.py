import logging
import re

from salt.modules import cmdmod

from saltext.ufw.utils.ufw.exceptions import UFWCommandError
from saltext.ufw.utils.ufw.network import is_port_number

log = logging.getLogger(__name__)


def _format_port_or_app(value):
    """Return formatted argument for app profile or port number."""
    if value is None:
        return None

    if is_port_number(value):
        return f"port {value}"

    return f"app '{str(value)}'"


def _is_app(sport, dport):
    """Determine if either sport or dport is an application profile."""
    if not is_port_number(sport) and sport is not None:
        return True
    if not is_port_number(dport) and dport is not None:
        return True
    return False


class UFWClient:
    def __init__(self):
        self.ufw_path = "/usr/sbin/ufw"

    def _execute(self, cmd, ignore_errors=False):
        log.debug(f"Executing UFW command: {cmd}")

        out = cmdmod.run_all(
            cmd, python_shell=False, ignore_retcode=ignore_errors, redirect_stderr=False
        )
        if out["retcode"] != 0 and not ignore_errors:
            raise UFWCommandError(cmd, out)
        return out

    def _build_args(self, **kwargs):
        cmd_args = []
        kwargs = {k: v for k, v in kwargs.items() if v is not None}

        def _append_port_arg(key):
            val = kwargs.get(key)
            formatted = _format_port_or_app(val)
            if formatted is not None:
                cmd_args.append(formatted)
            if key in kwargs:
                del kwargs[key]

        # Check if we have app defined. This affects how we handle proto and port args.
        is_app_defined = _is_app(kwargs.get("sport"), kwargs.get("dport"))

        # If app is defined, remove proto argument as it's not applicable
        if is_app_defined and "proto" in kwargs:
            del kwargs["proto"]  # proto is not applicable for app profiles

        # Order here is important
        if "method" in kwargs:
            cmd_args.append(f"{kwargs['method']}")
            del kwargs["method"]

        if "action" in kwargs:
            cmd_args.append(f"{kwargs['action']}")
            del kwargs["action"]

        if "policy" in kwargs:
            cmd_args.append(f"{kwargs['policy']}")
            del kwargs["policy"]

        if "insert" in kwargs:
            cmd_args.append(f"insert {str(kwargs['insert'])}")
            del kwargs["insert"]

        if "direction" in kwargs:
            cmd_args.append(f"{kwargs['direction']}")
            del kwargs["direction"]

        if "interface" in kwargs:
            cmd_args.append(f"on {kwargs['interface']}")
            del kwargs["interface"]

        if "interface_in" in kwargs:
            cmd_args.append(f"in on {kwargs['interface_in']}")
            del kwargs["interface_in"]

        if "interface_out" in kwargs:
            cmd_args.append(f"out on {kwargs['interface_out']}")
            del kwargs["interface_out"]

        if "rule_log" in kwargs:
            if kwargs["rule_log"]:
                cmd_args.append("log")
            del kwargs["rule_log"]

        # If we still have "proto" argument, append it here
        if "proto" in kwargs:
            cmd_args.append(f"proto {kwargs['proto']}")
            del kwargs["proto"]

        # Ensure source is correctly placed
        if "src" in kwargs:
            cmd_args.append(f"from {kwargs['src']}")
            _append_port_arg("sport")
            del kwargs["src"]

        # Ensure destination is correctly placed
        if "dst" in kwargs:
            cmd_args.append(f"to {kwargs['dst']}")
            _append_port_arg("dport")
            del kwargs["dst"]

        # Append sport and dport if not already processed
        if "sport" in kwargs:
            _append_port_arg("sport")

        if "dport" in kwargs:
            _append_port_arg("dport")

        if "comment" in kwargs and kwargs["comment"] != "":
            ufw_major, ufw_minor, dummy = self.version()
            # comment is supported only in ufw version after 0.35
            if (ufw_major == 0 and ufw_minor >= 35) or ufw_major > 0:
                cmd_args.append(f"comment '{kwargs['comment']}'")
            del kwargs["comment"]

        # Process remaining arguments
        for k, v in kwargs.items():
            cmd_args.append(f"{v}")

        return cmd_args

    def execute(self, command, force=False, dry_run=False, **kwargs):
        """
        Execute a UFW command and return the output.
        Raise UFWCommandError if the command fails.
        """

        cmd = [self.ufw_path]
        if force:
            cmd.append("--force")
        if dry_run:
            cmd.append("--dry-run")
        cmd.append(command)
        cmd.extend(self._build_args(**kwargs))

        cmd = " ".join(cmd)

        return self._execute(cmd)

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
            raise UFWCommandError(
                "version", {"retcode": 1, "stderr": "Unable to parse UFW version."}
            )

        # Convert version to numbers
        major = int(matches.group(1))
        minor = int(matches.group(2))
        rev = 0
        if matches.group(3) is not None:
            rev = int(matches.group(3))

        return major, minor, rev


def get_client():
    """
    Get an instance of the UFWClient.
    """
    return UFWClient()
