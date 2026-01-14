import logging
import re

from salt.modules import cmdmod

from saltext.ufw.utils.ufw.exceptions import UFWCommandError

log = logging.getLogger(__name__)


class UFWClient:
    def __init__(self):
        self.ufw_path = "/usr/sbin/ufw"
        self.grep_path = cmdmod.which("grep") or "/bin/grep"
        self.user_rules_files = [
            "/lib/ufw/user.rules",
            "/lib/ufw/user6.rules",
            "/etc/ufw/user.rules",
            "/etc/ufw/user6.rules",
            "/var/lib/ufw/user.rules",
            "/var/lib/ufw/user6.rules",
        ]

    def _execute(self, cmd, ignore_errors=False):
        log.debug(f"Executing UFW command: {cmd}")

        out = cmdmod.run_all(
            cmd, python_shell=False, ignore_retcode=ignore_errors, redirect_stderr=False
        )
        if out["retcode"] != 0 and not ignore_errors:
            raise UFWCommandError(cmd, out)
        return out

    def _build_args(self, **kwargs):
        args = []
        kwargs = {k: v for k, v in kwargs.items() if v is not None}

        for k, v in kwargs.items():
            if k == "insert":
                args.append(f"insert {str(v)}")
            elif k == "action":
                args.append(f"{v}")
            elif k == "direction":
                args.append(f"{v}")
            elif k == "interface":
                args.append(f"on {v}")
            elif k == "from_ip":
                args.append(f"from {v}")
            elif k == "from_port":
                args.append(f"port {v}")
            elif k == "to_ip":
                args.append(f"to {v}")
            elif k == "to_port":
                args.append(f"port {v}")
            elif k == "proto":
                args.append(f"proto {v}")
            elif k == "app":
                args.append(f"app {v}")
            elif k == "comment" and v:
                ufw_major, ufw_minor, dummy = self.version()
                # comment is supported only in ufw version after 0.35
                if (ufw_major == 0 and ufw_minor >= 35) or ufw_major > 0:
                    args.append(f"comment '{v}'")
            else:
                args.append(str(v))

        return args

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

    def get_current_rules(self):
        cmd = [self.grep_path, "-h", "'^### tuple'"]
        cmd.extend(self.user_rules_files)
        cmd = " ".join(cmd)
        out = self._execute(cmd, ignore_errors=True)
        return out["stdout"]


def get_client():
    """
    Get an instance of the UFWClient.
    """
    return UFWClient()
