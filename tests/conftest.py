import logging
import os
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from saltfactories.utils import random_string

from saltext.ufw import PACKAGE_ROOT
from saltext.ufw.utils.ufw import rules as utilrules

# Reset the root logger to its default level(because salt changed it)
logging.root.setLevel(logging.WARNING)


# This swallows all logging to stdout.
# To show select logs, set --log-cli-level=<level>
for handler in logging.root.handlers[:]:  # pragma: no cover
    logging.root.removeHandler(handler)
    handler.close()


@pytest.fixture(scope="session")
def salt_factories_config():  # pragma: no cover
    """
    Return a dictionary with the keyword arguments for FactoriesManager
    """
    return {
        "code_dir": str(PACKAGE_ROOT),
        "inject_sitecustomize": "COVERAGE_PROCESS_START" in os.environ,
        "start_timeout": 120 if os.environ.get("CI") else 60,
    }


@pytest.fixture(scope="module")
def master_config():  # pragma: no cover
    """
    Salt master configuration overrides for integration tests.
    """
    return {}


@pytest.fixture(scope="module")
def master_config_overrides():  # pragma: no cover
    """
    Salt master configuration overrides for integration tests.
    """
    return {}


@pytest.fixture(scope="module")
def master(salt_factories, master_config, master_config_overrides):  # pragma: no cover
    return salt_factories.salt_master_daemon(
        random_string("master-"), overrides=master_config_overrides, defaults=master_config
    )


@pytest.fixture(scope="module")
def minion_config():  # pragma: no cover
    """
    Salt minion configuration overrides for integration tests.
    """
    return {}


@pytest.fixture(scope="module")
def minion_config_overrides():  # pragma: no cover
    """
    You can override the default configuration per package by overriding this
    fixture in a conftest.py file.
    """
    return {}


@pytest.fixture(scope="module")
def minion(master, minion_config, minion_config_overrides):  # pragma: no cover
    return master.salt_minion_daemon(
        random_string("minion-"), defaults=minion_config, overrides=minion_config_overrides
    )


@pytest.fixture()
def ufw_client(firewall_rules_file):
    # mock = MagicMock(spec_set=ufw_client_module.UFWClient)
    # default_cmd_response = {"stdout": "", "stderr": "", "retcode": 0}
    # mock._execute.return_value = default_cmd_response
    # # mock.execute.return_value = default_cmd_response

    # mock.execute.side_effect = execute_side_effect
    # mock.version.return_value = (0, 0, 0)
    # # mock.get_current_rules.return_value = ""
    # mock.get_current_rules.side_effect = get_current_rules_side_effect

    with patch("saltext.ufw.utils.ufw.UFWClient") as mocked_cls:
        mock = UFWClientMock(rules_file=firewall_rules_file)
        mocked_cls.return_value = mock
        patch("saltext.ufw.utils.ufw.get_client", MagicMock(return_value=mock)).start()

        yield mock


@pytest.fixture
def firewall_rules_file():
    return "/tmp/mock_ufw_user.rules"


@pytest.fixture(autouse=True)
def mock_list_current_rules(firewall_rules_file):
    with patch("saltext.ufw.utils.ufw.rules.USER_RULES_FILES", [firewall_rules_file]):
        yield


class UFWClientMock:
    rules_file = None
    mock_firewall_rules_file = ""
    logging_level = "off"
    state = "active"
    default_policy = {
        "incoming": "deny",
        "outgoing": "allow",
        "routed": "deny",
    }

    def __init__(self, rules_file=None):
        if rules_file is not None:
            self.mock_firewall_rules_file = rules_file

    def _reset(self):
        with open(self.mock_firewall_rules_file, "w", encoding="utf-8") as f:
            f.write("")

    def cleanup(self):
        try:
            # os.remove(self.mock_firewall_rules_file)
            pass
        except FileNotFoundError:
            pass

    def set_default_policy(self, policy, direction="incoming", dry_run=False):
        if not dry_run:
            self.default_policy[direction] = policy
        return {
            "stdout": f"Default {direction} policy set to {policy}",
            "stderr": "",
            "retcode": 0,
        }

    def set_logging_level(self, level, dry_run=False):
        if level != "off":
            level = f"on ({level})"

        if not dry_run:
            self.logging_level = level
        return {
            "stdout": f"Logging set to {level}",
            "stderr": "",
            "retcode": 0,
        }

    def enable(self, dry_run=False):
        if not dry_run:
            self.state = "active"
        return {
            "stdout": "Firewall is active and enabled on system startup",
            "stderr": "",
            "retcode": 0,
        }

    def disable(self, dry_run=False):
        if not dry_run:
            self.state = "inactive"
        return {
            "stdout": "Firewall stopped and disabled on system startup",
            "stderr": "",
            "retcode": 0,
        }

    def reload(self, dry_run=False):
        if dry_run:
            return {
                "stdout": "",
                "stderr": "",
                "retcode": 0,
            }

        return {
            "stdout": "Firewall reloaded",
            "stderr": "",
            "retcode": 0,
        }

    def reset(self, dry_run=False):
        if not dry_run:
            self._reset()
        return {
            "stdout": "Firewall reset to default state",
            "stderr": "",
            "retcode": 0,
        }

    def status(self, verbose=False, numbered=False):
        out = f"""Status: {self.state}
    Logging: {self.logging_level}
    Default: {self.default_policy['incoming']} (incoming), {self.default_policy['outgoing']} (outgoing), {self.default_policy['routed']} (routed)
    New profiles: skip"""

        if numbered or verbose:
            out += "\n\nTo                         Action      From\n--                         ------      ----"

        return {
            "stdout": out,
            "stderr": "",
            "retcode": 0,
        }

    def update_rule(self, fwrule, dry_run=False):

        sapp = None
        dapp = None
        dport = fwrule.dport if fwrule.dport != "" else "any"
        sport = fwrule.sport if fwrule.sport != "" else "any"
        proto = fwrule.protocol
        action = fwrule.action

        if fwrule.forward:
            action = f"route:{action}"

        if fwrule.logtype != "":
            action = f"{action}_{fwrule.logtype}"

        rule_line = f"### tuple ### {action} {proto} {dport} {fwrule.dst} {sport} {fwrule.src} {fwrule.direction}"

        if fwrule.dapp != "":
            dapp = "OpenSSH"
            dport = "22"
            proto = "tcp"
        if fwrule.sapp != "":
            sapp = "OpenSSH"
            sport = "22"
            proto = "tcp"

        if sapp is not None or dapp is not None:
            rule_line = f"### tuple ### {action} {proto} {dport} {fwrule.dst} {sport} {fwrule.src} {sapp or '-'} {dapp or '-'} {fwrule.direction}"

        if fwrule.comment != "":
            comment = bytes(fwrule.comment, "utf-8").hex()
            rule_line += f" comment={comment}"

        # Add the final new line...
        rule_line += "\n"

        if fwrule.delete:
            return self._delete_rule(rule_line, dry_run=dry_run)

        return self._add_rule(rule_line, dry_run=dry_run)

    def _add_rule(self, rule_line, dry_run=False):
        current_rules = utilrules.list_current_rules()
        if rule_line in current_rules:
            return {
                "stdout": "Skipping adding existing rule",
                "stderr": "",
                "retcode": 0,
            }
        if dry_run:
            join = "".join(current_rules + [rule_line])
            return {
                "stdout": join,
                "stderr": "",
                "retcode": 0,
            }

        with open(self.mock_firewall_rules_file, "a", encoding="utf-8") as f:
            f.write(rule_line)

        return {
            "stdout": "Rule added",
            "stderr": "",
            "retcode": 0,
        }

    def _delete_rule(self, rule_line, dry_run=False):
        with open(self.mock_firewall_rules_file, encoding="utf-8") as f:
            rules = f.read()

        if dry_run:
            return {
                "stdout": rules.replace(rule_line, ""),
                "stderr": "",
                "retcode": 0,
            }

        with open(self.mock_firewall_rules_file, "w", encoding="utf-8") as f:
            f.write(rules.replace(rule_line, ""))

        return {
            "stdout": "Rule removed",
            "stderr": "",
            "retcode": 0,
        }
