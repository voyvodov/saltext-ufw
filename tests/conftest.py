import logging
import os
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from saltfactories.utils import random_string

from saltext.ufw import PACKAGE_ROOT
from saltext.ufw.utils.ufw import client as ufw_client_module

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
def ufw_client(monkeypatch, firewall_rules_file):
    # mock = MagicMock(spec_set=ufw_client_module.UFWClient)
    # default_cmd_response = {"stdout": "", "stderr": "", "retcode": 0}
    # mock._execute.return_value = default_cmd_response
    # # mock.execute.return_value = default_cmd_response

    # mock.execute.side_effect = execute_side_effect
    # mock.version.return_value = (0, 0, 0)
    # # mock.get_current_rules.return_value = ""
    # mock.get_current_rules.side_effect = get_current_rules_side_effect

    with patch("saltext.ufw.utils.ufw.client.UFWClient") as mocked_cls:
        mock = UFWClientMock(rules_file=firewall_rules_file)
        mocked_cls.return_value = mock
        monkeypatch.setattr(ufw_client_module, "get_client", MagicMock(return_value=mock))

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

    def reset(self):
        with open(self.mock_firewall_rules_file, "w", encoding="utf-8") as f:
            f.write("")

    def cleanup(self):
        try:
            os.remove(self.mock_firewall_rules_file)
        except FileNotFoundError:
            pass

    def execute(self, command, force=False, dry_run=False, **kwargs):

        ret = {}
        if command == "status":
            ret = {
                "stdout": f"""Status: {self.state}
    Logging: {self.logging_level}
    Default: {self.default_policy['incoming']} (incoming), {self.default_policy['outgoing']} (outgoing), {self.default_policy['routed']} (routed)
    New profiles: skip""",
                "stderr": "",
                "retcode": 0,
            }

        if command == "reload":
            ret = {
                "stdout": "Firewall reloaded",
                "stderr": "",
                "retcode": 0,
            }

        if command == "enable" and force:
            if not dry_run:
                self.state = "active"
            ret = {
                "stdout": "Firewall is active and enabled on system startup",
                "stderr": "",
                "retcode": 0,
            }

        if command == "disable":
            if not dry_run:
                self.state = "inactive"
            ret = {
                "stdout": "Firewall stopped and disabled on system startup",
                "stderr": "",
                "retcode": 0,
            }

        if command == "logging":
            level = kwargs.get("level", "off")
            if level != "off":
                level = f"on ({level})"

            if not dry_run:
                self.logging_level = level
            ret = {
                "stdout": f"Logging set to {level}",
                "stderr": "",
                "retcode": 0,
            }

        if command == "default":
            policy = kwargs.get("policy", "deny")
            direction = kwargs.get("direction", "incoming")

            if not dry_run:
                self.default_policy[direction] = policy
            ret = {
                "stdout": f"Default {direction} policy set to {policy}",
                "stderr": "",
                "retcode": 0,
            }

        if command == "reset":
            self.reset()
            ret = {
                "stdout": "Firewall reset to default state",
                "stderr": "",
                "retcode": 0,
            }

        if command == "rule":
            method = kwargs.get("method") or None
            direction = kwargs.get("direction") or "in"
            action = kwargs.get("action") or "allow"
            dport = kwargs.get("dport") or "any"
            sport = kwargs.get("sport") or "any"
            proto = kwargs.get("proto") or "any"
            src = kwargs.get("src") or "0.0.0.0/0"
            dst = kwargs.get("dst") or "0.0.0.0/0"

            if (kwargs.get("interface") or None) is not None:
                interface = kwargs.get("interface")
                direction = f"{direction}_{interface}"

            rule_line = f"### tuple ### {action} {proto} {dport} {dst} {sport} {src} {direction}\n"

            if method == "delete":
                ret = self._delete_rule(rule_line, dry_run=dry_run)
            else:
                ret = self._add_rule(rule_line, dry_run=dry_run)

        return ret

    def _add_rule(self, rule_line, dry_run=False):
        current_rules = self.get_current_rules().splitlines()
        if rule_line.strip() in current_rules:
            return {
                "stdout": "Skipping adding existing rule",
                "stderr": "",
                "retcode": 0,
            }
        if dry_run:
            join = "\n".join(current_rules + [rule_line.strip()])
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

    def get_current_rules(self):
        with open(self.mock_firewall_rules_file, encoding="utf-8") as f:
            rules = f.read()
        return rules
