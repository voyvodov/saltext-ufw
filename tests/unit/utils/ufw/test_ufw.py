from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.ufw.utils.ufw import FirewallRule
from saltext.ufw.utils.ufw import UFWClient
from saltext.ufw.utils.ufw import get_client
from saltext.ufw.utils.ufw import rules_match


class TestExecute:
    @patch("salt.modules.cmdmod.run_all")
    def test_execute_success(self, mock_run_all):
        mock_run_all.return_value = {"retcode": 0, "stdout": "ok"}
        client = UFWClient()
        result = client._execute("ufw status")
        assert result["stdout"] == "ok"

    @patch("salt.modules.cmdmod.run_all")
    def test_execute_failure(self, mock_run_all):
        mock_run_all.return_value = {"retcode": 1, "stdout": "", "stderr": "boom"}
        client = UFWClient()
        with pytest.raises(CommandExecutionError):
            client._execute("ufw status")


class TestFirewallRuleBuilding:
    def test_build_rule_string_with_ports(self):
        rule = FirewallRule(
            action="allow",
            protocol="tcp",
            dport=22,
            dst="10.0.0.2",
            sport=53,
            src="10.0.0.1",
        )

        assert (
            rule.build_rule_string()
            == "rule allow proto tcp from 10.0.0.1 port 53 to 10.0.0.2 port 22"
        )

    def test_build_route_rule_includes_interfaces_and_comment(self):
        rule = FirewallRule(
            action="deny_log",
            protocol="udp",
            dport="Apache",
            direction="forward",
            comment="audit",
        )
        rule.set_interface("in", "eth0")
        rule.set_interface("out", "eth1")

        assert (
            rule.build_rule_string()
            == 'route deny in on eth0 out on eth1 log from 0.0.0.0/0 to 0.0.0.0/0 app Apache comment "audit"'
        )

    def test_build_rule_string_delete_returns_position_only(self):
        rule = FirewallRule(action="allow", protocol="tcp")
        rule.delete = True
        rule.position = 3

        assert rule.build_rule_string() == "rule delete 3"


class TestFirewallRuleValidation:
    def test_invalid_action_raises_value_error(self):
        rule = FirewallRule(action="block", protocol="tcp")

        with pytest.raises(ValueError):
            rule.validate()

    def test_invalid_direction_raises_value_error(self):
        rule = FirewallRule(action="allow", protocol="tcp", direction="sideways")

        with pytest.raises(ValueError):
            rule.validate()

    def test_set_interface_rejects_aliases(self):
        rule = FirewallRule(action="allow", protocol="tcp")

        with pytest.raises(ValueError):
            rule.set_interface("in", "eth0:1")

    def test_validate_rejects_invalid_position(self):
        rule = FirewallRule(action="allow", protocol="tcp")
        rule.position = -2

        with pytest.raises(ValueError):
            rule.validate()


class TestRulesMatch:
    def test_rules_match_returns_zero_for_identical_rules(self):
        rule_a = FirewallRule(action="allow", protocol="tcp", dport=22)
        rule_b = FirewallRule(action="allow", protocol="tcp", dport=22)

        assert rules_match(rule_a, rule_b) == 0

    def test_rules_match_returns_minus_one_for_comment_difference(self):
        rule_a = FirewallRule(action="allow", protocol="tcp", dport=22)
        rule_b = FirewallRule(action="allow", protocol="tcp", dport=22, comment="note")

        assert rules_match(rule_a, rule_b) == -1

    def test_rules_match_returns_one_for_port_difference(self):
        rule_a = FirewallRule(action="allow", protocol="tcp", dport=22)
        rule_b = FirewallRule(action="allow", protocol="tcp", dport=23)

        assert rules_match(rule_a, rule_b) == 1


class TestClientCommands:
    def test_set_default_policy_calls_execute(self, monkeypatch):
        client = UFWClient()
        executed = {}

        def fake_execute(cmd):
            executed["cmd"] = cmd
            return cmd

        monkeypatch.setattr(client, "_execute", fake_execute)
        client.set_default_policy("deny", dry_run=True)
        assert executed["cmd"] == "/usr/sbin/ufw --dry-run default deny incoming"

    def test_set_logging_level(self, monkeypatch):
        client = UFWClient()
        executed = {}
        monkeypatch.setattr(client, "_execute", lambda cmd: executed.setdefault("cmd", cmd))
        client.set_logging_level("high")
        assert executed["cmd"] == "/usr/sbin/ufw logging high"

    def test_enable_adds_force_and_dry_run(self, monkeypatch):
        client = UFWClient()
        executed = {}
        monkeypatch.setattr(client, "_execute", lambda cmd: executed.setdefault("cmd", cmd))
        client.enable(dry_run=True)
        assert executed["cmd"] == "/usr/sbin/ufw --force --dry-run enable"

    def test_disable(self, monkeypatch):
        client = UFWClient()
        executed = {}
        monkeypatch.setattr(client, "_execute", lambda cmd: executed.setdefault("cmd", cmd))
        client.disable()
        assert executed["cmd"] == "/usr/sbin/ufw disable"

    def test_reload(self, monkeypatch):
        client = UFWClient()
        executed = {}
        monkeypatch.setattr(client, "_execute", lambda cmd: executed.setdefault("cmd", cmd))
        client.reload(dry_run=True)
        assert executed["cmd"] == "/usr/sbin/ufw --dry-run reload"

    def test_reset(self, monkeypatch):
        client = UFWClient()
        executed = {}
        monkeypatch.setattr(client, "_execute", lambda cmd: executed.setdefault("cmd", cmd))
        client.reset()
        assert executed["cmd"] == "/usr/sbin/ufw reset"

    def test_status_verbose(self, monkeypatch):
        client = UFWClient()
        executed = {}
        monkeypatch.setattr(client, "_execute", lambda cmd: executed.setdefault("cmd", cmd))
        client.status(verbose=True)
        assert executed["cmd"] == "/usr/sbin/ufw status verbose"

    def test_status_rejects_invalid_combo(self):
        client = UFWClient()
        with pytest.raises(SaltInvocationError):
            client.status(verbose=True, numbered=True)

    def test_update_rule_uses_firewall_rule(self, monkeypatch):
        client = UFWClient()
        rule = FirewallRule(action="allow", protocol="tcp")
        monkeypatch.setattr(
            rule,
            "build_rule_string",
            lambda: "rule allow proto tcp from 0.0.0.0/0 to 0.0.0.0/0",
        )
        executed = {}
        monkeypatch.setattr(client, "_execute", lambda cmd: executed.setdefault("cmd", cmd))
        client.update_rule(rule, dry_run=True)
        assert (
            executed["cmd"]
            == "/usr/sbin/ufw --dry-run rule allow proto tcp from 0.0.0.0/0 to 0.0.0.0/0"
        )


class TestVersionParsing:
    def test_version_with_three_parts(self, monkeypatch):
        client = UFWClient()

        def fake_execute(_):
            return {"stdout": "ufw 0.36.1\n"}

        monkeypatch.setattr(client, "_execute", fake_execute)
        assert client.version() == (0, 36, 1)

    def test_version_unknown(self, monkeypatch):
        client = UFWClient()
        monkeypatch.setattr(client, "_execute", lambda _: {"stdout": ""})
        assert client.version() == "Unknown"

    def test_version_parse_error(self, monkeypatch):
        client = UFWClient()
        monkeypatch.setattr(client, "_execute", lambda _: {"stdout": "bad output\n"})
        with pytest.raises(CommandExecutionError):
            client.version()


def test_get_client_returns_instance():
    assert isinstance(get_client(), UFWClient)
