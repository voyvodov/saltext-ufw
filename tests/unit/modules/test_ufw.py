from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.ufw.modules import ufw
from saltext.ufw.utils.ufw import FirewallRule


@pytest.fixture
def configure_loader_modules():
    return {
        ufw: {
            "__grains__": {"id": "test-minion"},
        }
    }


@pytest.fixture
def state():
    return "active"


@pytest.fixture
def policy():
    return {"incoming": "deny", "outgoing": "allow", "routed": "deny"}


@pytest.fixture
def log_level():
    return "low"


@pytest.fixture(autouse=True)
def client():
    with patch("saltext.ufw.modules.ufw.get_client") as get_client:
        client = MagicMock()
        get_client.return_value = client
        yield client


def status_out(state, default_policy, log_level):
    return (
        f"Status: {state}\n"
        f"Logging: {log_level}\n"
        f"Default: {default_policy.get('incoming', 'deny')} (incoming), "
        f"{default_policy.get('outgoing', 'allow')} (outgoing), "
        f"{default_policy.get('routed', 'deny')} (routed)"
    )


def _captured_rule(client):
    client.update_rule.assert_called()
    (rule,), _ = client.update_rule.call_args
    assert isinstance(rule, FirewallRule)
    return rule


def test_reload_returns_stdout(client):
    client.reload.return_value = {"stdout": "reloaded\n"}
    assert ufw.reload() == "reloaded"
    client.reload.assert_called_once_with()


def test_reload_failure_returns_false(client):
    client.reload.side_effect = CommandExecutionError("cmd", {})
    assert ufw.reload() is False


def test_reset(client):
    client.reset.return_value = {"stdout": "reset\n"}
    assert ufw.reset() == "reset"
    client.reset.assert_called_once_with()


def test_enable_disable(client):
    client.enable.return_value = {"stdout": "enabled\n"}
    client.disable.return_value = {"stdout": "disabled\n"}
    assert ufw.enable() == "enabled"
    assert ufw.disable() == "disabled"
    client.enable.assert_called_once_with()
    client.disable.assert_called_once_with()


def test_status_parses_fields(client, state, policy, log_level):
    client.status.return_value = status_out(state, policy, log_level)
    result = ufw.status()
    client.status.assert_called_once_with(verbose=True, numbered=False)
    assert result["status"] == state
    assert result["logging"] == log_level
    assert result["default_policy"] == policy


def test_status_raw_output(client):
    client.status.return_value = "raw"
    assert ufw.status(raw=True) == "raw"
    client.status.assert_called_once_with(verbose=True, numbered=False)


def test_status_numbered_forces_raw(client):
    client.status.return_value = "numbered"
    assert ufw.status(numbered=True) == "numbered"
    client.status.assert_called_once_with(verbose=False, numbered=True)


@pytest.mark.parametrize("level", ["off", "low", "medium", "high", "full"])
def test_logging_level_calls_client(client, level):
    client.set_logging_level.return_value = {"stdout": f"set {level}\n"}
    assert ufw.logging_level(level) == f"set {level}"
    client.set_logging_level.assert_called_once_with(level=level)


def test_logging_level_false_becomes_off(client):
    ufw.logging_level(False)
    client.set_logging_level.assert_called_once_with(level="off")


def test_logging_level_invalid():
    with pytest.raises(SaltInvocationError):
        ufw.logging_level("invalid_level")


def test_default_policy_calls_client(client):
    client.set_default_policy.return_value = {"stdout": "ok\n"}
    assert ufw.default_policy("incoming", "deny") == "ok"
    client.set_default_policy.assert_called_once_with(policy="deny", direction="incoming")


def test_default_policy_invalid_direction():
    with pytest.raises(SaltInvocationError):
        ufw.default_policy("invalid", "allow")


def test_default_policy_invalid_policy():
    with pytest.raises(SaltInvocationError):
        ufw.default_policy("incoming", "invalid")


def test_version_returns_string(client):
    client.version.return_value = (0, 36, 1)
    assert ufw.version() == "0.36.1"
    client.version.assert_called_once_with()


def test_version_failure_returns_false(client):
    client.version.side_effect = CommandExecutionError("cmd", {})
    assert ufw.version() is False


def test_list_rules():
    with patch("saltext.ufw.modules.ufw.list_current_rules", return_value=["rule 1"]) as mock_list:
        assert ufw.list_rules() == ["rule 1"]
        mock_list.assert_called_once_with()


def test_get_rules_filters_by_index():
    rules = [{"index": 1, "rule": "first"}, {"index": 2, "rule": "second"}]
    with patch("saltext.ufw.modules.ufw.get_firewall_rules", return_value=rules):
        assert ufw.get_rules(index=2) == [{"index": 2, "rule": "second"}]


def test_get_rules_invalid_index_type():
    with pytest.raises(SaltInvocationError):
        ufw.get_rules(index="one")


def test_get_rules_index_out_of_range():
    with patch("saltext.ufw.modules.ufw.get_firewall_rules", return_value=[{"index": 1}]):
        with pytest.raises(SaltInvocationError):
            ufw.get_rules(index=5)


def test_add_rule_with_numeric_ports(client):
    ufw.add_rule(action="allow", direction="in", dport="8080", proto="tcp")
    rule = _captured_rule(client)
    assert rule.direction == "in"
    assert rule.dport == "8080"
    assert rule.protocol == "tcp"
    assert rule.src == "0.0.0.0/0"
    assert rule.dst == "0.0.0.0/0"


def test_add_rule_application_name_sets_dapp(client):
    ufw.add_rule(action="allow", direction="in", dport="Apache", dst="192.168.1.1")
    rule = _captured_rule(client)
    assert rule.dapp == "Apache"
    assert rule.dport == ""
    assert rule.protocol == "any"
    assert rule.dst == "192.168.1.1"


def test_add_rule_sport_application_name_sets_sapp(client):
    ufw.add_rule(action="deny", direction="out", sport="MyApp")
    rule = _captured_rule(client)
    assert rule.sapp == "MyApp"
    assert rule.sport == ""
    assert rule.protocol == "any"


def test_add_rule_sets_comment_and_position(client):
    ufw.add_rule(action="allow", direction="in", dport=22, position=2, comment="audit")
    rule = _captured_rule(client)
    assert rule.comment == "audit"
    assert rule.position == 2


def test_add_rule_interface_validation_error():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="in", dport=22, interface="eth0:1")


def test_add_rule_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="invalid", direction="in", dport=22)


def test_add_rule_missing_port():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="in", proto="tcp")


def test_add_rule_invalid_direction():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="invalid", dport=22)


def test_add_rule_application_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="in", dport="Apache", proto="tcp")


def test_add_rule_sport_application_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="out", sport="MyApp", proto="udp")


def test_remove_rule_marks_delete(client):
    ufw.remove_rule(action="allow", direction="in", dport=22, proto="tcp")
    rule = _captured_rule(client)
    assert rule.delete is True
    assert rule.direction == "in"
    assert rule.dport == "22"


def test_remove_rule_application_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="allow", direction="in", dport="Apache", proto="tcp")


def test_remove_rule_invalid_direction():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="allow", direction="invalid", dport=22)


def test_add_route_basic(client):
    ufw.add_route(
        action="allow",
        interface_in="eth0",
        interface_out="eth1",
        dport="8443",
        proto="tcp",
        comment="text",
    )
    rule = _captured_rule(client)
    assert rule.forward is True
    assert rule.interface_in == "eth0"
    assert rule.interface_out == "eth1"
    assert rule.dport == "8443"
    assert rule.comment == "text"


def test_add_route_with_numeric_ports(client):
    ufw.add_route(
        action="allow", src="10.0.0.1", dst="10.0.0.2", sport="55000", dport="56000", proto="udp"
    )
    rule = _captured_rule(client)
    assert rule.sport == "55000"
    assert rule.dport == "56000"
    assert rule.protocol == "udp"


@pytest.mark.parametrize("logtype,expected", [("log", "log"), ("log-all", "log-all"), (None, "")])
def test_add_route_logging_modes(client, logtype, expected):
    ufw.add_route(action="allow", src="1.2.3.4", dst="5.6.7.8", logtype=logtype)
    rule = _captured_rule(client)
    if expected:
        assert rule.logtype == expected
    else:
        assert rule.logtype == ""


def test_add_route_invalid_logtype():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="allow", src="1.2.3.4", dst="5.6.7.8", logtype="invalid")


def test_add_route_application_name_sets_dapp(client):
    ufw.add_route(action="allow", dport="Storage")
    rule = _captured_rule(client)
    assert rule.dapp == "Storage"
    assert rule.protocol == "any"


def test_add_route_sport_application_name_sets_sapp(client):
    ufw.add_route(action="allow", sport="StorageApp")
    rule = _captured_rule(client)
    assert rule.sapp == "StorageApp"
    assert rule.protocol == "any"


def test_add_route_application_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="allow", dport="Storage", proto="udp")


def test_add_route_sport_application_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="allow", sport="StorageApp", proto="tcp")


def test_add_route_invalid_position():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="allow", dport=80, proto="tcp", position=-2)


def test_add_route_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="invalid", dport=80, proto="tcp")


def test_add_route_missing_port_with_proto():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="allow", proto="tcp")


def test_remove_route_marks_delete(client):
    ufw.remove_route(action="deny", sport="5353", proto="udp")
    rule = _captured_rule(client)
    assert rule.delete is True
    assert rule.forward is True
    assert rule.sport == "5353"
    assert rule.protocol == "udp"


def test_remove_route_sport_application_name_sets_sapp(client):
    ufw.remove_route(action="deny", sport="CustomApp")
    rule = _captured_rule(client)
    assert rule.sapp == "CustomApp"
    assert rule.protocol == "any"


def test_remove_route_application_name_sets_dapp(client):
    ufw.remove_route(action="allow", dport="CustomService")
    rule = _captured_rule(client)
    assert rule.dapp == "CustomService"
    assert rule.protocol == "any"


def test_remove_route_application_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="allow", dport="CustomService", proto="tcp")


def test_remove_route_sport_application_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="allow", sport="CustomApp", proto="udp")


def test_remove_route_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="invalid", dport=80, proto="tcp")


def test_remove_route_missing_port_with_proto():
    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="allow", proto="udp")


def test_add_rule_mixed_network():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="in", dport=22, src="127.0.0.1/32", dst="::1/128")

    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="in", dport=22, src="::1/128", dst="127.0.0.1/32")


def test_remove_rule_mixed_network():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="allow", direction="in", dport=22, src="127.0.0.1/32", dst="::1/128")

    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="allow", direction="in", dport=22, src="::1/128", dst="127.0.0.1/32")


def test_add_route_mixed_network():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="allow", dport=22, src="127.0.0.1/32", dst="::1/128")

    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="allow", dport=22, src="::1/128", dst="127.0.0.1/32")


def test_remove_route_mixed_network():
    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="allow", dport=22, src="127.0.0.1/32", dst="::1/128")

    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="allow", dport=22, src="::1/128", dst="127.0.0.1/32")


def test_rule_default_network_is_replaced_for_ipv6(client):
    ipv6_network = "fd3b:91a3:a9b4:709e::/64"

    ufw.add_rule(action="allow", direction="in", dport=22, src=ipv6_network)
    rule = _captured_rule(client)
    assert rule.src == ipv6_network
    assert rule.dst == "::/0"

    ufw.remove_rule(action="allow", direction="in", dport=22, src=ipv6_network)
    rule = _captured_rule(client)
    assert rule.src == ipv6_network
    assert rule.dst == "::/0"

    ufw.add_rule(action="allow", direction="in", dport=22, dst=ipv6_network)
    rule = _captured_rule(client)
    assert rule.src == "::/0"
    assert rule.dst == ipv6_network

    ufw.remove_rule(action="allow", direction="in", dport=22, dst=ipv6_network)
    rule = _captured_rule(client)
    assert rule.src == "::/0"
    assert rule.dst == ipv6_network


def test_route_default_network_is_replaced_for_ipv6(client):
    ipv6_network = "fd3b:91a3:a9b4:709e::/64"

    ufw.add_route(action="allow", sport=22, src=ipv6_network)
    rule = _captured_rule(client)
    assert rule.src == ipv6_network
    assert rule.dst == "::/0"

    ufw.remove_route(action="allow", sport=22, src=ipv6_network)
    rule = _captured_rule(client)
    assert rule.src == ipv6_network
    assert rule.dst == "::/0"

    ufw.add_route(action="allow", dport=22, dst=ipv6_network)
    rule = _captured_rule(client)
    assert rule.src == "::/0"
    assert rule.dst == ipv6_network

    ufw.remove_route(action="allow", dport=22, dst=ipv6_network)
    rule = _captured_rule(client)
    assert rule.src == "::/0"
    assert rule.dst == ipv6_network
