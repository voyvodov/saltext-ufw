from unittest.mock import patch

import pytest
from salt.exceptions import SaltInvocationError

from saltext.ufw.modules import ufw


@pytest.fixture
def configure_loader_modules():
    return {
        ufw: {
            "__grains__": {"id": "test-minion"},
        }
    }


@pytest.fixture
def data():
    return ""


@pytest.fixture
def state():
    return "active"


@pytest.fixture
def policy():
    return {"incoming": "deny", "outgoing": "allow", "routed": "deny"}


@pytest.fixture
def log_level():
    return "off"


def status_out(state, default_policy, log_level):
    ret = f"""Status: {state}
        Logging: {log_level}
        Default: {default_policy.get("incoming", "deny")} (incoming), {default_policy.get("outgoing", "allow")} (outgoing), {default_policy.get("routed", "deny")} (routed)"""
    return ret


@pytest.fixture
def read_status(state, policy, log_level):
    with patch("saltext.ufw.utils.ufw.client.UFWClient.execute", autospec=True) as _data:
        st = status_out(state=state, default_policy=policy, log_level=log_level)
        _data.return_value = st
        yield _data


@pytest.fixture
def execute():
    with patch("saltext.ufw.utils.ufw.client.UFWClient.execute", autospec=True) as _execute:
        yield _execute


def test_reload(execute):
    ufw.reload()
    cmd = execute.call_args[0][1]
    assert cmd == "reload"


@pytest.mark.usefixtures("read_status")
@pytest.mark.parametrize(
    "log_level",
    [
        ("off"),
        ("low"),
        ("medium"),
        ("high"),
        ("full"),
    ],
)
def test_logging_level(log_level):
    ufw.logging_level(log_level)
    status = ufw.status()

    assert status.get("logging") == log_level


def test_logging_level_invalid():
    with pytest.raises(SaltInvocationError):
        ufw.logging_level("invalid_level")


@pytest.mark.usefixtures("read_status")
@pytest.mark.parametrize(
    "policy",
    [
        ({"incoming": "deny", "outgoing": "allow", "routed": "deny"}),
        ({"incoming": "deny", "outgoing": "deny", "routed": "reject"}),
        ({"incoming": "allow", "outgoing": "reject", "routed": "deny"}),
        ({"incoming": "reject", "outgoing": "allow", "routed": "allow"}),
        ({"incoming": "reject", "outgoing": "deny", "routed": "allow"}),
    ],
)
def test_default_policy(policy):
    ufw.default_policy("incoming", policy["incoming"])
    ufw.default_policy("outgoing", policy["outgoing"])
    ufw.default_policy("routed", policy["routed"])
    status = ufw.status()
    assert status.get("default_policy") == policy


def test_default_policy_invalid_direction():
    with pytest.raises(SaltInvocationError):
        ufw.default_policy("invalid_direction", "allow")


def test_default_policy_invalid_policy():
    with pytest.raises(SaltInvocationError):
        ufw.default_policy("incoming", "invalid_policy")


def test_reset(execute):
    ufw.reset()
    cmd = execute.call_args[0][1]
    assert cmd == "reset"


def test_add_rule_allow_in_to_port(execute):
    ufw.add_rule(action="allow", direction="in", dport="8080", proto="tcp")
    cmd = execute.call_args[0][1]
    direction = execute.call_args[1]["direction"]
    port = execute.call_args[1]["dport"]
    proto = execute.call_args[1]["proto"]
    assert direction == "in"
    assert cmd == "rule"
    assert port == "8080"
    assert proto == "tcp"


def test_add_rule_deny_out_from_port(execute):
    ufw.add_rule(action="deny", direction="out", sport="9090", proto="udp")
    cmd = execute.call_args[0][1]
    direction = execute.call_args[1]["direction"]
    port = execute.call_args[1]["sport"]
    proto = execute.call_args[1]["proto"]
    assert direction == "out"
    assert cmd == "rule"
    assert port == "9090"
    assert proto == "udp"


def test_add_rule_port_range_with_proto(execute):
    ufw.add_rule(action="allow", direction="in", dport="1000:1010", proto="tcp")
    kwargs = execute.call_args[1]
    assert kwargs["dport"] == "1000:1010"
    assert kwargs["proto"] == "tcp"


def test_add_rule_application_name(execute):
    ufw.add_rule(action="allow", direction="in", dport="Apache", dst="192.168.1.1")
    cmd = execute.call_args[0][1]
    kwargs = execute.call_args[1]
    assert cmd == "rule"
    assert kwargs["dport"] == "Apache"
    assert kwargs["dst"] == "192.168.1.1"
    assert kwargs["proto"] == "any"


def test_add_rule_application_name_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="in", dport="Apache", proto="tcp")


def test_add_rule_sport_application_name_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="out", sport="MyApp", proto="udp")


def test_add_rule_sport_application_name_allowed_with_any_proto(execute):
    ufw.add_rule(action="deny", direction="out", sport="MyApp")
    kwargs = execute.call_args[1]
    assert kwargs["sport"] == "MyApp"
    assert kwargs["proto"] == "any"


def test_add_rule_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="invalid_action", direction="in", dport="8080", proto="tcp")


def test_add_rule_missing_port():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="in", proto="tcp")


def test_add_rule_invalid_direction():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="invalid_direction", dport="8080", proto="tcp")


def test_add_rule_to_port_no_ip(execute):
    ufw.add_rule(action="allow", direction="in", dport="8080", proto="tcp")
    cmd = execute.call_args[0][1]
    src = execute.call_args[1].get("src")
    dst = execute.call_args[1].get("dst")
    assert cmd == "rule"
    assert src == "0.0.0.0/0"
    assert dst == "0.0.0.0/0"


def test_add_rule_from_port_no_ip(execute):
    ufw.add_rule(action="allow", direction="in", sport="8080", proto="tcp")
    cmd = execute.call_args[0][1]
    src = execute.call_args[1].get("src")
    dst = execute.call_args[1].get("dst")
    assert cmd == "rule"
    assert src == "0.0.0.0/0"
    assert dst == "0.0.0.0/0"


def test_remove_rule_allow_in_to_port(execute):
    ufw.remove_rule(action="allow", direction="in", dport="8080", proto="tcp")
    cmd = execute.call_args[0][1]
    direction = execute.call_args[1]["direction"]
    port = execute.call_args[1]["dport"]
    proto = execute.call_args[1]["proto"]
    method = execute.call_args[1].get("method")
    assert direction == "in"
    assert method == "delete"
    assert cmd == "rule"
    assert port == "8080"
    assert proto == "tcp"


def test_remove_rule_deny_out_from_port(execute):
    ufw.remove_rule(action="deny", direction="out", sport="9090", proto="udp")
    cmd = execute.call_args[0][1]
    direction = execute.call_args[1]["direction"]
    port = execute.call_args[1]["sport"]
    proto = execute.call_args[1]["proto"]
    method = execute.call_args[1].get("method")
    assert direction == "out"
    assert method == "delete"
    assert cmd == "rule"
    assert port == "9090"
    assert proto == "udp"


def test_remove_rule_application_name(execute):
    ufw.remove_rule(action="allow", direction="in", dport="Apache")
    kwargs = execute.call_args[1]
    assert kwargs["method"] == "delete"
    assert kwargs["dport"] == "Apache"
    assert kwargs["proto"] == "any"


def test_remove_rule_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="invalid_action", direction="in", dport="8080", proto="tcp")


def test_remove_rule_missing_port():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="allow", direction="in", proto="tcp")


def test_remove_rule_application_name_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="allow", direction="in", dport="Apache", proto="tcp")


def test_remove_rule_sport_application_name_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="allow", direction="in", sport="Daemon", proto="udp")


def test_remove_rule_invalid_direction():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="allow", direction="invalid_direction", dport="8080", proto="tcp")


def test_add_route_basic(execute):
    ufw.add_route(
        action="allow",
        interface_in="eth0",
        interface_out="eth1",
        dport="8443",
        proto="tcp",
        comment="text",
    )
    cmd = execute.call_args[0][1]
    kwargs = execute.call_args[1]
    assert cmd == "route"
    assert kwargs["interface_in"] == "eth0"
    assert kwargs["interface_out"] == "eth1"
    assert kwargs["dport"] == "8443"
    assert kwargs["proto"] == "tcp"
    assert kwargs["comment"] == "text"
    assert kwargs["src"] == "0.0.0.0/0"
    assert kwargs["dst"] == "0.0.0.0/0"


def test_add_route_with_numeric_sport_and_dport(execute):
    ufw.add_route(
        action="allow",
        src="10.0.0.1",
        dst="10.0.0.2",
        sport="55000",
        dport="56000",
        proto="udp",
    )
    kwargs = execute.call_args[1]
    assert kwargs["sport"] == "55000"
    assert kwargs["dport"] == "56000"
    assert kwargs["proto"] == "udp"


@pytest.mark.parametrize("rule_log,expected", [(True, "log"), ("all", "log-all"), (False, None)])
def test_add_route_logging_modes(execute, rule_log, expected):
    ufw.add_route(action="allow", src="1.2.3.4", dst="5.6.7.8", rule_log=rule_log)
    logging_value = execute.call_args[1]["rule_log"]
    assert logging_value == expected


def test_add_route_application_name(execute):
    ufw.add_route(action="allow", interface_in="eth0", interface_out="eth1", dport="Storage")
    kwargs = execute.call_args[1]
    assert kwargs["dport"] == "Storage"
    assert kwargs["proto"] == "any"


def test_add_route_sport_application_name_allowed_with_any_proto(execute):
    ufw.add_route(action="allow", sport="StorageApp")
    kwargs = execute.call_args[1]
    assert kwargs["sport"] == "StorageApp"
    assert kwargs["proto"] == "any"


def test_add_route_application_name_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="allow", dport="Storage", proto="udp")


def test_add_route_sport_application_name_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="allow", sport="StorageApp", proto="tcp")


def test_add_route_invalid_insert():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(insert=-1, action="allow", dport="8080", proto="tcp")


def test_add_route_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="invalid", dport="80", proto="tcp")


def test_add_route_missing_port_with_proto():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="allow", proto="tcp")


def test_remove_route_basic(execute):
    ufw.remove_route(
        action="deny",
        interface_in="eth0",
        interface_out="eth1",
        sport="5353",
        proto="udp",
    )
    cmd = execute.call_args[0][1]
    kwargs = execute.call_args[1]
    assert cmd == "route"
    assert kwargs["method"] == "delete"
    assert kwargs["interface_in"] == "eth0"
    assert kwargs["interface_out"] == "eth1"
    assert kwargs["sport"] == "5353"
    assert kwargs["proto"] == "udp"
    assert kwargs["src"] == "0.0.0.0/0"
    assert kwargs["dst"] == "0.0.0.0/0"


def test_remove_route_sport_application_name_allowed_with_any_proto(execute):
    ufw.remove_route(action="deny", sport="CustomApp")
    kwargs = execute.call_args[1]
    assert kwargs["sport"] == "CustomApp"
    assert kwargs["proto"] == "any"


def test_remove_route_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="invalid", dport="80", proto="tcp")


def test_remove_route_missing_port_with_proto():
    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="allow", proto="udp")


def test_remove_route_application_name(execute):
    ufw.remove_route(action="allow", dport="CustomService")
    kwargs = execute.call_args[1]
    assert kwargs["dport"] == "CustomService"
    assert kwargs["proto"] == "any"


def test_remove_route_application_name_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="allow", dport="CustomService", proto="tcp")


def test_remove_route_sport_application_name_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="allow", sport="CustomApp", proto="udp")
