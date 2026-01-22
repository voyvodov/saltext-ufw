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
def logging():
    return "off"


def status_out(state, default_policy, logging_level):
    ret = f"""Status: {state}
        Logging: {logging_level}
        Default: {default_policy.get("incoming", "deny")} (incoming), {default_policy.get("outgoing", "allow")} (outgoing), {default_policy.get("routed", "deny")} (routed)"""
    return ret


@pytest.fixture
def read_status(state, policy, logging):
    with patch("saltext.ufw.utils.ufw.client.UFWClient.execute", autospec=True) as _data:
        st = status_out(state=state, default_policy=policy, logging_level=logging)
        _data.return_value = st
        yield _data


@pytest.fixture
def execute():
    with patch("saltext.ufw.utils.ufw.client.UFWClient.execute", autospec=True) as _execute:
        yield _execute


@pytest.mark.usefixtures("read_status")
@pytest.mark.parametrize(
    "state, policy, logging",
    [
        (
            "active",
            {"incoming": "deny", "outgoing": "allow", "routed": "deny"},
            "off",
        ),
        (
            "inactive",
            {"incoming": "allow", "outgoing": "deny", "routed": "allow"},
            "low",
        ),
        (
            "active",
            {"incoming": "deny", "outgoing": "deny", "routed": "deny"},
            "full",
        ),
    ],
)
def test_status(state, policy, logging):
    ret = ufw.status()
    assert ret["status"] == state
    assert ret["default_policy"] == policy
    assert ret["logging"] == logging


def test_enable(execute):
    ufw.enable()
    cmd = execute.call_args[0][1]
    assert cmd == "enable"


def test_disable(execute):
    ufw.disable()
    cmd = execute.call_args[0][1]
    assert cmd == "disable"


def test_reload(execute):
    ufw.reload()
    cmd = execute.call_args[0][1]
    assert cmd == "reload"


@pytest.mark.usefixtures("read_status")
@pytest.mark.parametrize(
    "logging",
    [
        ("off"),
        ("low"),
        ("medium"),
        ("high"),
        ("full"),
    ],
)
def test_logging_level(logging):
    ufw.logging_level(logging)
    status = ufw.status()

    assert status.get("logging") == logging


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


def test_add_rule_app_with_ip(execute):
    ufw.add_rule(action="allow", direction="in", app="Apache", dst="192.168.1.1")
    cmd = execute.call_args[0][1]
    app = execute.call_args[1]["app"]
    dst = execute.call_args[1]["dst"]
    assert cmd == "rule"
    assert app == "Apache"
    assert dst == "192.168.1.1"


def test_add_rule_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="invalid_action", direction="in", dport="8080", proto="tcp")


def test_add_rule_missing_port():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="in", proto="tcp")


def test_add_rule_invalid_direction():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="invalid_direction", dport="8080", proto="tcp")


def test_add_rule_app_with_no_ip():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="in", app="Apache")


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


def test_remove_rule_app_with_ip(execute):
    ufw.remove_rule(action="allow", direction="in", app="Apache", dst="192.168.1.1")
    cmd = execute.call_args[0][1]
    app = execute.call_args[1]["app"]
    dst = execute.call_args[1]["dst"]
    method = execute.call_args[1].get("method")
    assert cmd == "rule"
    assert method == "delete"
    assert app == "Apache"
    assert dst == "192.168.1.1"


def test_remove_rule_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="invalid_action", direction="in", dport="8080", proto="tcp")


def test_remove_rule_missing_port():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="allow", direction="in", proto="tcp")


def test_remove_rule_invalid_direction():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="allow", direction="invalid_direction", dport="8080", proto="tcp")


def test_remove_rule_app_with_no_ip():
    with pytest.raises(SaltInvocationError):
        ufw.remove_rule(action="allow", direction="in", app="Apache")
