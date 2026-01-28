from types import MethodType
from unittest.mock import MagicMock

import pytest
from salt.exceptions import SaltInvocationError

from saltext.ufw.modules import ufw
from saltext.ufw.utils.ufw import UFWClient


@pytest.fixture
def configure_loader_modules():
    return {ufw: {"__grains__": {"id": "test-minion"}}}


def status_out(state, default_policy, log_level):
    return (
        f"Status: {state}\n"
        f"Logging: {log_level}\n"
        f"Default: {default_policy.get('incoming', 'deny')} (incoming), "
        f"{default_policy.get('outgoing', 'allow')} (outgoing), "
        f"{default_policy.get('routed', 'deny')} (routed)"
    )


def _last_command(execute):
    args, _ = execute.call_args
    return args[0]


def _captured_rule(client):
    assert client._captured_rule is not None
    return client._captured_rule


@pytest.fixture
def state():
    return "active"


@pytest.fixture
def policy():
    return {"incoming": "deny", "outgoing": "allow", "routed": "deny"}


@pytest.fixture
def log_level():
    return "low"


@pytest.fixture
def client(monkeypatch):
    c = UFWClient()
    execute_fn = MagicMock(return_value={"stdout": ""})
    c._execute = execute_fn
    c._captured_rule = None

    def _update_rule(self, fwrule, dry_run=False):
        self._captured_rule = fwrule
        cmd = [self.ufw_path]
        if dry_run:
            cmd.append("--dry-run")
        rule_def = fwrule.build_rule_string()

        cmd.append(rule_def)
        c._execute(" ".join(cmd))

    c.update_rule = MethodType(_update_rule, c)

    monkeypatch.setattr(ufw, "get_client", lambda: c)
    return c


@pytest.fixture
def execute(client):
    return client._execute


@pytest.fixture
def read_status(client, state, policy, log_level):
    mocked = MagicMock(return_value=status_out(state, policy, log_level))
    client.status = mocked
    yield mocked


def test_reload_returns_stdout(execute):
    execute.return_value = {"stdout": "reloaded\n"}
    assert ufw.reload() == "reloaded"
    assert _last_command(execute) == "/usr/sbin/ufw reload"


@pytest.mark.parametrize("level", ["off", "low", "medium", "high", "full"])
def test_logging_level_sets_status(read_status, state, policy, level):
    read_status.return_value = status_out(state, policy, level)
    ufw.logging_level(level)
    status = ufw.status()
    assert status["logging"] == level


def test_logging_level_invalid():
    with pytest.raises(SaltInvocationError):
        ufw.logging_level("invalid")


@pytest.mark.parametrize(
    "target_policy",
    [
        {"incoming": "deny", "outgoing": "allow", "routed": "deny"},
        {"incoming": "allow", "outgoing": "reject", "routed": "deny"},
        {"incoming": "reject", "outgoing": "deny", "routed": "allow"},
    ],
)
def test_default_policy_is_reflected(read_status, state, log_level, target_policy):
    read_status.return_value = status_out(state, target_policy, log_level)
    ufw.default_policy("incoming", target_policy["incoming"])
    ufw.default_policy("outgoing", target_policy["outgoing"])
    ufw.default_policy("routed", target_policy["routed"])
    status = ufw.status()
    assert status["default_policy"] == target_policy


def test_default_policy_invalid_direction():
    with pytest.raises(SaltInvocationError):
        ufw.default_policy("sideways", "allow")


def test_default_policy_invalid_policy():
    with pytest.raises(SaltInvocationError):
        ufw.default_policy("incoming", "invalid")


def test_reset(execute):
    execute.return_value = {"stdout": "reset\n"}
    assert ufw.reset() == "reset"
    assert _last_command(execute) == "/usr/sbin/ufw reset"


def test_add_rule_allow_in_to_port(client, execute):
    ufw.add_rule(action="allow", direction="in", dport="8080", proto="tcp")
    rule = _captured_rule(client)
    assert rule.direction == "in"
    assert rule.dport == "8080"
    assert rule.protocol == "tcp"
    assert (
        _last_command(execute)
        == "/usr/sbin/ufw rule allow proto tcp from 0.0.0.0/0 to 0.0.0.0/0 port 8080"
    )


def test_add_rule_deny_out_from_port(client, execute):
    ufw.add_rule(action="deny", direction="out", sport="9090", proto="udp")
    rule = _captured_rule(client)
    assert rule.direction == "out"
    assert rule.sport == "9090"
    assert rule.protocol == "udp"
    assert "rule deny" in _last_command(execute)


def test_add_rule_port_range_with_proto(client):
    ufw.add_rule(action="allow", direction="in", dport="1000:1010", proto="tcp")
    rule = _captured_rule(client)
    assert rule.dport == "1000:1010"
    assert rule.protocol == "tcp"


def test_add_rule_application_name_sets_dapp(client):
    ufw.add_rule(action="allow", direction="in", dport="Apache", dst="192.168.1.1")
    rule = _captured_rule(client)
    assert rule.dapp == "Apache"
    assert rule.dst == "192.168.1.1"
    assert rule.protocol == "any"


def test_add_rule_application_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="in", dport="Apache", proto="tcp")


def test_add_rule_sport_application_requires_numeric_port_when_proto_set():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="out", sport="MyApp", proto="udp")


def test_add_rule_sport_application_name_allowed_with_any_proto(client):
    ufw.add_rule(action="deny", direction="out", sport="MyApp")
    rule = _captured_rule(client)
    assert rule.sapp == "MyApp"
    assert rule.protocol == "any"


def test_add_rule_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="invalid_action", direction="in", dport="8080", proto="tcp")


def test_add_rule_missing_port():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="in", proto="tcp")


def test_add_rule_invalid_direction():
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(action="allow", direction="invalid_direction", dport="8080", proto="tcp")


def test_add_rule_default_addresses(client):
    ufw.add_rule(action="allow", direction="in", dport="8080", proto="tcp")
    rule = _captured_rule(client)
    assert rule.src == "0.0.0.0/0"
    assert rule.dst == "0.0.0.0/0"


def test_remove_rule_allow_in_to_port(client):
    ufw.remove_rule(action="allow", direction="in", dport="8080", proto="tcp")
    rule = _captured_rule(client)
    assert rule.delete is True
    assert rule.direction == "in"
    assert rule.dport == "8080"


def test_remove_rule_deny_out_from_port(client):
    ufw.remove_rule(action="deny", direction="out", sport="9090", proto="udp")
    rule = _captured_rule(client)
    assert rule.delete is True
    assert rule.direction == "out"
    assert rule.sport == "9090"


def test_remove_rule_application_name(client):
    ufw.remove_rule(action="allow", direction="in", dport="Apache")
    rule = _captured_rule(client)
    assert rule.delete is True
    assert rule.dapp == "Apache"
    assert rule.protocol == "any"


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
        action="allow",
        src="10.0.0.1",
        dst="10.0.0.2",
        sport="55000",
        dport="56000",
        proto="udp",
    )
    rule = _captured_rule(client)
    assert rule.sport == "55000"
    assert rule.dport == "56000"
    assert rule.protocol == "udp"


@pytest.mark.parametrize("logtype,expected", [("log", "log"), ("log-all", "log-all"), (None, "")])
def test_add_route_logging_modes(client, logtype, expected):
    ufw.add_route(action="allow", src="1.2.3.4", dst="5.6.7.8", logtype=logtype)
    rule = _captured_rule(client)
    assert rule.logtype == expected


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
        ufw.add_route(position=-5, action="allow", dport="8080", proto="tcp")


def test_add_route_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="invalid", dport="80", proto="tcp")


def test_add_route_missing_port_with_proto():
    with pytest.raises(SaltInvocationError):
        ufw.add_route(action="allow", proto="tcp")


def test_remove_route_basic(client):
    ufw.remove_route(
        action="deny",
        interface_in="eth0",
        interface_out="eth1",
        sport="5353",
        proto="udp",
    )
    rule = _captured_rule(client)
    assert rule.delete is True
    assert rule.forward is True
    assert rule.interface_in == "eth0"
    assert rule.interface_out == "eth1"
    assert rule.sport == "5353"
    assert rule.protocol == "udp"


def test_remove_route_sport_application_name_sets_sapp(client):
    ufw.remove_route(action="deny", sport="CustomApp")
    rule = _captured_rule(client)
    assert rule.sapp == "CustomApp"
    assert rule.protocol == "any"


def test_remove_route_invalid_action():
    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="invalid", dport="80", proto="tcp")


def test_remove_route_missing_port_with_proto():
    with pytest.raises(SaltInvocationError):
        ufw.remove_route(action="allow", proto="udp")


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
