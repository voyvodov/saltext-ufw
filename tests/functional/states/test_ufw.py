import logging
import random

import pytest

pytestmark = [
    pytest.mark.skip_if_binaries_missing("ufw"),
    pytest.mark.requires_salt_states("ufw"),
]

log = logging.getLogger(__name__)


@pytest.fixture
def ufw_state(states, ufw_client):
    ufw_client.reset()
    yield states.ufw
    ufw_client.cleanup()


@pytest.fixture
def ufw_module(modules):
    return modules.ufw


def _random_port():
    return str(random.randint(20000, 65000))


def _find_forward_rule(rules, **expected):
    for rule in rules:
        if rule.get("direction") != "forward":
            continue
        match = True
        for key, value in expected.items():
            if value is None:
                continue
            if str(rule.get(key)) != str(value):
                match = False
                break
        if match:
            return rule
    return None


def test_enabled_turns_firewall_on(ufw_state):
    ufw_state.disabled(name="ensure-ufw-disabled")
    ret = ufw_state.enabled(name="ensure-ufw-enabled")
    assert ret.result is True
    assert ret.changes == {"old": "inactive", "new": "active"}

    ret = ufw_state.enabled(name="ensure-ufw-enabled-idempotent")
    assert ret.result is True
    assert ret.changes == {}


def test_disabled_turns_firewall_off(ufw_state):
    ufw_state.enabled(name="ensure-ufw-enabled")
    ret = ufw_state.disabled(name="ensure-ufw-disabled")
    assert ret.result is True
    assert ret.changes == {"old": "active", "new": "inactive"}

    ret = ufw_state.disabled(name="ensure-ufw-disabled-idempotent")
    assert ret.result is True
    assert ret.changes == {}


def test_default_policy_updates_direction(ufw_state):
    target = "allow"

    ret = ufw_state.default_policy(
        name="set-incoming-policy",
        policy=target,
        direction="incoming",
    )
    assert ret.result is True
    assert ret.changes["new"]["policy"] == target

    reset = ufw_state.default_policy(
        name="reset-incoming-policy",
        policy="deny",
        direction="incoming",
    )
    assert reset.result is True
    assert reset.changes["new"]["policy"] == "deny"


def test_rule_present_adds_rule_and_is_idempotent(ufw_state):
    port = _random_port()

    ret = ufw_state.rule_present(
        name=f"allow-port-{port}",
        action="allow",
        direction="in",
        dport=port,
        proto="tcp",
    )
    assert ret.result is True
    assert ret.changes

    ret_again = ufw_state.rule_present(
        name=f"allow-port-{port}-is-idempotent",
        action="allow",
        direction="in",
        dport=port,
        proto="tcp",
    )
    assert ret_again.result is True
    assert ret_again.changes == {}


def test_rule_absent_removes_rule(ufw_state):
    port = _random_port()
    ret = ufw_state.rule_present(
        name=f"allow-port-{port}",
        action="allow",
        direction="in",
        dport=port,
        proto="tcp",
    )
    assert ret.result is True
    assert ret.changes

    ret = ufw_state.rule_absent(
        name=f"remove-port-{port}",
        action="allow",
        direction="in",
        dport=port,
        proto="tcp",
    )
    assert ret.result is True
    assert ret.changes

    ret_again = ufw_state.rule_absent(
        name=f"remove-port-{port}",
        action="allow",
        direction="in",
        dport=port,
        proto="tcp",
    )
    assert ret_again.result is True
    assert ret_again.changes == {}


def test_rule_present_requires_port_when_proto_set(ufw_state):
    ret = ufw_state.rule_present(name="bad-rule", proto="tcp")
    assert ret.result is False
    assert "proto" in ret.comment


def test_rule_absent_requires_port_when_proto_set(ufw_state):
    ret = ufw_state.rule_absent(name="bad-rule", proto="tcp")
    assert ret.result is False
    assert "proto" in ret.comment


def test_route_present_adds_route_and_is_idempotent(ufw_state, ufw_module):
    sport = _random_port()
    dport = _random_port()
    src = "10.100.100.1"
    dst = "10.100.200.1"

    ret = ufw_state.route_present(
        name="add-forward-route",
        action="allow",
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto="tcp",
        comment="functional route test",
    )
    assert ret.result is True
    assert ret.changes

    rules = ufw_module.get_rules()
    route = _find_forward_rule(rules, src=src, dst=dst, dport=dport, sport=sport)
    assert route is not None
    assert route["protocol"] == "tcp"
    assert route["action"] == "allow"

    ret_again = ufw_state.route_present(
        name="add-forward-route-idempotent",
        action="allow",
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto="tcp",
        comment="functional route test",
    )
    assert ret_again.result is True
    assert ret_again.changes == {}

    cleanup = ufw_state.route_absent(
        name="cleanup-forward-route",
        action="allow",
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto="tcp",
    )
    assert cleanup.result is True


def test_route_absent_removes_route_and_is_idempotent(ufw_state, ufw_module):
    sport = _random_port()
    dport = _random_port()
    src = "10.200.100.1"
    dst = "10.200.200.1"

    ufw_state.route_present(
        name="ensure-route-exists",
        action="allow",
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto="tcp",
    )

    ret = ufw_state.route_absent(
        name="remove-forward-route",
        action="allow",
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto="tcp",
    )
    assert ret.result is True
    assert ret.changes

    rules = ufw_module.get_rules()
    assert _find_forward_rule(rules, src=src, dst=dst, dport=dport, sport=sport) is None

    ret_again = ufw_state.route_absent(
        name="remove-forward-route-idempotent",
        action="allow",
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto="tcp",
    )
    assert ret_again.result is True
    assert ret_again.changes == {}


def test_route_present_handles_application_profiles(ufw_state, ufw_module):
    src = "172.31.1.10"
    dst = "172.31.1.11"

    ret = ufw_state.route_present(
        name="forward-ssh",
        action="allow",
        src=src,
        dst=dst,
        sport="openssh",
        dport="openssh",
    )
    assert ret.result is True

    rules = ufw_module.get_rules()
    route = _find_forward_rule(rules, src=src, dst=dst)
    assert route is not None
    assert route["sport"] == "22"
    assert route["dport"] == "22"
    assert route["protocol"] == "tcp"

    ufw_state.route_absent(
        name="cleanup-forward-ssh",
        action="allow",
        src=src,
        dst=dst,
        sport="openssh",
        dport="openssh",
    )


def test_route_present_requires_port_when_proto_set(ufw_state):
    ret = ufw_state.route_present(name="bad-route-present", proto="tcp", dport="openssh")
    assert ret.result is False
    assert "proto" in ret.comment


def test_route_absent_requires_port_when_proto_set(ufw_state):
    ret = ufw_state.route_absent(name="bad-route-absent", proto="udp", sport="openssh")
    assert ret.result is False
    assert "proto" in ret.comment
