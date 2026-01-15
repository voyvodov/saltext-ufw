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
        to_port=port,
        proto="tcp",
    )
    assert ret.result is True
    assert ret.changes

    ret_again = ufw_state.rule_present(
        name=f"allow-port-{port}-is-idempotent",
        action="allow",
        direction="in",
        to_port=port,
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
        to_port=port,
        proto="tcp",
    )
    assert ret.result is True
    assert ret.changes

    ret = ufw_state.rule_absent(
        name=f"remove-port-{port}",
        action="allow",
        direction="in",
        to_port=port,
        proto="tcp",
    )
    assert ret.result is True
    assert ret.changes

    ret_again = ufw_state.rule_absent(
        name=f"remove-port-{port}",
        action="allow",
        direction="in",
        to_port=port,
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
