import logging

import pytest
from salt.exceptions import SaltInvocationError

pytestmark = [
    pytest.mark.skip_if_binaries_missing("ufw"),
]


log = logging.getLogger(__name__)


@pytest.fixture
def ufw(modules, ufw_client):
    ufw_client.reset()
    yield modules.ufw
    ufw_client.cleanup()


def test_status(ufw):
    status = ufw.status()
    assert "status" in status
    assert status["status"] in ["active", "inactive"]
    assert "default_policy" in status
    assert "incoming" in status["default_policy"]
    assert "outgoing" in status["default_policy"]
    assert "routed" in status["default_policy"]


def test_status_raw(ufw):
    status = ufw.status(raw=True)
    assert isinstance(status, str)
    assert "Status:" in status
    assert "Default:" in status


def test_reload(ufw):
    # This test assumes UFW is already enabled
    ufw.reload()
    assert True  # If no exception is raised, the test passes
    status = ufw.status()
    assert status["status"] == "active"


def test_logging_level(ufw):
    # Set logging level to 'low'
    ufw.logging_level("low")
    status = ufw.status()
    assert status.get("logging") == "low"

    # Set logging level to 'full'
    ufw.logging_level("full")
    status = ufw.status()
    assert status.get("logging") == "full"

    # Set logging level to 'off'
    ufw.logging_level("off")
    status = ufw.status()
    assert status.get("logging") == "off"


def test_reset(ufw):
    ufw.add_rule(
        action="allow",
        direction="in",
        dport="25000",
        proto="tcp",
    )
    rules_before_reset = ufw.list_rules()
    assert len(rules_before_reset) > 0

    ufw.reset()
    rules_after_reset = ufw.list_rules()
    assert len(rules_after_reset) == 0


def test_add_rule_port(ufw):
    # Add a rule to allow port
    ret = ufw.add_rule(
        action="allow",
        dport="22000",
        proto="tcp",
        direction="in",
    )

    assert ret == "Rule added"
    rules = ufw.list_rules()

    assert "### tuple ### allow tcp 22000 0.0.0.0/0 any 0.0.0.0/0 in\n" in rules


def test_add_rule_deny_port(ufw):
    # Add a rule to deny port
    ret = ufw.add_rule(
        action="deny",
        dport="23000",
        proto="tcp",
        direction="in",
    )
    assert ret == "Rule added"

    rules = ufw.list_rules()

    assert "### tuple ### deny tcp 23000 0.0.0.0/0 any 0.0.0.0/0 in\n" in rules


def test_add_rule_to_ip(ufw):
    # Add a rule to specific IP
    ret = ufw.add_rule(
        action="allow",
        direction="in",
        dst="12.34.56.78",
    )
    assert ret == "Rule added"

    rules = ufw.list_rules()
    assert "### tuple ### allow any any 12.34.56.78 any 0.0.0.0/0 in\n" in rules


def test_add_rule_from_ip(ufw):
    # Add a rule to specific IP
    ret = ufw.add_rule(
        action="allow",
        direction="in",
        src="12.34.56.78",
    )
    assert ret == "Rule added"

    rules = ufw.list_rules()
    assert "### tuple ### allow any any 0.0.0.0/0 any 12.34.56.78 in\n" in rules


def test_remove_rule(ufw):
    # Add a rule to allow port
    ufw.add_rule(
        action="allow",
        dport="24000",
        proto="tcp",
        direction="in",
    )

    rules_before = ufw.list_rules()
    assert "### tuple ### allow tcp 24000 0.0.0.0/0 any 0.0.0.0/0 in\n" in rules_before
    # Remove the rule
    ufw.remove_rule(
        action="allow",
        dport="24000",
        proto="tcp",
        direction="in",
    )
    rules_after = ufw.list_rules()
    assert "### tuple ### allow tcp 24000 0.0.0.0/0 any 0.0.0.0/0 in\n" not in rules_after


def test_application_name_with_proto_raises_error(ufw):
    with pytest.raises(SaltInvocationError):
        ufw.add_rule(
            action="allow",
            dport="SomeApp",
            proto="tcp",
            direction="in",
        )


def test_list_rules(ufw):
    # Add some rules first
    ufw.add_rule(
        action="allow",
        dport="26000",
        proto="tcp",
        direction="in",
    )
    ufw.add_rule(
        action="deny",
        dport="27000",
        proto="udp",
        direction="in",
    )

    rules = ufw.list_rules()
    assert isinstance(rules, list)
    assert len(rules) >= 2
    # Check that rules contain expected information
    assert any("26000" in str(rule) for rule in rules)
    assert any("27000" in str(rule) for rule in rules)


def test_get_rules(ufw):
    # Add some rules first
    ufw.add_rule(
        action="allow",
        dport="28000",
        proto="tcp",
        direction="in",
    )
    ufw.add_rule(
        action="deny",
        src="10.0.0.1",
        direction="in",
    )

    rules = ufw.get_rules()
    assert isinstance(rules, list)
    assert len(rules) == 2
    # Check that rules dictionary contains numbered entries
    frule = rules[0]
    srule = rules[1]

    assert frule.get("dport") == "28000"
    assert frule.get("protocol") == "tcp"
    assert frule.get("action") == "allow"

    assert srule.get("src") == "10.0.0.1"
    assert srule.get("action") == "deny"


def test_get_rules_with_index(ufw):
    # Add some rules first
    ufw.add_rule(
        action="allow",
        dport="29000",
        proto="tcp",
        direction="in",
    )
    ufw.add_rule(
        action="deny",
        src="10.0.0.2",
        direction="in",
    )
    rules = ufw.get_rules(index=1)
    assert isinstance(rules, list)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.get("action") == "allow"
    assert rule.get("dport") == "29000"
    assert rule.get("protocol") == "tcp"

    rules = ufw.get_rules(index=2)
    assert isinstance(rules, list)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.get("action") == "deny"
    assert rule.get("src") == "10.0.0.2"


def test_add_and_remove_route_ports(ufw):
    initial_rules = ufw.get_rules()
    ret = ufw.add_route(
        action="allow",
        src="10.10.10.1",
        dst="10.10.10.2",
        sport="30000",
        dport="31000",
        proto="tcp",
    )
    assert ret == "Rule added"
    rules = ufw.get_rules()
    assert len(rules) == len(initial_rules) + 1

    assert rules[-1]["action"] == "allow"
    assert rules[-1]["src"] == "10.10.10.1"
    assert rules[-1]["direction"] == "forward"

    ufw.remove_route(
        action="allow",
        src="10.10.10.1",
        dst="10.10.10.2",
        sport="30000",
        dport="31000",
        proto="tcp",
    )
    rules_after = ufw.get_rules()
    assert len(rules_after) == len(initial_rules)


def test_add_and_remove_route_application(ufw):
    initial_rules = ufw.get_rules()
    ret = ufw.add_route(
        action="allow",
        src="192.168.99.1",
        dst="192.168.99.2",
        sport="openssh",
        dport="openssh",
    )
    assert ret == "Rule added"
    rules = ufw.get_rules()
    assert len(rules) == len(initial_rules) + 1

    assert rules[-1]["action"] == "allow"
    assert rules[-1]["src"] == "192.168.99.1"
    assert rules[-1]["dport"] == "22"
    assert rules[-1]["sport"] == "22"
    assert rules[-1]["protocol"] == "tcp"
    assert rules[-1]["direction"] == "forward"

    ufw.remove_route(
        action="allow",
        src="192.168.99.1",
        dst="192.168.99.2",
        sport="openssh",
        dport="openssh",
    )
    rules_after = ufw.get_rules()
    assert len(rules_after) == len(initial_rules)
