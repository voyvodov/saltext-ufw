import logging

import pytest

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


def test_reset(ufw, ufw_client):
    ufw.add_rule(
        action="allow",
        direction="in",
        to_port="25000",
        proto="tcp",
    )
    rules_before_reset = ufw_client.get_current_rules()
    assert len(rules_before_reset.strip().splitlines()) > 0

    ufw.reset()
    rules_after_reset = ufw_client.get_current_rules()
    assert rules_after_reset.strip() == ""


def test_add_rule_port(ufw, ufw_client):
    # Add a rule to allow port
    ret = ufw.add_rule(
        action="allow",
        to_port="22000",
        proto="tcp",
        direction="in",
    )

    assert ret == "Rule added"
    rules = ufw_client.get_current_rules()
    rules = rules.splitlines()

    assert "### tuple ### allow tcp 22000 0.0.0.0/0 any 0.0.0.0/0 in" in rules


def test_add_rule_deny_port(ufw, ufw_client):
    # Add a rule to deny port
    ret = ufw.add_rule(
        action="deny",
        to_port="23000",
        proto="tcp",
        direction="in",
    )
    assert ret == "Rule added"

    rules = ufw_client.get_current_rules()
    rules = rules.splitlines()

    assert "### tuple ### deny tcp 23000 0.0.0.0/0 any 0.0.0.0/0 in" in rules


def test_add_rule_to_ip(ufw, ufw_client):
    # Add a rule to specific IP
    ret = ufw.add_rule(
        action="allow",
        direction="in",
        to_ip="12.34.56.78",
    )
    assert ret == "Rule added"

    rules = ufw_client.get_current_rules()
    rules = rules.splitlines()
    assert "### tuple ### allow any any 12.34.56.78 any 0.0.0.0/0 in" in rules


def test_add_rule_from_ip(ufw, ufw_client):
    # Add a rule to specific IP
    ret = ufw.add_rule(
        action="allow",
        direction="in",
        from_ip="12.34.56.78",
    )
    assert ret == "Rule added"

    rules = ufw_client.get_current_rules()
    rules = rules.splitlines()
    assert "### tuple ### allow any any 0.0.0.0/0 any 12.34.56.78 in" in rules


def test_remove_rule(ufw, ufw_client):
    # Add a rule to allow port
    ufw.add_rule(
        action="allow",
        to_port="24000",
        proto="tcp",
        direction="in",
    )

    rules_before = ufw_client.get_current_rules()
    rules_before = rules_before.splitlines()
    assert "### tuple ### allow tcp 24000 0.0.0.0/0 any 0.0.0.0/0 in" in rules_before
    # Remove the rule
    ufw.remove_rule(
        action="allow",
        to_port="24000",
        proto="tcp",
        direction="in",
    )
    rules_after = ufw_client.get_current_rules()
    rules_after = rules_after.splitlines()
    assert "### tuple ### allow tcp 24000 0.0.0.0/0 any 0.0.0.0/0 in" not in rules_after
