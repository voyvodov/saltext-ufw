"""
Salt state module
"""

import logging

from saltext.ufw.utils.ufw import network as utilnet
from saltext.ufw.utils.ufw.client import get_client
from saltext.ufw.utils.ufw.exceptions import UFWCommandError
from saltext.ufw.utils.ufw.filter import filter_line_that_contains
from saltext.ufw.utils.ufw.filter import filter_line_that_contains_ipv4
from saltext.ufw.utils.ufw.filter import filter_line_that_contains_ipv6
from saltext.ufw.utils.ufw.filter import filter_line_that_not_start_with
from saltext.ufw.utils.ufw.filter import remove_tuple_prefix

log = logging.getLogger(__name__)

__virtualname__ = "ufw"


def __virtual__():
    # To force a module not to load return something like:
    #   return (False, "The ufw state module is not implemented yet")

    # Replace this with your own logic
    return __virtualname__


def _compare_rules(rules_current, rules_dry, from_ip, to_ip):
    changes = {}

    if from_ip is None:
        from_ip = "0.0.0.0/0"
    if to_ip is None:
        to_ip = "0.0.0.0/0"

    # Filter out non-tuple lines. Those are rules which are not relevant for comparison
    # We care only about user defined rules which are stored as tuples
    rules_dry = filter_line_that_not_start_with("### tuple", rules_dry)

    # Remove tuple prefix from current rules for accurate comparison
    rules_current = remove_tuple_prefix(rules_current)
    rules_dry = remove_tuple_prefix(rules_dry)

    log.info(f"Checking for from_ip: {from_ip}, to_ip: {to_ip}")
    if utilnet.is_starting_by_ipv4(from_ip) or utilnet.is_starting_by_ipv4(to_ip):
        rules_current = filter_line_that_contains_ipv4(rules_current)
        rules_dry = filter_line_that_contains_ipv4(rules_dry)
        if rules_current != rules_dry:
            changes["old"] = rules_current
            changes["new"] = rules_dry
    elif utilnet.is_starting_by_ipv6(from_ip) or utilnet.is_starting_by_ipv6(to_ip):
        rules_current = filter_line_that_contains_ipv6(rules_current)
        rules_dry = filter_line_that_contains_ipv6(rules_dry)
        if rules_current != rules_dry:
            changes["old"] = rules_current
            changes["new"] = rules_dry
    elif rules_current != rules_dry:
        changes["old"] = rules_current
        changes["new"] = rules_dry
    return changes


def enabled(name):
    """
    Ensure UFW is enabled

    .. code-block:: yaml

        enable_ufw:
          ufw.enabled
    """

    ret = {
        "name": name,
        "changes": {},
        "result": True,
        "comment": "UFW is already enabled.",
    }

    try:
        pre_state = __salt__["ufw.status"]()
    except UFWCommandError as err:
        log.error("Failed to get UFW status! %s: %s", type(err).__name__, err)
        ret["result"] = False
        ret["comment"] = f"Failed to get UFW status: {err}"
        return ret

    if pre_state["status"] == "active":
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "UFW would be enabled."
        ret["changes"] = {"old": "inactive", "new": "active"}
        return ret

    try:
        __salt__["ufw.enable"]()
        ret["comment"] = "UFW has been enabled."
        ret["changes"] = {"old": "inactive", "new": "active"}
        return ret
    except UFWCommandError as err:
        log.error("Failed to ensure UFW is enabled! %s: %s", type(err).__name__, err)
        return False


def disabled(name):
    """
    Ensure UFW is disabled

    .. code-block:: yaml

        disable_ufw:
          ufw.disabled
    """

    ret = {
        "name": name,
        "changes": {},
        "result": True,
        "comment": "UFW is already disabled.",
    }
    try:
        pre_state = __salt__["ufw.status"]()
    except UFWCommandError as err:
        log.error("Failed to get UFW status! %s: %s", type(err).__name__, err)
        ret["result"] = False
        ret["comment"] = f"Failed to get UFW status: {err}"
        return ret

    if pre_state["status"] != "active":
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "UFW would be disabled."
        ret["changes"] = {"old": "active", "new": "inactive"}
        return ret

    try:
        __salt__["ufw.disable"]()
        ret["comment"] = "UFW has been disabled."
        ret["changes"] = {"old": "active", "new": "inactive"}
        return ret
    except UFWCommandError as err:
        log.error("Failed to ensure UFW is disabled! %s: %s", type(err).__name__, err)
        return False


def default_policy(
    name,
    policy,
    direction="incoming",
):
    """
    Ensure UFW default policy is set as specified.

    name
        Irrelevant, used only for state identification

    policy
        The default policy to set. One of: ``allow``, ``deny``, ``reject``

    direction
        The direction of the policy. One of: ``incoming``, ``outgoing``, ``routed`` ``None``
        Default is ``incoming``
    """
    ret = {
        "name": name,
        "changes": {},
        "result": True,
        "comment": "Default policy is already set as specified.",
    }
    changes = {}

    try:
        pre_state = __salt__["ufw.status"]()
    except UFWCommandError as err:
        log.error("Failed to get UFW status! %s: %s", type(err).__name__, err)
        ret["result"] = False
        ret["comment"] = f"Failed to get UFW status: {err}"
        return ret

    current_default_values = pre_state["default_policy"]

    d = current_default_values[direction]
    if d not in (policy, "disabled"):
        changes = {
            "old": {
                "direction": direction,
                "policy": d,
            },
            "new": {
                "direction": direction,
                "policy": policy,
            },
        }

    ret["changes"] = changes
    if changes:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Default policy for {direction} would be set to {policy}."
            return ret

        try:
            __salt__["ufw.default_policy"](
                policy=policy,
                direction=direction,
            )
            ret["comment"] = f"Default policy for {direction} has been set to {policy}."
            return ret
        except UFWCommandError as err:
            log.error("Failed to set UFW default policy! %s: %s", type(err).__name__, err)
            ret["result"] = False
            ret["comment"] = f"Failed to set UFW default policy: {err}"
            return ret
    return ret


def rule_present(
    name,
    action="allow",
    insert=None,
    direction="in",
    interface=None,
    from_ip=None,
    from_port=None,
    to_ip=None,
    to_port=None,
    proto=None,
    app=None,
    comment=None,
):
    """
    Ensure the UFW rule is present as specified.
    Rules can be inserted at a specific position or appended to the end of the ruleset.


    name
        Irrelevant, used only for state identification

    action
        The action to take. One of: ``allow``, ``deny``, ``reject``, ``limit``
        Default is ``allow``

    insert
        The position to insert the rule at. If not specified, the rule is added at the end of the ruleset.

    direction
        The direction of the rule. One of: ``in``, ``out``
        Default is ``in``

    interface
        The network interface to apply the rule to. If not specified, the rule applies to all interfaces.

    from_ip
        The source IP address or subnet for the rule. If not specified, the rule applies to all source addresses.

    from_port
        The source port for the rule. If not specified, the rule applies to all source ports.

    to_ip
        The destination IP address or subnet for the rule. If not specified, the rule applies to all destination addresses.

    to_port
        The destination port for the rule. If not specified, the rule applies to all destination ports.

    proto
        The protocol for the rule. One of: ``tcp``, ``udp``, ``any``
        If not specified, the rule applies to all protocols.
        If specified, any of the ``to_port``, ``from_port``, ``to_ip``, ``from_ip`` must also be set.

    app
        The application profile to use for the rule. If specified, all other parameters except ``direction`` are ignored.

    comment
        An optional comment to associate with the rule.

    """

    ret = {
        "name": name,
        "result": True,
        "comment": "The rule is present as specified",
        "changes": {},
    }

    changes = {}

    if proto is not None and (
        from_port is None and to_port is None and from_ip is None and to_ip is None
    ):
        ret["result"] = False
        ret[
            "comment"
        ] = """When 'proto' is specified,
            any of 'to_port', 'from_port', 'to_ip', 'from_ip' must also be specified."""
        return ret

    rules_dry = __salt__["ufw.add_rule"](
        insert=insert,
        action=action,
        direction=direction,
        interface=interface,
        from_ip=from_ip,
        from_port=from_port,
        to_ip=to_ip,
        to_port=to_port,
        proto=proto,
        app=app,
        comment=comment,
        dry_run=True,
    )

    # Filter out lines with "Skipping"
    # If the output is empty after that, the rule is already present
    nb_skipping_line = len(filter_line_that_contains("Skipping", rules_dry))
    if nb_skipping_line > 0:
        return ret

    client = get_client()
    # Get current rules and compare
    try:
        rules_current = client.get_current_rules()
    except UFWCommandError as err:
        log.error("Failed to get UFW current rules! %s: %s", type(err).__name__, err)
        ret["result"] = False
        ret["comment"] = f"Failed to get UFW current rules: {err}"
        return ret

    changes = _compare_rules(
        rules_current=rules_current,
        rules_dry=rules_dry,
        from_ip=from_ip,
        to_ip=to_ip,
    )

    ret["changes"] = changes

    if changes:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The rule would be added."
            return ret

        try:
            __salt__["ufw.add_rule"](
                action=action,
                direction=direction,
                interface=interface,
                from_ip=from_ip,
                from_port=from_port,
                to_ip=to_ip,
                to_port=to_port,
                proto=proto,
                app=app,
                comment=comment,
            )
            ret["comment"] = "The rule has been added."
            return ret
        except UFWCommandError as err:
            log.error("Failed to add UFW rule! %s: %s", type(err).__name__, err)
            ret["result"] = False
            ret["comment"] = f"Failed to add UFW rule: {err}"
            return ret

    return ret


def rule_absent(
    name,
    action="allow",
    direction="in",
    interface=None,
    from_ip=None,
    from_port=None,
    to_ip=None,
    to_port=None,
    proto=None,
    app=None,
):
    """
    Ensure the UFW rule is absent as specified.

    name
        Irrelevant, used only for state identification

    action
        The action of the rule to remove. One of: ``allow``, ``deny``, ``reject``, ``limit``
        Default is ``allow``

    direction
        The direction of the rule. One of: ``in``, ``out``
        Default is ``in``

    interface
        The network interface of the rule to remove. If not specified, the rule applies to all interfaces.

    from_ip
        The source IP address or subnet of the rule to remove. If not specified, the rule applies to all source addresses.

    from_port
        The source port of the rule to remove. If not specified, the rule applies to all source ports.

    to_ip
        The destination IP address or subnet of the rule to remove. If not specified, the rule applies to all destination addresses.

    to_port
        The destination port of the rule to remove. If not specified, the rule applies to all destination ports.

    proto
        The protocol of the rule to remove. One of: ``tcp``, ``udp``, ``any``
        If not specified, the rule applies to all protocols.
        If specified, ``to_port`` or ``from_port`` must also be set.

    """

    ret = {
        "name": name,
        "result": True,
        "comment": "The rule is absent as specified",
        "changes": {},
    }

    changes = {}

    if proto is not None and (
        from_port is None and to_port is None and from_ip is None and to_ip is None
    ):
        ret["result"] = False
        ret[
            "comment"
        ] = """When 'proto' is specified,
            any of 'to_port', 'from_port', 'to_ip', 'from_ip' must also be specified."""
        return ret

    rules_dry = __salt__["ufw.remove_rule"](
        action=action,
        direction=direction,
        interface=interface,
        from_ip=from_ip,
        from_port=from_port,
        to_ip=to_ip,
        to_port=to_port,
        proto=proto,
        app=app,
        dry_run=True,
    )

    client = get_client()
    # Get current rules and compare
    try:
        rules_current = client.get_current_rules()
    except UFWCommandError as err:
        log.error("Failed to get UFW current rules! %s: %s", type(err).__name__, err)
        ret["result"] = False
        ret["comment"] = f"Failed to get UFW current rules: {err}"
        return ret

    changes = _compare_rules(
        rules_current=rules_current,
        rules_dry=rules_dry,
        from_ip=from_ip,
        to_ip=to_ip,
    )

    ret["changes"] = changes

    if changes:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The rule would be removed."
            return ret

        try:
            __salt__["ufw.remove_rule"](
                action=action,
                direction=direction,
                interface=interface,
                from_ip=from_ip,
                from_port=from_port,
                to_ip=to_ip,
                to_port=to_port,
                proto=proto,
                app=app,
            )
            ret["comment"] = "The rule has been removed."
            return ret
        except UFWCommandError as err:
            log.error("Failed to remove UFW rule! %s: %s", type(err).__name__, err)
            ret["result"] = False
            ret["comment"] = f"Failed to remove UFW rule: {err}"
            return ret

    return ret
