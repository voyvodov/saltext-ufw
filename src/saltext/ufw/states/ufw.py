"""
Salt state module
"""

import logging

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.ufw.utils.ufw import network as utilnet
from saltext.ufw.utils.ufw.filter import filter_line_that_contains
from saltext.ufw.utils.ufw.filter import filter_line_that_contains_ipv4
from saltext.ufw.utils.ufw.filter import filter_line_that_contains_ipv6
from saltext.ufw.utils.ufw.filter import filter_line_that_not_start_with
from saltext.ufw.utils.ufw.rules import list_current_rules

log = logging.getLogger(__name__)

__virtualname__ = "ufw"


def __virtual__():
    # To force a module not to load return something like:
    #   return (False, "The ufw state module is not implemented yet")

    # Replace this with your own logic
    return __virtualname__


def _compare_rules(rules_current, rules_dry, src, dst):
    changes = {}

    # Filter out non-tuple lines. Those are rules which are not relevant for comparison
    # We care only about user defined rules which are stored as tuples
    rules_dry = filter_line_that_not_start_with("### tuple", rules_dry)

    if utilnet.is_starting_by_ipv4(src) or utilnet.is_starting_by_ipv4(dst):
        rules_current = filter_line_that_contains_ipv4(rules_current)
        rules_dry = filter_line_that_contains_ipv4(rules_dry)
        if rules_current != rules_dry:
            changes["old"] = rules_current
            changes["new"] = rules_dry
    elif utilnet.is_starting_by_ipv6(src) or utilnet.is_starting_by_ipv6(dst):
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

    name
        Irrelevant, used only for state identification

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
    except CommandExecutionError as err:
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
    except CommandExecutionError as err:
        log.error("Failed to ensure UFW is enabled! %s: %s", type(err).__name__, err)
        return False


def disabled(name):
    """
    Ensure UFW is disabled

    name
        Irrelevant, used only for state identification

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
    except CommandExecutionError as err:
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
    except CommandExecutionError as err:
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

    .. code-block:: yaml

        set_default_incoming_policy:
          ufw.default_policy:
            - policy: deny
            - direction: incoming

    .. code-block:: yaml

        set_default_routing_policy:
          ufw.default_policy:
            - policy: allow
            - direction: routed

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
    except CommandExecutionError as err:
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
        except CommandExecutionError as err:
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
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
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

    src
        The source IP address or subnet for the rule.

    sport
        The source port, port range or application name for the rule. If not specified, the rule applies to all source ports.

    dst
        The destination IP address or subnet for the rule.

    dport
        The destination port, port range or application name for the rule. If not specified, the rule applies to all destination ports.

    proto
        The protocol for the rule. One of: ``tcp``, ``udp``, ``any``
        If not ``any``, ``dport`` or ``sport`` must also be set as port numbers.

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

    if direction not in ["in", "out"]:
        log.error(f"Invalid direction: {direction}. Must be 'in' or 'out'.")
        raise SaltInvocationError(f"Invalid direction: {direction}. Must be 'in' or 'out'.")

    if action not in ["allow", "deny", "reject", "limit"]:
        log.error(f"Invalid action: {action}. Must be 'allow', 'deny', 'reject', or 'limit'.")
        raise SaltInvocationError(
            f"Invalid action: {action}. Must be 'allow', 'deny', 'reject', or 'limit'."
        )

    if proto != "any":
        if (utilnet.is_port_number(sport) is False and utilnet.is_port_number(dport) is False) or (
            sport is None and dport is None
        ):
            ret["result"] = False
            ret[
                "comment"
            ] = """When 'proto' is specified,
                any of 'dport', 'sport' must also be specified as port numbers."""
            return ret

    try:
        rules_dry = __salt__["ufw.add_rule"](
            insert=insert,
            action=action,
            direction=direction,
            interface=interface,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            proto=proto,
            comment=comment,
            dry_run=True,
        )
    except CommandExecutionError as err:
        log.error("Failed to check UFW rule! %s: %s", type(err).__name__, err)
        ret["result"] = False
        ret["comment"] = f"Failed to check UFW rule: {err}"
        return ret

    # Filter out lines with "Skipping"
    # If the output is empty after that, the rule is already present
    nb_skipping_line = len(filter_line_that_contains("Skipping", rules_dry))
    if nb_skipping_line > 0:
        return ret

    # Get current rules and compare
    rules_current = list_current_rules()

    changes = _compare_rules(
        rules_current=rules_current,
        rules_dry=rules_dry,
        src=src,
        dst=dst,
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
                src=src,
                sport=sport,
                dst=dst,
                dport=dport,
                proto=proto,
                comment=comment,
            )
            ret["comment"] = "The rule has been added."
            return ret
        except CommandExecutionError as err:
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
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
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

    src
        The source IP address or subnet of the rule to remove.

    sport
        The source port, port range or application name for the rule to remove. If not specified, the rule applies to all source ports.

    dst
        The destination IP address or subnet of the rule to remove.

    dport
        The destination port, port range or application name for the rule to remove. If not specified, the rule applies to all destination ports.

    proto
        The protocol of the rule to remove. One of: ``tcp``, ``udp``, ``any``
        If not ``any``, ``dport`` or ``sport`` must also be set as port numbers.

    """

    ret = {
        "name": name,
        "result": True,
        "comment": "The rule is absent as specified",
        "changes": {},
    }

    changes = {}

    if direction not in ["in", "out"]:
        log.error(f"Invalid direction: {direction}. Must be 'in' or 'out'.")
        raise SaltInvocationError(f"Invalid direction: {direction}. Must be 'in' or 'out'.")

    if action not in ["allow", "deny", "reject", "limit"]:
        log.error(f"Invalid action: {action}. Must be 'allow', 'deny', 'reject', or 'limit'.")
        raise SaltInvocationError(
            f"Invalid action: {action}. Must be 'allow', 'deny', 'reject', or 'limit'."
        )

    if proto != "any":
        if (utilnet.is_port_number(sport) is False and utilnet.is_port_number(dport) is False) or (
            sport is None and dport is None
        ):
            ret["result"] = False
            ret[
                "comment"
            ] = """When 'proto' is specified,
                any of 'dport', 'sport' must also be specified as port numbers."""
            return ret

    try:
        rules_dry = __salt__["ufw.remove_rule"](
            action=action,
            direction=direction,
            interface=interface,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            proto=proto,
            dry_run=True,
        )
    except CommandExecutionError as err:
        log.error("Failed to remove UFW rule in dry-run mode! %s: %s", type(err).__name__, err)
        ret["result"] = False
        ret["comment"] = f"Failed to remove UFW rule in dry-run mode: {err}"
        return ret

    rules_current = list_current_rules()

    changes = _compare_rules(
        rules_current=rules_current,
        rules_dry=rules_dry,
        src=src,
        dst=dst,
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
                src=src,
                sport=sport,
                dst=dst,
                dport=dport,
                proto=proto,
            )
            ret["comment"] = "The rule has been removed."
            return ret
        except CommandExecutionError as err:
            log.error("Failed to remove UFW rule! %s: %s", type(err).__name__, err)
            ret["result"] = False
            ret["comment"] = f"Failed to remove UFW rule: {err}"
            return ret

    return ret


def route_present(
    name,
    action="allow",
    insert=None,
    interface_in=None,
    interface_out=None,
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
    comment=None,
    rule_log=False,
):
    """
    Ensure the UFW route rule is present as specified.
    Rules can be inserted at a specific position or appended to the end of the ruleset.

    name
        Irrelevant, used only for state identification

    action
        The action to take. One of: ``allow``, ``deny``, ``reject``, ``limit``

    insert
        The position to insert the rule at. If not specified, the rule is added at the end of the ruleset.

    interface_in
        The incoming network interface to apply the rule to. If not specified, the rule applies to all interfaces.

    interface_out
        The outgoing network interface to apply the rule to. If not specified, the rule applies to all interfaces.

    src
        The source IP address or subnet for the rule.

    sport
        The source port, port range or application name for the rule. If not specified, the rule applies to all source ports.

    dst
        The destination IP address or subnet for the rule.

    dport
        The destination port, port range or application name for the rule. If not specified, the rule applies to all destination ports.

    proto
        The protocol for the rule. One of: ``tcp``, ``udp``, ``any``
        If not ``any``, ``dport`` or ``sport`` must also be set as port numbers.

    comment
        An optional comment to associate with the rule.

    rule_log
        Can be ``true``, ``false`` or ``all``.
        If set to ``true``, will log all new connections matching the rule.
        If set to ``all``, enables logging for all matching packets.


    .. code-block:: yaml

        # Allow forwarding between eth0 and eth1 interfaces
        allow_from_eth0_to_eth1:
        ufw.route_present:
            - action: allow
            - interface_in: eth0
            - interface_out: eth1

        allow_from_eth1_to_eth0:
        ufw.route_present:
            - action: allow
            - interface_in: eth1
            - interface_out: eth0


    .. code-block:: yaml

        # Deny forwarding from specific IP/subnet to specific IP/subnet
        deny_from_ip1_to_ip2:
        ufw.route_present:
            - action: deny
            - src: 192.168.0.0/24
            - dst: 192.168.1.20

    .. code-block:: yaml

        # Allow port forwarding of ssh traffic via app between eth0 and eth1 interfaces
        allow_ssh_from_eth0_to_eth1:
          ufw.route_present:
            - action: allow
            - interface_in: eth0
            - interface_out: eth1
            - dport: OpenSSH
    """

    ret = {
        "name": name,
        "result": True,
        "comment": "The rule is present as specified",
        "changes": {},
    }

    changes = {}

    if proto != "any":
        if (utilnet.is_port_number(sport) is False and utilnet.is_port_number(dport) is False) or (
            sport is None and dport is None
        ):
            ret["result"] = False
            ret[
                "comment"
            ] = """When 'proto' is specified,
                any of 'dport', 'sport' must also be specified as port numbers."""
            return ret

    try:
        rules_dry = __salt__["ufw.add_route"](
            insert=insert,
            action=action,
            interface_in=interface_in,
            interface_out=interface_out,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            proto=proto,
            comment=comment,
            rule_log=rule_log,
            dry_run=True,
        )
    except CommandExecutionError as err:
        log.error("Failed to add UFW route rule in dry-run mode! %s: %s", type(err).__name__, err)
        ret["result"] = False
        ret["comment"] = f"Failed to add UFW route rule in dry-run mode: {err}"
        return ret

    # Filter out lines with "Skipping"
    # If the output is empty after that, the rule is already present
    nb_skipping_line = len(filter_line_that_contains("Skipping", rules_dry))
    if nb_skipping_line > 0:
        return ret

    # Get current rules and compare
    rules_current = list_current_rules()

    changes = _compare_rules(
        rules_current=rules_current,
        rules_dry=rules_dry,
        src=src,
        dst=dst,
    )

    ret["changes"] = changes

    if changes:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The route rule would be added."
            return ret

        try:
            __salt__["ufw.add_route"](
                action=action,
                interface_in=interface_in,
                interface_out=interface_out,
                src=src,
                sport=sport,
                dst=dst,
                dport=dport,
                proto=proto,
                rule_log=rule_log,
                comment=comment,
            )
            ret["comment"] = "The route rulehas been added."
            return ret
        except CommandExecutionError as err:
            log.error("Failed to add UFW route rule! %s: %s", type(err).__name__, err)
            ret["result"] = False
            ret["comment"] = f"Failed to add UFW route rule: {err}"
            return ret

    return ret


def route_absent(
    name,
    action="allow",
    interface_in=None,
    interface_out=None,
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
):
    """
    Ensure the UFW route rule is absent as specified.

    name
        Irrelevant, used only for state identification

    action
        The action of the rule to remove. One of: ``allow``, ``deny``, ``reject``, ``limit``

    interface_in
        The incoming network interface of the rule to remove. If not specified, the rule applies to all interfaces.

    interface_out
        The outgoing network interface of the rule to remove. If not specified, the rule applies to all interfaces.

    src
        The source IP address or subnet of the rule to remove.

    sport
        The source port or application name for the rule to remove.

    dst
        The destination IP address or subnet of the rule to remove.

    dport
        The destination port or application name for the rule to remove.

    proto
        The protocol of the rule to remove. One of: ``tcp``, ``udp``, ``any``
        If not ``any``, ``dport`` or ``sport`` must also be set as port numbers.


    .. code-block:: yaml

        # Remove forwarding rule between eth0 and eth1 interfaces
        remove_allow_from_eth0_to_eth1:
          ufw.route_absent:
            - action: allow
            - interface_in: eth0
            - interface_out: eth1

    .. code-block:: yaml

        # Remove forwarding rule from specific IP/subnet to specific IP/subnet
        remove_deny_from_ip1_to_ip2:
          ufw.route_absent:
            - action: deny
            - src: 192.168.0.0/24
            - dst: 192.168.1.15

    .. code-block:: yaml

        # Remove port forwarding of ssh traffic via app between eth0 and eth1 interfaces
        remove_ssh_from_eth0_to_eth1:
          ufw.route_absent:
            - action: allow
            - interface_in: eth0
            - interface_out: eth1
            - dport: OpenSSH
    """

    ret = {
        "name": name,
        "result": True,
        "comment": "The route rule is absent as specified",
        "changes": {},
    }

    changes = {}

    if proto != "any":
        if (utilnet.is_port_number(sport) is False and utilnet.is_port_number(dport) is False) or (
            sport is None and dport is None
        ):
            ret["result"] = False
            ret[
                "comment"
            ] = """When 'proto' is specified,
                any of 'dport', 'sport' must also be specified as port numbers."""
            return ret

    try:
        rules_dry = __salt__["ufw.remove_route"](
            action=action,
            interface_in=interface_in,
            interface_out=interface_out,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            proto=proto,
            dry_run=True,
        )
    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = f"Failed to remove UFW route rule in dry-run mode: {err}"
        return ret

    rules_current = list_current_rules()

    changes = _compare_rules(
        rules_current=rules_current,
        rules_dry=rules_dry,
        src=src,
        dst=dst,
    )

    ret["changes"] = changes

    if changes:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The route rule would be removed."
            return ret

        try:
            __salt__["ufw.remove_route"](
                action=action,
                interface_in=interface_in,
                interface_out=interface_out,
                src=src,
                sport=sport,
                dst=dst,
                dport=dport,
                proto=proto,
            )
            ret["comment"] = "The route rule has been removed."
            return ret
        except CommandExecutionError as err:
            log.error("Failed to remove UFW route rule! %s: %s", type(err).__name__, err)
            ret["result"] = False
            ret["comment"] = f"Failed to remove UFW route rule: {err}"
            return ret

    return ret
