"""
Salt state module
"""

import logging

from salt.exceptions import SaltException
from salt.utils.path import which

from saltext.ufw.utils.ufw import FirewallRule
from saltext.ufw.utils.ufw import network as utilnet
from saltext.ufw.utils.ufw import rules_match
from saltext.ufw.utils.ufw.rules import get_firewall_rules

log = logging.getLogger(__name__)

__virtualname__ = "ufw"


def __virtual__():
    if which("ufw"):
        return True

    return (
        False,
        "The ufw execution module cannot be loaded: the ufw binary is not in the path.",
    )


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

    pre_state = __salt__["ufw.status"]()
    if not pre_state:
        log.error("Failed to get UFW status!")
        ret["result"] = False
        return ret

    if pre_state["status"] == "active":
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "UFW would be enabled."
        ret["changes"] = {"old": "inactive", "new": "active"}
        return ret

    try:
        if not __salt__["ufw.enable"]():
            log.error("Failed to enable UFW!")
            ret["result"] = False
            return ret
        ret["comment"] = "UFW has been enabled."
        ret["changes"] = {"old": "inactive", "new": "active"}
        return ret
    except SaltException as err:
        ret["result"] = False
        ret["comment"] = f"Failed to ensure UFW is enabled! {type(err).__name__}: {err}"
        return ret


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

    pre_state = __salt__["ufw.status"]()
    if not pre_state:
        log.error("Failed to get UFW status!")
        ret["result"] = False
        return ret

    if pre_state["status"] != "active":
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "UFW would be disabled."
        ret["changes"] = {"old": "active", "new": "inactive"}
        return ret

    try:
        if not __salt__["ufw.disable"]():
            log.error("Failed to disable UFW!")
            ret["result"] = False
            return ret
        ret["comment"] = "UFW has been disabled."
        ret["changes"] = {"old": "active", "new": "inactive"}
        return ret
    except SaltException as err:
        ret["result"] = False
        ret["comment"] = f"Failed to ensure UFW is disabled! {type(err).__name__}: {err}"
        return ret


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

    pre_state = __salt__["ufw.status"]()
    if not pre_state:
        ret["result"] = False
        ret["comment"] = "Failed to get UFW status!"
        return ret

    if pre_state["status"] != "active":
        ret["result"] = False
        ret["comment"] = "UFW is not active, cannot set default policy!"
        return ret

    current_default_values = pre_state["default_policy"]

    if current_default_values is None or direction not in current_default_values:
        log.error("Failed to get UFW default policy!")
        ret["result"] = False
        return ret

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
            if not __salt__["ufw.default_policy"](
                policy=policy,
                direction=direction,
            ):
                ret["result"] = False
                ret["comment"] = f"Failed to set default policy for {direction} to {policy}."
                return ret
            ret["comment"] = f"Default policy for {direction} has been set to {policy}."
            return ret
        except SaltException as err:
            log.error("Failed to set UFW default policy! %s: %s", type(err).__name__, err)
            ret["result"] = False
            ret["comment"] = f"Failed to set UFW default policy: {err}"
            return ret
    return ret


def logging_level(name, level):
    """
    Ensure UFW logging level is set as specified.

    .. versionadded:: 0.8.0

    name
        Irrelevant, used only for state identification

    level
        The logging level to set. One of: ``off``, ``low``, ``medium``, ``high``, ``full``

    .. code-block:: yaml

        set_logging_level:
          ufw.logging_level:
            - name: low

    """

    ret = {
        "name": name,
        "changes": {},
        "result": True,
        "comment": "Logging level is already set as specified.",
    }
    changes = {}

    if level not in ["off", "low", "medium", "high", "full"]:
        ret["result"] = False
        ret["comment"] = (
            f"Invalid logging level: {level}. Must be 'off', 'low', 'medium', 'high', or 'full'."
        )
        return ret

    pre_state = __salt__["ufw.status"]()
    if not pre_state:
        log.error("Failed to get UFW status!")
        ret["result"] = False
        return ret

    if pre_state["status"] != "active":
        ret["result"] = False
        ret["comment"] = "UFW is not active, cannot set logging level!"
        return ret

    current_default_values = pre_state["logging"]
    if current_default_values is None:
        log.error("Failed to get UFW logging level!")
        ret["result"] = False
        return ret

    if current_default_values != level:
        changes = {
            "old": current_default_values,
            "new": level,
        }

    ret["changes"] = changes

    if changes:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Logging level would be set to {level}."
            return ret

        try:
            if not __salt__["ufw.logging_level"](
                level=level,
            ):
                ret["result"] = False
                ret["comment"] = f"Failed to set logging level to {level}."
                return ret
            ret["comment"] = f"Logging level has been set to {level}."
            return ret
        except SaltException as err:
            ret["result"] = False
            ret["comment"] = f"Failed to set UFW logging level: {err}"
            return ret
    return ret


def _rule_match(rule):
    """
    Check if rule matches existing rules.
    Returns:
    (True, existing) if exact match found
    (False, existing) if similar rule found with differences
    (False, None) if no match found
    """
    existing_rules = get_firewall_rules()

    for r in existing_rules:
        ex_rule = FirewallRule(
            action=r["action"],
            direction=r["direction"],
            src=r["src"],
            sport=r["sport"],
            dst=r["dst"],
            dport=r["dport"],
            protocol=r["protocol"],
            comment=r["comment"],
        )

        if r.get("dapp", None):
            ex_rule.set_port(r.get("dapp"), loc="dst")
        if r.get("sapp", None):
            ex_rule.set_port(r.get("sapp"), loc="src")

        r_in_iface = r.get("interface_in")
        r_out_iface = r.get("interface_out")

        if r_in_iface != "":
            ex_rule.set_interface("in", r_in_iface)

        if r_out_iface != "":
            ex_rule.set_interface("out", r_out_iface)

        if r["direction"] == "forward":
            ex_rule.forward = True
            ex_rule.direction = "in"

        r_match = rules_match(ex_rule, rule)

        if r_match == 0:
            return True, ex_rule

        if r_match == -1:
            return False, ex_rule

    return False, None


def rule_present(
    name,
    action="allow",
    postion=0,
    direction="in",
    interface=None,
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
    logtype=None,
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

    position
        The position of the rule to remove (1-based index).
        If > 0 the rule will be inserted at the specified position.
        If -1 the rule will be prepended.

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

    logtype
        Can be ``log`` or ``log-all``.
        If set to ``log``, will log all new connections matching the rule.
        If set to ``log-all``, enables logging for all matching packets.

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
        ret["result"] = False
        ret["comment"] = f"Invalid direction: {direction}. Must be 'in' or 'out'."
        return ret

    if action not in ["allow", "deny", "reject", "limit"]:
        ret["result"] = False
        ret["comment"] = f"Invalid action: {action}. Must be 'allow', 'deny', 'reject', or 'limit'."
        return ret

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

    if logtype not in (None, "log", "log-all"):
        ret["result"] = False
        ret["comment"] = "logtype must be either 'log', 'log-all', or None."
        return ret

    rule = FirewallRule(
        action=action,
        direction=direction,
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        protocol=proto,
        comment=comment,
    )
    try:
        if interface is not None:
            rule.set_interface(direction, interface)
        rule.position = postion
        rule.set_logtype(logtype)
        rule.validate()
    except ValueError as err:
        ret["result"] = False
        ret["comment"] = f"Invalid rule parameter: {err}"
        return ret

    is_match, existing_rule = _rule_match(rule)
    if not is_match and existing_rule is not None:
        changes = {
            "old": existing_rule.build_rule_string(),
            "new": rule.build_rule_string(),
        }
    elif not is_match:
        changes = {
            "old": "",
            "new": rule.build_rule_string(),
        }

    ret["changes"] = changes

    if changes:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The rule would be added."
            return ret

        try:
            if (
                __salt__["ufw.add_rule"](
                    action=action,
                    direction=direction,
                    interface=interface,
                    src=src,
                    sport=sport,
                    dst=dst,
                    dport=dport,
                    proto=proto,
                    logtype=logtype,
                    comment=comment,
                )
                is False
            ):
                ret["result"] = False
                ret["comment"] = "Failed to add UFW rule."
                return ret
            ret["comment"] = "The rule has been added."
            return ret
        except SaltException as err:
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
        ret["result"] = False
        ret["comment"] = f"Invalid direction: {direction}. Must be 'in' or 'out'."
        return ret

    if action not in ["allow", "deny", "reject", "limit"]:
        ret["result"] = False
        ret["comment"] = f"Invalid action: {action}. Must be 'allow', 'deny', 'reject', or 'limit'."
        return ret

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

    rule = FirewallRule(
        action=action,
        direction=direction,
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        protocol=proto,
    )
    try:
        if interface is not None:
            rule.set_interface(direction, interface)
        rule.delete = True
        rule.validate()
    except ValueError as err:
        ret["result"] = False
        ret["comment"] = f"Invalid rule parameter: {err}"
        return ret

    _, existing_rule = _rule_match(rule)
    # Only if we have match (don't care about log level or comment) and action is the same!
    if existing_rule is not None and action == existing_rule.action:
        changes = {
            "old": existing_rule.build_rule_string(),
            "new": "",
        }

    ret["changes"] = changes

    if changes:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The rule would be removed."
            return ret

        try:
            if (
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
                is False
            ):
                ret["result"] = False
                ret["comment"] = "Failed to remove UFW rule."
                return ret
            ret["comment"] = "The rule has been removed."
            return ret
        except SaltException as err:
            ret["result"] = False
            ret["comment"] = f"Failed to remove UFW rule: {err}"
            return ret

    return ret


def route_present(
    name,
    action="allow",
    position=0,
    interface_in=None,
    interface_out=None,
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
    logtype=None,
    comment=None,
):
    """
    Ensure the UFW route rule is present as specified.
    Rules can be inserted at a specific position or appended to the end of the ruleset.

    .. versionadded:: 0.8.0

    name
        Irrelevant, used only for state identification

    action
        The action to take. One of: ``allow``, ``deny``, ``reject``, ``limit``

    position
        The position of the rule to remove (1-based index).
        If > 0 the rule will be inserted at the specified position.
        If -1 the rule will be prepended.

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

    logtype
        Can be ``log`` or ``log-all``.
        If set to ``log``, will log all new connections matching the rule.
        If set to ``log-all``, enables logging for all matching packets.

    comment
        An optional comment to associate with the rule.

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

    if logtype not in (None, "log", "log-all"):
        ret["result"] = False
        ret["comment"] = "logtype must be either 'log', 'log-all', or None."
        return ret

    rule = FirewallRule(
        action=action,
        dport=dport,
        dst=dst,
        src=src,
        sport=sport,
        protocol=proto,
        forward=True,
        comment=comment,
    )

    try:
        if interface_in is not None:
            rule.set_interface("in", interface_in)
        if interface_out is not None:
            rule.set_interface("out", interface_out)
        rule.position = position
        rule.set_logtype(logtype)
        rule.validate()
    except ValueError as err:
        ret["result"] = False
        ret["comment"] = f"Invalid rule parameter: {err}"
        return ret

    is_match, existing_rule = _rule_match(rule)
    if not is_match and existing_rule is not None:
        changes = {
            "old": existing_rule.build_rule_string(),
            "new": rule.build_rule_string(),
        }
    elif not is_match:
        changes = {
            "old": "",
            "new": rule.build_rule_string(),
        }

    ret["changes"] = changes

    if changes:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The route rule would be added."
            return ret

        try:
            if (
                __salt__["ufw.add_route"](
                    action=action,
                    interface_in=interface_in,
                    interface_out=interface_out,
                    src=src,
                    sport=sport,
                    dst=dst,
                    dport=dport,
                    proto=proto,
                    logtype=logtype,
                    comment=comment,
                )
                is False
            ):
                ret["result"] = False
                ret["comment"] = "Failed to add UFW route rule."
                return ret
            ret["comment"] = "The route rulehas been added."
            return ret
        except SaltException as err:
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

    .. versionadded:: 0.8.0

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

    rule = FirewallRule(
        action=action,
        dst=dst,
        dport=dport,
        src=src,
        sport=sport,
        protocol=proto,
        forward=True,
    )
    try:
        if interface_in is not None:
            rule.set_interface("in", interface_in)
        if interface_out is not None:
            rule.set_interface("out", interface_out)
        rule.delete = True
        rule.validate()
    except ValueError as err:
        ret["result"] = False
        ret["comment"] = f"Invalid rule parameter: {err}"
        return ret

    _, existing_rule = _rule_match(rule)
    # Only if we have match (don't care about log level or comment) and action is the same!
    if existing_rule is not None and action == existing_rule.action:
        changes = {
            "old": existing_rule.build_rule_string(),
            "new": "",
        }

    ret["changes"] = changes

    if changes:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The route rule would be removed."
            return ret

        try:
            if (
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
                is False
            ):
                ret["result"] = False
                ret["comment"] = "Failed to remove UFW route rule."
                return ret
            ret["comment"] = "The route rule has been removed."
            return ret
        except SaltException as err:
            ret["result"] = False
            ret["comment"] = f"Failed to remove UFW route rule: {err}"
            return ret

    return ret
