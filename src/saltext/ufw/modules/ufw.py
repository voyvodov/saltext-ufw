"""
Salt execution module
"""

import logging
import re

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError
from salt.utils.path import which

from saltext.ufw.utils.ufw import FirewallRule
from saltext.ufw.utils.ufw import get_client
from saltext.ufw.utils.ufw import network as netutils
from saltext.ufw.utils.ufw.rules import get_firewall_rules
from saltext.ufw.utils.ufw.rules import list_current_rules

log = logging.getLogger(__name__)

__virtualname__ = "ufw"


def __virtual__():
    if which("ufw"):
        return True

    return (
        False,
        "The ufw execution module cannot be loaded: the ufw binary is not in the path.",
    )


def enable():
    """
    Enable UFW

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.enable
    """
    client = get_client()
    try:
        result = client.enable()
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except CommandExecutionError as err:
        log.error("Failed to enable UFW! %s: %s", type(err).__name__, err)
        return False


def disable():
    """
    Disable UFW

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.disable
    """
    client = get_client()
    try:
        result = client.disable()
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except CommandExecutionError as err:
        log.error("Failed to disable UFW! %s: %s", type(err).__name__, err)
        return False


def status(numbered=False, raw=False):
    """
    Get UFW status

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.status

    verbose
        To get more detailed status information.

    numbered
        To get numbered list of rules.
    """
    client = get_client()

    # If numbered is True, set raw to True to get the raw output
    if numbered:
        raw = True
    try:
        result = client.status(verbose=not numbered, numbered=numbered)
        if isinstance(result, dict):
            result = result["stdout"].strip()

        if raw:
            return result

        out = {
            "default_policy": {
                "incoming": None,
                "outgoing": None,
                "routed": None,
            },
            "logging": None,
            "status": None,
        }

        default_policy_r = r"Default: (deny|allow|reject) \(incoming\), (deny|allow|reject) \(outgoing\), (deny|allow|reject|disabled) \(routed\)"
        extract = re.search(default_policy_r, result)

        if extract is not None:
            out["default_policy"]["incoming"] = extract.group(1)
            out["default_policy"]["outgoing"] = extract.group(2)
            out["default_policy"]["routed"] = extract.group(3)

        status_r = r"Status: (active|inactive)"
        extract = re.search(status_r, result)
        if extract is not None:
            out["status"] = extract.group(1)

        logging_r = r"Logging: (?:on \()?(off|low|medium|high|full)\)?"
        extract = re.search(logging_r, result)
        if extract is not None:
            out["logging"] = str(extract.group(1))

        return out

    except CommandExecutionError as err:
        log.error("Failed to get UFW status! %s: %s", type(err).__name__, err)
        return False


def reload():
    """
    Reload UFW

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.reload
    """
    client = get_client()
    try:
        result = client.reload()
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except CommandExecutionError as err:
        log.error("Failed to reload UFW! %s: %s", type(err).__name__, err)
        return False


def default_policy(direction, policy):
    """
    Set UFW default policy.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.default_policy <direction> <policy>

    direction
        The direction to set the default policy for.
        Possible directions: 'incoming', 'outgoing', 'routed'

    policy
        The default policy to set.
        Possible policies: 'allow', 'deny', 'reject', 'limit'
    """
    client = get_client()

    if direction not in ["incoming", "outgoing", "routed"]:
        log.error(f"Invalid direction: {direction}. Must be 'incoming', 'outgoing', or 'routed'.")
        raise SaltInvocationError(
            f"Invalid direction: {direction}. Must be 'incoming', 'outgoing', or 'routed'."
        )

    if policy not in ["allow", "deny", "reject", "limit"]:
        log.error(f"Invalid policy: {policy}. Must be 'allow', 'deny', 'reject', or 'limit'.")
        raise SaltInvocationError(
            f"Invalid policy: {policy}. Must be 'allow', 'deny', 'reject', or 'limit'."
        )

    try:
        result = client.set_default_policy(policy=policy, direction=direction)
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except CommandExecutionError as err:
        log.error("Failed to set UFW default policy! %s: %s", type(err).__name__, err)
        return False


def version():
    """
    Get UFW version.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.version
    """
    client = get_client()
    try:
        major, minor, rev = client.version()
        out = f"{major}.{minor}.{rev}"
        return out
    except CommandExecutionError as err:
        log.error("Failed to get UFW version! %s: %s", type(err).__name__, err)
        return False


def reset():
    """
    Reset UFW to default state.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.reset
    """
    client = get_client()
    try:
        result = client.reset()
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except CommandExecutionError as err:
        log.error("Failed to reset UFW! %s: %s", type(err).__name__, err)
        return False


def _check_rule_params(action, direction, dst, dport, src, sport, proto):

    if action not in ["allow", "deny", "reject", "limit"]:
        raise SaltInvocationError("Invalid action. Must be 'allow', 'deny', 'reject', or 'limit'.")

    if direction and direction not in ["in", "out"]:
        raise SaltInvocationError("Invalid direction. Must be 'in' or 'out'.")

    if dst is None or dst == "":
        raise SaltInvocationError("Destination (dst) must be specified.")

    if src is None or src == "":
        raise SaltInvocationError("Source (src) must be specified.")

    if proto not in (None, "any"):
        if not (dport or sport):
            raise SaltInvocationError(
                "When specifying a protocol, at least one of dport or sport must be set."
            )

        for field_name, field_value in ("dport", dport), ("sport", sport):
            if field_value is None:
                continue
            if not netutils.is_port_number(field_value):
                raise SaltInvocationError(
                    f"When specifying a protocol, {field_name} must be a port number."
                )


def add_rule(
    action="allow",
    direction="in",
    interface=None,
    position=0,
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
    logtype=None,
    comment=None,
):
    """
    Insert or append a UFW rule at a specific position.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.add_rule action=allow direction=in interface=eth0 dst=any dport=2553

    action
        The action to take. Possible values: 'allow', 'deny', 'reject', 'limit'.
    direction
        The direction of the rule. Possible values: 'in', 'out'.
    interface
        The network interface to apply the rule on.
    position
        The position of the rule.
        If set to 0 or not specified, the rule will be appended.
        If set to -1, the rule will be prepended.
        If set to a positive integer, the rule will be inserted at that position (1-based index).
    src
        The source IP address for the rule.
    sport
        The source port, port range or application name for the rule.
    dst
        The destination IP address for the rule.
    dport
        The destination port, port range or application name for the rule.
    proto
        The protocol for the rule (e.g., tcp, udp or any).
        If set to something different than "any", ``dport``, ``sport`` must also be set as port numbers.
    logtype
        Can be ``log`` or ``log-all``.
        If set to ``log``, will log all new connections matching the rule.
        If set to ``log-all``, enables logging for all matching packets.
    comment
        A comment to add to the rule.

    """
    _check_rule_params(action, direction, dst, dport, src, sport, proto)

    if logtype not in (None, "log", "log-all"):
        raise SaltInvocationError("logtype must be either 'log', 'log-all', or None.")

    # Check if src and dst are both IPv4 or both IPv6. If one of them is IPv6 and the other is not, raise an error.
    # In case one of them is IPv6 and the other is the default, convert the default to the appropriate format for IPv6.
    if netutils.is_ipv6(src) and not netutils.is_ipv6(dst):
        if dst == "0.0.0.0/0":
            dst = "::/0"
        else:
            raise SaltInvocationError("Source is IPv6 but destination is not IPv6.")

    if netutils.is_ipv6(dst) and not netutils.is_ipv6(src):
        if src == "0.0.0.0/0":
            src = "::/0"
        else:
            raise SaltInvocationError("Destination is IPv6 but source is not IPv6.")

    client = get_client()

    rule = FirewallRule(
        action=action,
        direction=direction,
        protocol=proto,
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        comment=comment,
    )

    try:
        if interface is not None:
            rule.set_interface(direction, interface)

        rule.position = position
        if logtype:
            rule.set_logtype(logtype)
        rule.validate()
    except ValueError as err:
        raise SaltInvocationError(f"Invalid rule parameters! {type(err).__name__}: {err}") from err

    try:
        ret = client.update_rule(rule)
        if isinstance(ret, dict):
            return ret["stdout"].strip()
        return ret
    except CommandExecutionError as err:
        log.error("Failed to add or update UFW rule! %s: %s", type(err).__name__, err)
        return False


def remove_rule(
    action="allow",
    position=0,
    direction="in",
    interface=None,
    dst="0.0.0.0/0",
    dport=None,
    src="0.0.0.0/0",
    sport=None,
    proto="any",
):
    """
    Remove a UFW rule.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.remove_rule action=allow direction=in interface=eth0 dst=any dport=2553

    action
        The action of the rule to remove. Possible values: 'allow', 'deny', 'reject', 'limit'.
    position
        The position of the rule to remove (1-based index).
        If > 0, other parameters are ignored.
        If 0, other parameters are used to identify the rule to remove.
    direction
        The direction of the rule to remove. Possible values: 'in', 'out'.
    interface
        The network interface of the rule to remove.
    dst
        The destination IP address of the rule to remove.
    dport
        The destination port, port range or application name of the rule to remove.
    src
        The source IP address of the rule to remove.
    sport
        The source port, port range or application name of the rule to remove.
    proto
        The protocol of the rule to remove (e.g., tcp, udp, any).
        If set to something different than "any", ``dport``, ``sport`` must also be set as port numbers.
    """

    _check_rule_params(action, direction, dst, dport, src, sport, proto)

    # Check if src and dst are both IPv4 or both IPv6. If one of them is IPv6 and the other is not, raise an error.
    # In case one of them is IPv6 and the other is the default, convert the default to the appropriate format for IPv6.
    if netutils.is_ipv6(src) and not netutils.is_ipv6(dst):
        if dst == "0.0.0.0/0":
            dst = "::/0"
        else:
            raise SaltInvocationError("Source is IPv6 but destination is not IPv6.")

    if netutils.is_ipv6(dst) and not netutils.is_ipv6(src):
        if src == "0.0.0.0/0":
            src = "::/0"
        else:
            raise SaltInvocationError("Destination is IPv6 but source is not IPv6.")

    client = get_client()

    rule = FirewallRule(
        action=action,
        direction=direction,
        protocol=proto,
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
    )
    # We want to delete the rule, not add it
    rule.delete = True

    try:
        rule.position = position

        if interface is not None:
            rule.set_interface(direction, interface)
        rule.validate()
    except ValueError as err:
        raise SaltInvocationError(f"Invalid rule parameters! {type(err).__name__}: {err}") from err

    try:
        ret = client.update_rule(rule)
        if isinstance(ret, dict):
            return ret["stdout"].strip()
        return ret
    except CommandExecutionError as err:
        log.error("Failed to remove UFW rule! %s: %s", type(err).__name__, err)
        return False


def add_route(
    action="allow",
    interface_in=None,
    interface_out=None,
    position=0,
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
    logtype=None,
    comment=None,
):
    """
    Insert or append a UFW route rule at a specific position.

    .. versionadded:: 0.8.0

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.add_route action=allow interface_in=eth0 interface_out=eth1 dport=2553

    action
        The action to take. Possible values: 'allow', 'deny', 'reject', 'limit'.

    interface_in
        The incoming network interface to apply the rule to. If not specified, the rule applies to all interfaces.

    interface_out
        The outgoing network interface to apply the rule to. If not specified, the rule applies to all interfaces.

    position
        The position of the rule.
        If set to 0 or not specified, the rule will be appended.
        If set to -1, the rule will be prepended.
        If set to a positive integer, the rule will be inserted at that position (1-based index).

    src
        The source IP address for the rule.

    sport
        The source port, port range or application name for the rule.

    dst
        The destination IP address for the rule.

    dport
        The destination port, port range or application name for the rule.

    proto
        The protocol for the rule (e.g., tcp, udp).
        If set to something different than "any", ``dport``, ``sport`` must also be set as port numbers.

    logtype
        Can be ``log`` or ``log-all``.
        If set to ``log``, will log all new connections matching the rule.
        If set to ``log-all``, enables logging for all matching packets.

    comment
        A comment to add to the rule.

    """

    _check_rule_params(action, None, dst, dport, src, sport, proto)

    client = get_client()

    if logtype not in (None, "log", "log-all"):
        raise SaltInvocationError("logtype must be either 'log', 'log-all', or None.")

    # Check if src and dst are both IPv4 or both IPv6. If one of them is IPv6 and the other is not, raise an error.
    # In case one of them is IPv6 and the other is the default, convert the default to the appropriate format for IPv6.
    if netutils.is_ipv6(src) and not netutils.is_ipv6(dst):
        if dst == "0.0.0.0/0":
            dst = "::/0"
        else:
            raise SaltInvocationError("Source is IPv6 but destination is not IPv6.")

    if netutils.is_ipv6(dst) and not netutils.is_ipv6(src):
        if src == "0.0.0.0/0":
            src = "::/0"
        else:
            raise SaltInvocationError("Destination is IPv6 but source is not IPv6.")

    rule = FirewallRule(
        action=action,
        forward=True,
        protocol=proto,
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        comment=comment,
    )

    try:
        if interface_in is not None:
            rule.set_interface("in", interface_in)
        if interface_out is not None:
            rule.set_interface("out", interface_out)
        rule.set_logtype(logtype)

        rule.position = position
        rule.validate()
    except ValueError as err:
        raise SaltInvocationError(f"Invalid rule parameters! {type(err).__name__}: {err}") from err

    try:
        ret = client.update_rule(rule)
        if isinstance(ret, dict):
            return ret["stdout"].strip()
        return ret
    except CommandExecutionError as err:
        log.error("Failed to add or update UFW route rule! %s: %s", type(err).__name__, err)
        return False


def remove_route(
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
    Remove a UFW route rule.

    .. versionadded:: 0.8.0

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.remove_route action=allow interface_in=eth0 interface_out=eth1 dport=2553

    action
        The action of the rule to remove. Possible values: 'allow', 'deny', 'reject', 'limit'.

    position
        The position of the rule to remove (1-based index). If specified, other parameters are ignored.

    interface_in
        The incoming network interface to apply the rule to. If not specified, the rule applies to all interfaces.

    interface_out
        The outgoing network interface to apply the rule to. If not specified, the rule applies to all interfaces.

    src
        The source IP address of the rule to remove.

    sport
        The source port, port range or application name for the rule to remove.

    dst
        The destination IP address of the rule to remove.

    dport
        The destination port, port range or application name for the rule to remove.

    proto
        The protocol of the rule to remove (e.g., tcp, udp, any).
        If set to something different than "any", ``dport`` or ``sport`` must also be set as port numbers.

    """
    _check_rule_params(action, None, dst, dport, src, sport, proto)

    # Check if src and dst are both IPv4 or both IPv6. If one of them is IPv6 and the other is not, raise an error.
    # In case one of them is IPv6 and the other is the default, convert the default to the appropriate format for IPv6.
    if netutils.is_ipv6(src) and not netutils.is_ipv6(dst):
        if dst == "0.0.0.0/0":
            dst = "::/0"
        else:
            raise SaltInvocationError("Source is IPv6 but destination is not IPv6.")

    if netutils.is_ipv6(dst) and not netutils.is_ipv6(src):
        if src == "0.0.0.0/0":
            src = "::/0"
        else:
            raise SaltInvocationError("Destination is IPv6 but source is not IPv6.")

    client = get_client()

    rule = FirewallRule(
        action=action,
        forward=True,
        protocol=proto,
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
    )
    # We want to delete the rule, not add it
    rule.delete = True

    try:
        if interface_in is not None:
            rule.set_interface("in", interface_in)
        if interface_out is not None:
            rule.set_interface("out", interface_out)

        rule.validate()
    except ValueError as err:
        raise SaltInvocationError(f"Invalid rule parameters! {type(err).__name__}: {err}") from err

    try:
        ret = client.update_rule(rule)
        if isinstance(ret, dict):
            return ret["stdout"].strip()
        return ret
    except CommandExecutionError as err:
        log.error("Failed to remove UFW route rule! %s: %s", type(err).__name__, err)
        return False


def logging_level(level):
    """
    Set UFW logging level.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.logging_level <level>

    level
        The logging level to set. Possible values: 'off', 'low', 'medium', 'high', 'full'.
    """
    client = get_client()

    if level is False:
        level = "off"

    if level not in ["off", "low", "medium", "high", "full"]:
        raise SaltInvocationError(
            f"Invalid logging level: {level}. Must be 'off', 'low', 'medium', 'high', or 'full'."
        )

    try:
        ret = client.set_logging_level(level=level)
        if isinstance(ret, dict):
            return ret["stdout"].strip()
        return ret
    except CommandExecutionError as err:
        log.error("Failed to set UFW logging level! %s: %s", type(err).__name__, err)
        return False


def list_rules():
    """
    List UFW rules as simple text output.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.list_rules
    """
    # client = get_client()
    result = list_current_rules()

    return result


def get_rules(index=None):
    """
    Get UFW rules as a list of dictionaries with all rule attributes.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.get_rules

    index
        If specified, returns only the rule at the given index (1-based).
    """

    result = get_firewall_rules()

    if index is not None:
        if not isinstance(index, int):
            raise SaltInvocationError("Rule index must be an integer.")

        if index < 1 or index > len(result):
            raise SaltInvocationError("Rule index out of range.")

        result = [rule for rule in result if index == rule["index"]]

    return result
