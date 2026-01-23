"""
Salt execution module
"""

import logging
import re

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError
from salt.utils.path import which

from saltext.ufw.utils.ufw.client import get_client
from saltext.ufw.utils.ufw.exceptions import UFWCommandError
from saltext.ufw.utils.ufw.network import is_port_number
from saltext.ufw.utils.ufw.rules import get_firewall_rules
from saltext.ufw.utils.ufw.rules import list_current_rules

log = logging.getLogger(__name__)

__virtualname__ = "ufw"


def _is_port_number(value):
    if value is None:
        return False
    return bool(PORT_VALUE_RE.fullmatch(str(value)))


def __virtual__():
    """
    Check to see if ufw cmd exists
    """
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
        result = client.execute("enable", force=True)
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
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
        result = client.execute("disable")
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
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
    cmd = "status"

    # If numbered is True, set raw to True to get the raw output
    if numbered:
        raw = True

    try:
        result = client.execute(cmd, extended="verbose" if not numbered else "numbered")
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
            out["logging"] = extract.group(1)

        return out

    except UFWCommandError as err:
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
        result = client.execute("reload")
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
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
        result = client.execute("default", policy=policy, direction=direction)
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        raise CommandExecutionError(
            f"Failed to set UFW default policy! {type(err).__name__}: {err}"
        ) from err


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
    except UFWCommandError as err:
        raise CommandExecutionError(
            f"Failed to get UFW version! {type(err).__name__}: {err}"
        ) from err


def reset():
    """
    Reset UFW to default state.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.reset
    """
    client = get_client()
    try:
        result = client.execute("reset", force=True)
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        raise CommandExecutionError(f"Failed to reset UFW! {type(err).__name__}: {err}") from err


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
            if not is_port_number(field_value):
                raise SaltInvocationError(
                    f"When specifying a protocol, {field_name} must be a port number."
                )


def add_rule(
    insert=None,
    action="allow",
    direction=None,
    interface=None,
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
    comment=None,
    dry_run=False,
):
    """
    Insert or append a UFW rule at a specific position.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.add_rule action=allow direction=in interface=eth0 dst=any dport=2553

    insert
        The position to insert the rule at (1-based index). If not specified, the rule will be appended.
    action
        The action to take. Possible values: 'allow', 'deny', 'reject', 'limit'.
    direction
        The direction of the rule. Possible values: 'in', 'out'.
    interface
        The network interface to apply the rule on.
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
    comment
        A comment to add to the rule.
    dry_run
        If True, the command will be simulated without making any changes.

    """
    if insert and insert < 1:
        raise SaltInvocationError("Rule insert position must be a positive integer.")

    _check_rule_params(action, direction, dst, dport, src, sport, proto)

    client = get_client()
    cmd = "rule"

    try:
        result = client.execute(
            cmd,
            dry_run=dry_run,
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
        )
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        raise CommandExecutionError(f"Failed to add UFW rule! {type(err).__name__}: {err}") from err


def remove_rule(
    action="allow",
    position=None,
    direction=None,
    interface=None,
    dst="0.0.0.0/0",
    dport=None,
    src="0.0.0.0/0",
    sport=None,
    proto="any",
    dry_run=False,
):
    """
    Remove a UFW rule.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.remove_rule action=allow direction=in interface=eth0 dst=any dport=2553

    action
        The action of the rule to remove. Possible values: 'allow', 'deny', 'reject', 'limit'.
    position
        The position of the rule to remove (1-based index). If specified, other parameters are ignored.
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

    dry_run
        If True, the command will be simulated without making any changes.
    """

    _check_rule_params(action, direction, dst, dport, src, sport, proto)

    client = get_client()

    cmd = "rule"

    try:
        if position:
            cmd = "delete"
            result = client.execute(
                cmd,
                dry_run=dry_run,
                position=position,
            )
        else:
            result = client.execute(
                cmd,
                method="delete",
                dry_run=dry_run,
                action=action,
                direction=direction,
                interface=interface,
                src=src,
                sport=sport,
                dst=dst,
                dport=dport,
                proto=proto,
            )

        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        raise CommandExecutionError(
            f"Failed to remove UFW rule! {type(err).__name__}: {err}"
        ) from err


def add_route(
    insert=None,
    action="allow",
    interface_in=None,
    interface_out=None,
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
    comment=None,
    rule_log=False,
    dry_run=False,
):
    """
    Insert or append a UFW route rule at a specific position.

    .. versionadded:: 0.8.0

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.add_route action=allow interface_in=eth0 interface_out=eth1 dport=2553

    insert
        The position to insert the rule at (1-based index). If not specified, the rule will be appended.

    action
        The action to take. Possible values: 'allow', 'deny', 'reject', 'limit'.

    interface_in
        The incoming network interface to apply the rule to. If not specified, the rule applies to all interfaces.

    interface_out
        The outgoing network interface to apply the rule to. If not specified, the rule applies to all interfaces.

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

    comment
        A comment to add to the rule.

    rule_log
        Can be ``true``, ``false`` or ``all``.
        If set to ``true``, will log all new connections matching the rule.
        If set to ``all``, enables logging for all matching packets.

    dry_run
        If True, the command will be simulated without making any changes.
    """

    if insert and insert < 1:
        raise SaltInvocationError("Rule insert position must be a positive integer.")

    _check_rule_params(action, None, dst, dport, src, sport, proto)

    client = get_client()
    cmd = "route"
    rule_log = "log-all" if rule_log == "all" else ("log" if rule_log else None)
    try:
        result = client.execute(
            cmd,
            dry_run=dry_run,
            insert=insert,
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
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        raise CommandExecutionError(
            f"Failed to add UFW route rule! {type(err).__name__}: {err}"
        ) from err


def remove_route(
    action="allow",
    interface_in=None,
    interface_out=None,
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
    dry_run=False,
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

    dry_run
        If True, the command will be simulated without making any changes.
    """
    _check_rule_params(action, None, dst, dport, src, sport, proto)

    client = get_client()

    cmd = "route"

    try:
        result = client.execute(
            cmd,
            method="delete",
            dry_run=dry_run,
            action=action,
            interface_in=interface_in,
            interface_out=interface_out,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            proto=proto,
        )

        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        raise CommandExecutionError(
            f"Failed to remove UFW route rule! {type(err).__name__}: {err}"
        ) from err


def add_route(
    insert=None,
    action="allow",
    src_interface=None,
    dst_interface=None,
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
    comment=None,
    rule_log=False,
    dry_run=False,
):
    """
    Insert or append a UFW route rule at a specific position.

    .. versionadded:: 0.8.0

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.add_route action=allow src_interface=eth0 dst_interface=eth1 dport=2553

    insert
        The position to insert the rule at (1-based index). If not specified, the rule will be appended.

    action
        The action to take. Possible values: 'allow', 'deny', 'reject', 'limit'.

    in_interface
        The network interface to apply the rule on for incoming traffic.

    out_interface
        The network interface to apply the rule on for outgoing traffic.

    src
        The source IP address for the rule.

    sport
        The source port or application name for the rule.

    dst
        The destination IP address for the rule.

    dport
        The destination port or application name for the rule.

    proto
        The protocol for the rule (e.g., tcp, udp).
        If set to something different than "any", ``dport``, ``sport`` must also be set as port numbers.

    comment
        A comment to add to the rule.

    rule_log
        Can be ``true``, ``false`` or ``all``.
        If set to ``true``, will log all new connections matching the rule.
        If set to ``all``, enables logging for all matching packets.

    dry_run
        If True, the command will be simulated without making any changes.
    """

    if insert and insert < 1:
        raise SaltInvocationError("Rule insert position must be a positive integer.")

    _check_rule_params(action, None, dst, dport, src, sport, proto)

    client = get_client()
    cmd = "route"
    rule_log = "log-all" if rule_log == "all" else ("log" if rule_log else None)
    try:
        result = client.execute(
            cmd,
            dry_run=dry_run,
            insert=insert,
            action=action,
            src_interface=src_interface,
            dst_interface=dst_interface,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            proto=proto,
            logging=rule_log,
            comment=comment,
        )
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        log.error("Failed to add UFW route! %s: %s", type(err).__name__, err)
        return False


def remove_route(
    action="allow",
    src_interface=None,
    dst_interface=None,
    src="0.0.0.0/0",
    sport=None,
    dst="0.0.0.0/0",
    dport=None,
    proto="any",
    dry_run=False,
):
    """
    Remove a UFW route rule.

    .. versionadded:: 0.8.0

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.remove_route action=allow src_interface=eth0 dst_interface=eth1 dport=2553

    action
        The action of the rule to remove. Possible values: 'allow', 'deny', 'reject', 'limit'.

    position
        The position of the rule to remove (1-based index). If specified, other parameters are ignored.

    src_interface
        The source network interface of the rule to remove.

    dst_interface
        The destination network interface of the rule to remove.

    src
        The source IP address of the rule to remove.

    sport
        The source port or application name for the rule to remove.

    dst
        The destination IP address of the rule to remove.

    dport
        The destination port or application name for the rule to remove.

    proto
        The protocol of the rule to remove (e.g., tcp, udp, any).
        If set to something different than "any", ``dport`` or ``sport`` must also be set as port numbers.

    dry_run
        If True, the command will be simulated without making any changes.
    """
    _check_rule_params(action, None, dst, dport, src, sport, proto)

    client = get_client()

    cmd = "route"

    try:
        result = client.execute(
            cmd,
            method="delete",
            dry_run=dry_run,
            action=action,
            src_interface=src_interface,
            dst_interface=dst_interface,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            proto=proto,
        )

        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        log.error("Failed to remove UFW route! %s: %s", type(err).__name__, err)
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
        result = client.execute("logging", level=level)
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        raise CommandExecutionError(
            f"Failed to set UFW logging level! {type(err).__name__}: {err}"
        ) from err


def list_rules():
    """
    List UFW rules as simple text output.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.list_rules
    """
    # client = get_client()
    try:
        result = list_current_rules()

        return result
    except UFWCommandError as err:
        raise CommandExecutionError(
            f"Failed to list UFW rules! {type(err).__name__}: {err}"
        ) from err


def get_rules(index=None):
    """
    Get UFW rules as a list of dictionaries with all rule attributes.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.get_rules

    index
        If specified, returns only the rule at the given index (1-based).
    """

    try:
        result = get_firewall_rules()

        if index is not None:
            if not isinstance(index, int):
                raise SaltInvocationError("Rule index must be an integer.")

            if index < 1 or index > len(result):
                raise SaltInvocationError("Rule index out of range.")

            result = [rule for rule in result if index == rule["index"]]

        return result
    except UFWCommandError as err:
        raise CommandExecutionError(
            f"Failed to get UFW rules! {type(err).__name__}: {err}"
        ) from err
