"""
Salt execution module
"""

import logging
import re

from salt.exceptions import SaltInvocationError
from salt.utils.path import which

from saltext.ufw.utils.ufw.client import get_client
from saltext.ufw.utils.ufw.exceptions import UFWCommandError

log = logging.getLogger(__name__)

__virtualname__ = "ufw"


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
    except UFWCommandError as err:
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
        result = client.execute("reset", force=True)
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        log.error("Failed to reset UFW! %s: %s", type(err).__name__, err)
        return False


def _check_rule_params(action, direction, to_ip, to_port, from_ip, from_port, app, proto):

    if action not in ["allow", "deny", "reject", "limit"]:
        raise SaltInvocationError("Invalid action. Must be 'allow', 'deny', 'reject', or 'limit'.")

    if direction and direction not in ["in", "out"]:
        raise SaltInvocationError("Invalid direction. Must be 'in' or 'out'.")

    if app and (to_port or from_port):
        raise SaltInvocationError("Cannot specify both application profile and ports.")

    if app and not (to_ip or from_ip):
        raise SaltInvocationError(
            "When specifying an application profile, at least one of to_ip or from_ip must be set."
        )

    if proto and not (to_port or from_port):
        raise SaltInvocationError(
            "When specifying a protocol, at least one of to_port or from_port must be set."
        )


def add_rule(
    insert=None,
    action="allow",
    direction=None,
    interface=None,
    from_ip=None,
    from_port=None,
    to_ip=None,
    to_port=None,
    proto=None,
    app=None,
    comment=None,
    dry_run=False,
):
    """
    Insert or append a UFW rule at a specific position.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.add_rule action=allow direction=in interface=eth0 to_ip=any to_port=2553

    insert
        The position to insert the rule at (1-based index). If not specified, the rule will be appended.
    action
        The action to take. Possible values: 'allow', 'deny', 'reject', 'limit'.
    direction
        The direction of the rule. Possible values: 'in', 'out'.
    interface
        The network interface to apply the rule on.
    from_ip
        The source IP address for the rule.
        Defaults to 0.0.0.0/0 if ``from_port`` or ``to_port`` is set.
    from_port
        The source port for the rule.
    to_ip
        The destination IP address for the rule.
        Defaults to 0.0.0.0/0 if ``from_port`` or ``to_port`` is set.
    to_port
        The destination port for the rule.
    proto
        The protocol for the rule (e.g., tcp, udp).
        If set any of ``to_port``, ``from_port``, ``to_ip``, ``from_ip`` must also be set.
    app
        The application profile for the rule. Can be used instead of specifying ports.
    comment
        A comment to add to the rule.
    dry_run
        If True, the command will be simulated without making any changes.

    """
    if insert and insert < 1:
        raise SaltInvocationError("Rule insert position must be a positive integer.")

    _check_rule_params(action, direction, to_ip, to_port, from_ip, from_port, app, proto)

    if (from_port or to_port) and not from_ip:
        from_ip = "0.0.0.0/0"

    if (from_port or to_port) and not to_ip:
        to_ip = "0.0.0.0/0"

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
            from_ip=from_ip,
            from_port=from_port,
            to_ip=to_ip,
            to_port=to_port,
            proto=proto,
            app=app,
            comment=comment,
        )
        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        log.error("Failed to add UFW rule! %s: %s", type(err).__name__, err)
        return False


def remove_rule(
    action="allow",
    position=None,
    direction=None,
    interface=None,
    from_ip=None,
    from_port=None,
    to_ip=None,
    to_port=None,
    proto=None,
    app=None,
    dry_run=False,
):
    """
    Remove a UFW rule.

    CLI Example:

    .. code-block:: bash

        salt '*' ufw.remove_rule action=allow direction=in interface=eth0 to_ip=any to_port=2553

    action
        The action of the rule to remove. Possible values: 'allow', 'deny', 'reject', 'limit'.
    position
        The position of the rule to remove (1-based index). If specified, other parameters are ignored.
    direction
        The direction of the rule to remove. Possible values: 'in', 'out'.
    interface
        The network interface of the rule to remove.
    from_ip
        The source IP address of the rule to remove.
        Defaults to 0.0.0.0/0 if ``from_port`` or ``to_port`` is set.
    from_port
        The source port of the rule to remove.
    to_ip
        The destination IP address of the rule to remove.
        Defaults to 0.0.0.0/0 if ``from_port`` or ``to_port`` is set.
    to_port
        The destination port of the rule to remove.
    proto
        The protocol of the rule to remove (e.g., tcp, udp).
        If set ``to_port`` or ``from_port`` must also be set.
    app
        The application profile of the rule to remove. Can be used instead of specifying ports.
    dry_run
        If True, the command will be simulated without making any changes.
    """

    _check_rule_params(action, direction, to_ip, to_port, from_ip, from_port, app, proto)

    if (from_port or to_port) and not from_ip:
        from_ip = "0.0.0.0/0"

    if (from_port or to_port) and not to_ip:
        to_ip = "0.0.0.0/0"

    client = get_client()

    cmd = "delete"

    try:
        if position:
            result = client.execute(
                cmd,
                dry_run=dry_run,
                position=position,
            )
        else:
            result = client.execute(
                cmd,
                dry_run=dry_run,
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

        if isinstance(result, dict):
            return result["stdout"].strip()
        return result
    except UFWCommandError as err:
        log.error("Failed to remove UFW rule! %s: %s", type(err).__name__, err)
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
        log.error("Failed to set UFW logging level! %s: %s", type(err).__name__, err)
        return False
