import salt.exceptions


class UFWError(salt.exceptions.SaltException):
    """
    Base class for exceptions raised by this module.
    """


class UFWCommandError(UFWError):
    """
    Exception raised when a UFW command fails.
    """

    def __init__(self, command, output):
        self.command = command
        self.output = output
        message = f"UFW command '{command}' failed with return code {output['retcode']}: {output['stderr']}"
        super().__init__(message)
