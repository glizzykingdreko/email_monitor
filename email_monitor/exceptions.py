
class EmailMonitorException(Exception):
    """Base class for EmailMonitor exceptions."""
    pass

class EmailMonitorConnectionError(EmailMonitorException):
    """Raised when there's an error while connecting to the mailbox."""
    pass

class CredentialFileInvalidError(EmailMonitorException):
    """Raised when the credentials file is invalid."""
    pass

class CredentialFileRequiredError(EmailMonitorException):
    """Raised when the credentials file is required."""
    pass

class InvalidCredentialsError(EmailMonitorException):
    """Raised when the credentials are invalid."""
    pass
