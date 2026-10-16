__all__ = [
    "UserError",
]


class UserError(RuntimeError):
    """A misconfiguration the developer has to fix; the message names the fix."""
