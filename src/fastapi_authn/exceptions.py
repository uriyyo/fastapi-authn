__all__ = [
    "MissingExtra",
    "UserError",
]


class UserError(RuntimeError):
    """A misconfiguration the developer has to fix; the message names the fix."""


class MissingExtra(UserError, ImportError):
    """An optional dependency is not installed; the message names the extra that brings it."""

    def __init__(self, extra: str, feature: str) -> None:
        super().__init__(f"{feature} needs the `{extra}` extra: pip install 'fastapi-authn[{extra}]'")
        self.extra = extra
