from fastapi import FastAPI
from fastapi_injected import add_injection

__all__ = [
    "add_authn",
]


def add_authn(app: FastAPI) -> None:
    add_injection(app)
