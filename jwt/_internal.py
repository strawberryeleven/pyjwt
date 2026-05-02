from __future__ import annotations

import warnings
from collections.abc import Container, Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Union

from .warnings import RemovedInPyjwt3Warning


def warn_deprecated_kwargs(function_name: str, kwargs: dict[str, Any]) -> None:
    """Emit a deprecation warning for unsupported keyword arguments.

    Centralises the kwargs-deprecation message previously duplicated across
    ``PyJWS.encode``, ``PyJWS.decode``, ``PyJWS.decode_complete``,
    ``PyJWT.decode`` and ``PyJWT.decode_complete``.
    """
    if not kwargs:
        return
    warnings.warn(
        f"passing additional kwargs to {function_name}() is deprecated "
        "and will be removed in pyjwt version 3. "
        f"Unsupported kwargs: {tuple(kwargs.keys())}",
        RemovedInPyjwt3Warning,
        stacklevel=3,
    )


@dataclass(frozen=True)
class DecodedToken:
    """Immutable result of parsing a JWS into its four constituent pieces.

    Replaces the four-tuple ``(payload, signing_input, header, signature)``
    that used to be returned from ``PyJWS._load``.
    """

    payload: bytes
    signing_input: bytes
    header: dict[str, Any]
    signature: bytes


@dataclass(frozen=True)
class ClaimContext:
    """Bundle of optional claim-validation parameters.

    Replaces the loose ``audience`` / ``issuer`` / ``subject`` / ``leeway``
    parameter group that used to be threaded through ``PyJWT.decode``,
    ``PyJWT.decode_complete`` and ``PyJWT._validate_claims``.
    """

    audience: Union[str, Iterable[str], None] = None
    issuer: Union[Container[str], str, None] = None
    subject: Union[str, None] = None
    leeway: Union[float, timedelta] = 0
