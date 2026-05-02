from __future__ import annotations

import warnings
from typing import Any

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
