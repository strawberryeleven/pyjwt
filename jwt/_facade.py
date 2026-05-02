from __future__ import annotations

from typing import Any

from .algorithms import Algorithm
from .api_jws import PyJWS
from .api_jwt import PyJWT


class JWTFacade:
    """Single object-oriented entry point that owns both layers of the library.

    Holds a :class:`PyJWS` (signature layer) and a :class:`PyJWT` (claim layer)
    instance, wired together explicitly in this constructor. Replaces the
    previous arrangement in which ``api_jws.py`` and ``api_jwt.py`` each held
    their own private module-level singleton and the latter monkey-patched
    its ``_jws`` attribute to share the former; with ``JWTFacade`` the wiring
    is visible from the class definition.

    The module-level convenience functions ``jwt.encode``, ``jwt.decode``,
    ``jwt.decode_complete``, ``jwt.register_algorithm`` etc. continue to work
    unchanged. ``JWTFacade`` is the recommended entry point for callers who
    prefer an object-oriented API or who need an isolated configuration.
    """

    def __init__(
        self,
        jws: PyJWS | None = None,
        jwt: PyJWT | None = None,
    ) -> None:
        self.jws = jws if jws is not None else PyJWS()
        self.jwt = jwt if jwt is not None else PyJWT(jws=self.jws)

    # --- claim-aware operations (JWT layer) ----------------------------------

    def encode(self, *args: Any, **kwargs: Any) -> str:
        return self.jwt.encode(*args, **kwargs)

    def decode(self, *args: Any, **kwargs: Any) -> Any:
        return self.jwt.decode(*args, **kwargs)

    def decode_complete(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.jwt.decode_complete(*args, **kwargs)

    # --- signature-only operations (JWS layer) -------------------------------

    def register_algorithm(self, alg_id: str, alg_obj: Algorithm) -> None:
        self.jws.register_algorithm(alg_id, alg_obj)

    def unregister_algorithm(self, alg_id: str) -> None:
        self.jws.unregister_algorithm(alg_id)

    def get_algorithm_by_name(self, alg_name: str) -> Algorithm:
        return self.jws.get_algorithm_by_name(alg_name)

    def get_unverified_header(self, jwt: str | bytes) -> dict[str, Any]:
        return self.jws.get_unverified_header(jwt)
