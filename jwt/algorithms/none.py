"""The ``none`` algorithm — placeholder for unsigned tokens."""
from __future__ import annotations

from typing import Any, NoReturn

from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ._base import Algorithm


class NoneAlgorithm(Algorithm):
    """Placeholder for use when no signing or verification operations are required."""

    def prepare_key(self, key: str | None) -> None:
        if key == "":
            key = None

        if key is not None:
            raise InvalidKeyError('When alg = "none", key value must be None.')

        return key

    def _compute_signature(self, msg: bytes, key: None) -> bytes:
        return b""

    def _do_verify(self, msg: bytes, key: None, sig: bytes) -> bool:
        return False

    @staticmethod
    def to_jwk(key_obj: Any, as_dict: bool = False) -> NoReturn:
        raise NotImplementedError()

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> NoReturn:
        raise NotImplementedError()
