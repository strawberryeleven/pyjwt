"""Abstract :class:`Algorithm` base class plus the shared :func:`_parse_jwk` helper."""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar, Literal, NoReturn, overload

from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ._crypto import AllowedKeys, has_crypto

if has_crypto:
    from ._crypto import default_backend, hashes

if TYPE_CHECKING:
    from ._crypto import PrivateKeyTypes, PublicKeyTypes


def _parse_jwk(jwk: str | JWKDict) -> JWKDict:
    """Parse a JWK input that may be a JSON string or already a dict.

    Centralises the str/dict/JSON-loads handling shared by every concrete
    ``Algorithm.from_jwk`` implementation.
    """
    try:
        if isinstance(jwk, str):
            return json.loads(jwk)
        if isinstance(jwk, dict):
            return jwk
        raise ValueError
    except ValueError:
        raise InvalidKeyError("Key is not valid JSON") from None


class Algorithm(ABC):
    """The interface for an algorithm used to sign and verify tokens."""

    # pyjwt-964: Validate to ensure the key passed in was decoded to the correct cryptography key family
    _crypto_key_types: tuple[type[AllowedKeys], ...] | None = None

    def compute_hash_digest(self, bytestr: bytes) -> bytes:
        """Compute a hash digest using the specified algorithm's hash algorithm.

        If there is no hash algorithm, raises a NotImplementedError.
        """
        # lookup self.hash_alg if defined in a way that mypy can understand
        hash_alg = getattr(self, "hash_alg", None)
        if hash_alg is None:
            raise NotImplementedError

        if (
            has_crypto
            and isinstance(hash_alg, type)
            and issubclass(hash_alg, hashes.HashAlgorithm)
        ):
            digest = hashes.Hash(hash_alg(), backend=default_backend())
            digest.update(bytestr)
            return bytes(digest.finalize())
        return bytes(hash_alg(bytestr).digest())

    def check_crypto_key_type(self, key: PublicKeyTypes | PrivateKeyTypes) -> None:
        """Check that the key belongs to the right cryptographic family.

        Note that this method only works when ``cryptography`` is installed.

        :param key: Potentially a cryptography key
        :raises ValueError: if ``cryptography`` is not installed, or this method is called by a non-cryptography algorithm
        :raises InvalidKeyError: if the key doesn't match the expected key classes
        """
        if not has_crypto or self._crypto_key_types is None:
            raise ValueError(
                "This method requires the cryptography library, and should only be used by cryptography-based algorithms."
            )

        if not isinstance(key, self._crypto_key_types):
            valid_classes = (cls.__name__ for cls in self._crypto_key_types)
            actual_class = key.__class__.__name__
            self_class = self.__class__.__name__
            raise InvalidKeyError(
                f"Expected one of {valid_classes}, got: {actual_class}. Invalid Key type for {self_class}"
            )

    @abstractmethod
    def prepare_key(self, key: Any) -> Any:
        """Performs necessary validation and conversions on the key and returns
        the key value in the proper format for sign() and verify().
        """

    def sign(self, msg: bytes, key: Any) -> bytes:
        """Template Method: prepare input -> compute signature -> finalise output.

        Subclasses normally only override :meth:`_compute_signature`. The
        ``_prepare_input`` and ``_finalise_signature`` hooks default to
        pass-through; only algorithms whose signature representation differs
        from the cryptography library's native form (such as ECDSA's
        DER -> raw R||S conversion) need to override them.
        """
        prepared = self._prepare_input(msg, key)
        raw = self._compute_signature(prepared, key)
        return self._finalise_signature(raw, key)

    def _prepare_input(self, msg: bytes, key: Any) -> bytes:
        """Hook called before :meth:`_compute_signature`. Default: pass-through."""
        return msg

    @abstractmethod
    def _compute_signature(self, msg: bytes, key: Any) -> bytes:
        """Algorithm-specific signature computation."""

    def _finalise_signature(self, sig: bytes, key: Any) -> bytes:
        """Hook called after :meth:`_compute_signature`. Default: pass-through."""
        return sig

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        """Template Method: call :meth:`_do_verify`; treat the exceptions in
        :attr:`_verify_failure_exceptions` as "invalid signature" -> ``False``.

        Other exceptions propagate.
        """
        try:
            return self._do_verify(msg, key, sig)
        except self._verify_failure_exceptions:
            return False

    _verify_failure_exceptions: ClassVar[tuple[type[Exception], ...]] = ()

    @abstractmethod
    def _do_verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        """Algorithm-specific verification.

        Return ``True`` for a valid signature; either return ``False`` or
        raise one of the algorithm's :attr:`_verify_failure_exceptions` for
        an invalid one.
        """

    @overload
    @staticmethod
    @abstractmethod
    def to_jwk(key_obj: Any, as_dict: Literal[True]) -> JWKDict: ...  # pragma: no cover

    @overload
    @staticmethod
    @abstractmethod
    def to_jwk(
        key_obj: Any, as_dict: Literal[False] = False
    ) -> str: ...  # pragma: no cover

    @staticmethod
    @abstractmethod
    def to_jwk(key_obj: Any, as_dict: bool = False) -> JWKDict | str:
        """Serializes a given key into a JWK."""

    @staticmethod
    @abstractmethod
    def from_jwk(jwk: str | JWKDict) -> Any:
        """Deserializes a given key from JWK back into a key object."""

    def check_key_length(self, key: Any) -> str | None:
        """Return a warning message if the key is below the minimum
        recommended length for this algorithm, or None if adequate.
        """
        return None
