from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any

from .algorithms import get_default_algorithms, has_crypto, requires_cryptography
from .exceptions import (
    InvalidKeyError,
    MissingCryptographyError,
    PyJWKError,
    PyJWKSetError,
    PyJWTError,
)
from .types import JWKDict


class KeyTypeResolver(ABC):
    """Strategy for deriving an algorithm name from a JWK's parameters.

    Replaces the in-place ``if kty == ...`` switch that previously lived in
    :class:`PyJWK`'s constructor. One concrete subclass exists per supported
    key type (``EC``, ``RSA``, ``oct``, ``OKP``); the registry below maps a
    ``kty`` value to its resolver instance.
    """

    @abstractmethod
    def resolve(self, jwk_data: JWKDict) -> str:
        """Return the algorithm name for the given JWK, or raise InvalidKeyError."""


class _ECKeyTypeResolver(KeyTypeResolver):
    _CURVE_TO_ALG = {
        "P-256": "ES256",
        "P-384": "ES384",
        "P-521": "ES512",
        "secp256k1": "ES256K",
    }

    def resolve(self, jwk_data: JWKDict) -> str:
        crv = jwk_data.get("crv", None)
        if not crv:
            return "ES256"
        try:
            return self._CURVE_TO_ALG[crv]
        except KeyError:
            raise InvalidKeyError(f"Unsupported crv: {crv}") from None


class _RSAKeyTypeResolver(KeyTypeResolver):
    def resolve(self, jwk_data: JWKDict) -> str:
        return "RS256"


class _OctKeyTypeResolver(KeyTypeResolver):
    def resolve(self, jwk_data: JWKDict) -> str:
        return "HS256"


class _OKPKeyTypeResolver(KeyTypeResolver):
    _CURVE_TO_ALG = {
        "Ed25519": "EdDSA",
    }

    def resolve(self, jwk_data: JWKDict) -> str:
        crv = jwk_data.get("crv", None)
        if not crv:
            raise InvalidKeyError(f"crv is not found: {jwk_data}")
        try:
            return self._CURVE_TO_ALG[crv]
        except KeyError:
            raise InvalidKeyError(f"Unsupported crv: {crv}") from None


_KEY_TYPE_RESOLVERS: dict[str, KeyTypeResolver] = {
    "EC": _ECKeyTypeResolver(),
    "RSA": _RSAKeyTypeResolver(),
    "oct": _OctKeyTypeResolver(),
    "OKP": _OKPKeyTypeResolver(),
}


class PyJWK:
    def __init__(self, jwk_data: JWKDict, algorithm: str | None = None) -> None:
        """A class that represents a `JSON Web Key <https://www.rfc-editor.org/rfc/rfc7517>`_.

        :param jwk_data: The decoded JWK data.
        :type jwk_data: dict[str, typing.Any]
        :param algorithm: The key algorithm. If not specified, the key's ``alg`` will be used.
        :type algorithm: str or None
        :raises InvalidKeyError: If the key type (``kty``) is not found or unsupported, or if the curve (``crv``) is not found or unsupported.
        :raises MissingCryptographyError: If the algorithm requires ``cryptography`` to be installed and it is not available.
        :raises PyJWKError: If unable to find an algorithm for the key.
        """
        self._jwk_data = jwk_data

        kty = self._jwk_data.get("kty", None)
        if not kty:
            raise InvalidKeyError(f"kty is not found: {self._jwk_data}")

        if not algorithm and isinstance(self._jwk_data, dict):
            algorithm = self._jwk_data.get("alg", None)

        if not algorithm:
            resolver = _KEY_TYPE_RESOLVERS.get(kty)
            if resolver is None:
                raise InvalidKeyError(f"Unsupported kty: {kty}")
            algorithm = resolver.resolve(self._jwk_data)

        if not has_crypto and algorithm in requires_cryptography:
            raise MissingCryptographyError(
                f"{algorithm} requires 'cryptography' to be installed."
            )

        self.algorithm_name = algorithm

        try:
            self.Algorithm = get_default_algorithms()[algorithm]
        except KeyError:
            raise PyJWKError(
                f"Unable to find an algorithm for key: {self._jwk_data}",
            ) from None

        self.key = self.Algorithm.from_jwk(self._jwk_data)

    @staticmethod
    def from_dict(obj: JWKDict, algorithm: str | None = None) -> PyJWK:
        """Creates a :class:`PyJWK` object from a JSON-like dictionary.

        :param obj: The JWK data, as a dictionary
        :type obj: dict[str, typing.Any]
        :param algorithm: The key algorithm. If not specified, the key's ``alg`` will be used.
        :type algorithm: str or None
        :rtype: PyJWK
        """
        return PyJWK(obj, algorithm)

    @staticmethod
    def from_json(data: str, algorithm: None = None) -> PyJWK:
        """Create a :class:`PyJWK` object from a JSON string.
        Implicitly calls :meth:`PyJWK.from_dict()`.

        :param str data: The JWK data, as a JSON string.
        :param algorithm:  The key algorithm.  If not specific, the key's ``alg`` will be used.
        :type algorithm: str or None

        :rtype: PyJWK
        """
        obj = json.loads(data)
        return PyJWK.from_dict(obj, algorithm)

    @property
    def key_type(self) -> str | None:
        """The `kty` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("kty", None)

    @property
    def key_id(self) -> str | None:
        """The `kid` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("kid", None)

    @property
    def public_key_use(self) -> str | None:
        """The `use` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("use", None)


class PyJWKSet:
    def __init__(self, keys: list[JWKDict]) -> None:
        self.keys: list[PyJWK] = []

        if not keys:
            raise PyJWKSetError("The JWK Set did not contain any keys")

        if not isinstance(keys, list):
            raise PyJWKSetError("Invalid JWK Set value")

        for key in keys:
            try:
                self.keys.append(PyJWK(key))
            except PyJWTError as error:
                if isinstance(error, MissingCryptographyError):
                    raise error
                # skip unusable keys
                continue

        if len(self.keys) == 0:
            raise PyJWKSetError(
                "The JWK Set did not contain any usable keys. Perhaps 'cryptography' is not installed?"
            )

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> PyJWKSet:
        keys = obj.get("keys", [])
        return PyJWKSet(keys)

    @staticmethod
    def from_json(data: str) -> PyJWKSet:
        obj = json.loads(data)
        return PyJWKSet.from_dict(obj)

    def __getitem__(self, kid: str) -> PyJWK:
        for key in self.keys:
            if key.key_id == kid:
                return key
        raise KeyError(f"keyset has no key for kid: {kid}")

    def __iter__(self) -> Iterator[PyJWK]:
        return iter(self.keys)
