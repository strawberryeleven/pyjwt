"""Octet-Key-Pair algorithm (EdDSA) for Ed25519 / Ed448 keys."""
from __future__ import annotations

import json
from typing import (
    TYPE_CHECKING,
    Any,
    Literal,
    Union,
    cast,
    get_args,
    overload,
)

from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ..utils import base64url_decode, base64url_encode, force_bytes
from ._base import Algorithm, _parse_jwk
from ._crypto import has_crypto

if has_crypto:
    from ._crypto import (
        AllowedKeys,
        AllowedOKPKeys,
        Ed448PrivateKey,
        Ed448PublicKey,
        Ed25519PrivateKey,
        Ed25519PublicKey,
        Encoding,
        InvalidSignature,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
        load_pem_public_key,
        load_ssh_public_key,
    )

    if TYPE_CHECKING:
        from ._crypto import PrivateKeyTypes, PublicKeyTypes

    class OKPAlgorithm(Algorithm):
        """Performs signing and verification operations using EdDSA.

        Requires ``cryptography>=2.6`` to be installed.
        """

        _crypto_key_types = cast(
            tuple[type[AllowedKeys], ...],
            get_args(
                Union[
                    Ed25519PrivateKey,
                    Ed25519PublicKey,
                    Ed448PrivateKey,
                    Ed448PublicKey,
                ]
            ),
        )

        def __init__(self, **kwargs: Any) -> None:
            pass

        def prepare_key(self, key: AllowedOKPKeys | str | bytes) -> AllowedOKPKeys:
            if not isinstance(key, (str, bytes)):
                self.check_crypto_key_type(key)
                return key

            key_str = key.decode("utf-8") if isinstance(key, bytes) else key
            key_bytes = key.encode("utf-8") if isinstance(key, str) else key

            loaded_key: PublicKeyTypes | PrivateKeyTypes
            if "-----BEGIN PUBLIC" in key_str:
                loaded_key = load_pem_public_key(key_bytes)
            elif "-----BEGIN PRIVATE" in key_str:
                loaded_key = load_pem_private_key(key_bytes, password=None)
            elif key_str[0:4] == "ssh-":
                loaded_key = load_ssh_public_key(key_bytes)
            else:
                raise InvalidKeyError("Not a public or private key")

            # Explicit check the key to prevent confusing errors from cryptography
            self.check_crypto_key_type(loaded_key)
            return cast("AllowedOKPKeys", loaded_key)

        _verify_failure_exceptions = (InvalidSignature,)

        def _compute_signature(
            self, msg: bytes, key: Ed25519PrivateKey | Ed448PrivateKey
        ) -> bytes:
            """Sign a message using an EdDSA private key."""
            msg_bytes = msg.encode("utf-8") if isinstance(msg, str) else msg
            signature: bytes = key.sign(msg_bytes)
            return signature

        def _do_verify(
            self, msg: bytes, key: AllowedOKPKeys, sig: bytes
        ) -> bool:
            """Verify an EdDSA signature; raise :class:`InvalidSignature` on failure."""
            msg_bytes = msg.encode("utf-8") if isinstance(msg, str) else msg
            sig_bytes = sig.encode("utf-8") if isinstance(sig, str) else sig

            public_key = (
                key.public_key()
                if isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey))
                else key
            )
            public_key.verify(sig_bytes, msg_bytes)
            return True

        @overload
        @staticmethod
        def to_jwk(key: AllowedOKPKeys, as_dict: Literal[True]) -> JWKDict: ...

        @overload
        @staticmethod
        def to_jwk(key: AllowedOKPKeys, as_dict: Literal[False] = False) -> str: ...

        @staticmethod
        def to_jwk(key: AllowedOKPKeys, as_dict: bool = False) -> JWKDict | str:
            if isinstance(key, (Ed25519PublicKey, Ed448PublicKey)):
                x = key.public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw,
                )
                crv = "Ed25519" if isinstance(key, Ed25519PublicKey) else "Ed448"

                obj = {
                    "x": base64url_encode(force_bytes(x)).decode(),
                    "kty": "OKP",
                    "crv": crv,
                }

                if as_dict:
                    return obj
                return json.dumps(obj)

            if isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey)):
                d = key.private_bytes(
                    encoding=Encoding.Raw,
                    format=PrivateFormat.Raw,
                    encryption_algorithm=NoEncryption(),
                )

                x = key.public_key().public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw,
                )

                crv = "Ed25519" if isinstance(key, Ed25519PrivateKey) else "Ed448"
                obj = {
                    "x": base64url_encode(force_bytes(x)).decode(),
                    "d": base64url_encode(force_bytes(d)).decode(),
                    "kty": "OKP",
                    "crv": crv,
                }

                if as_dict:
                    return obj
                return json.dumps(obj)

            raise InvalidKeyError("Not a public or private key")

        @staticmethod
        def from_jwk(jwk: str | JWKDict) -> AllowedOKPKeys:
            obj = _parse_jwk(jwk)

            if obj.get("kty") != "OKP":
                raise InvalidKeyError("Not an Octet Key Pair")

            curve = obj.get("crv")
            if curve not in ("Ed25519", "Ed448"):
                raise InvalidKeyError(f"Invalid curve: {curve}")

            if "x" not in obj:
                raise InvalidKeyError('OKP should have "x" parameter')

            return OKPAlgorithm._okp_build_key(obj, curve)

        @staticmethod
        def _okp_build_key(obj: JWKDict, curve: str) -> AllowedOKPKeys:
            """Build the public or private OKP key from the JWK ``x`` (and optional ``d``) components."""
            x = base64url_decode(obj.get("x"))
            try:
                if "d" not in obj:
                    if curve == "Ed25519":
                        return Ed25519PublicKey.from_public_bytes(x)
                    return Ed448PublicKey.from_public_bytes(x)
                d = base64url_decode(obj.get("d"))
                if curve == "Ed25519":
                    return Ed25519PrivateKey.from_private_bytes(d)
                return Ed448PrivateKey.from_private_bytes(d)
            except ValueError as err:
                raise InvalidKeyError("Invalid key parameter") from err
