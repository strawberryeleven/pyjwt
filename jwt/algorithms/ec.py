"""Elliptic-curve algorithms (ES256, ES256K, ES384, ES512)."""
from __future__ import annotations

import json
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Literal,
    Union,
    cast,
    get_args,
    overload,
)

from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ..utils import (
    base64url_decode,
    der_to_raw_signature,
    force_bytes,
    raw_to_der_signature,
    to_base64url_uint,
)
from ._base import Algorithm, _parse_jwk
from ._crypto import has_crypto

if has_crypto:
    from ._crypto import (
        ECDSA,
        SECP256K1,
        SECP256R1,
        SECP384R1,
        SECP521R1,
        AllowedECKeys,
        AllowedKeys,
        EllipticCurve,
        EllipticCurvePrivateKey,
        EllipticCurvePrivateNumbers,
        EllipticCurvePublicKey,
        EllipticCurvePublicNumbers,
        InvalidSignature,
        hashes,
        load_pem_private_key,
        load_pem_public_key,
        load_ssh_public_key,
    )

    if TYPE_CHECKING:
        from ._crypto import PrivateKeyTypes, PublicKeyTypes

    class ECAlgorithm(Algorithm):
        """Performs signing and verification operations using ECDSA and the specified hash function."""

        SHA256: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA256
        SHA384: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA384
        SHA512: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA512

        _crypto_key_types = cast(
            tuple[type[AllowedKeys], ...],
            get_args(Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]),
        )

        def __init__(
            self,
            hash_alg: type[hashes.HashAlgorithm],
            expected_curve: type[EllipticCurve] | None = None,
        ) -> None:
            self.hash_alg = hash_alg
            self.expected_curve = expected_curve

        def _validate_curve(self, key: AllowedECKeys) -> None:
            """Validate that the key's curve matches the expected curve."""
            if self.expected_curve is None:
                return

            if not isinstance(key.curve, self.expected_curve):
                raise InvalidKeyError(
                    f"The key's curve '{key.curve.name}' does not match the expected "
                    f"curve '{self.expected_curve.name}' for this algorithm"
                )

        def prepare_key(self, key: AllowedECKeys | str | bytes) -> AllowedECKeys:
            if isinstance(key, self._crypto_key_types):
                ec_key = cast(AllowedECKeys, key)
                self._validate_curve(ec_key)
                return ec_key

            if not isinstance(key, (bytes, str)):
                raise TypeError("Expecting a PEM-formatted key.")

            key_bytes = force_bytes(key)

            # Attempt to load key. We don't know if it's
            # a Signing Key or a Verifying Key, so we try
            # the Verifying Key first.
            try:
                if key_bytes.startswith(b"ecdsa-sha2-"):
                    public_key: PublicKeyTypes = load_ssh_public_key(key_bytes)
                else:
                    public_key = load_pem_public_key(key_bytes)

                # Explicit check the key to prevent confusing errors from cryptography
                self.check_crypto_key_type(public_key)
                ec_public_key = cast(EllipticCurvePublicKey, public_key)
                self._validate_curve(ec_public_key)
                return ec_public_key
            except ValueError:
                private_key = load_pem_private_key(key_bytes, password=None)
                self.check_crypto_key_type(private_key)
                ec_private_key = cast(EllipticCurvePrivateKey, private_key)
                self._validate_curve(ec_private_key)
                return ec_private_key

        _verify_failure_exceptions = (InvalidSignature, ValueError)

        def _compute_signature(
            self, msg: bytes, key: EllipticCurvePrivateKey
        ) -> bytes:
            return key.sign(msg, ECDSA(self.hash_alg()))

        def _finalise_signature(self, sig: bytes, key: Any) -> bytes:
            """Convert the cryptography library's DER signature to JWS-style raw R||S."""
            return der_to_raw_signature(sig, key.curve)

        def _do_verify(self, msg: bytes, key: AllowedECKeys, sig: bytes) -> bool:
            der_sig = raw_to_der_signature(sig, key.curve)
            public_key = (
                key.public_key()
                if isinstance(key, EllipticCurvePrivateKey)
                else key
            )
            public_key.verify(der_sig, msg, ECDSA(self.hash_alg()))
            return True

        @overload
        @staticmethod
        def to_jwk(key_obj: AllowedECKeys, as_dict: Literal[True]) -> JWKDict: ...

        @overload
        @staticmethod
        def to_jwk(key_obj: AllowedECKeys, as_dict: Literal[False] = False) -> str: ...

        @staticmethod
        def to_jwk(key_obj: AllowedECKeys, as_dict: bool = False) -> JWKDict | str:
            if isinstance(key_obj, EllipticCurvePrivateKey):
                public_numbers = key_obj.public_key().public_numbers()
            elif isinstance(key_obj, EllipticCurvePublicKey):
                public_numbers = key_obj.public_numbers()
            else:
                raise InvalidKeyError("Not a public or private key")

            if isinstance(key_obj.curve, SECP256R1):
                crv = "P-256"
            elif isinstance(key_obj.curve, SECP384R1):
                crv = "P-384"
            elif isinstance(key_obj.curve, SECP521R1):
                crv = "P-521"
            elif isinstance(key_obj.curve, SECP256K1):
                crv = "secp256k1"
            else:
                raise InvalidKeyError(f"Invalid curve: {key_obj.curve}")

            obj: dict[str, Any] = {
                "kty": "EC",
                "crv": crv,
                "x": to_base64url_uint(
                    public_numbers.x,
                    bit_length=key_obj.curve.key_size,
                ).decode(),
                "y": to_base64url_uint(
                    public_numbers.y,
                    bit_length=key_obj.curve.key_size,
                ).decode(),
            }

            if isinstance(key_obj, EllipticCurvePrivateKey):
                obj["d"] = to_base64url_uint(
                    key_obj.private_numbers().private_value,
                    bit_length=key_obj.curve.key_size,
                ).decode()

            if as_dict:
                return obj
            return json.dumps(obj)

        @staticmethod
        def from_jwk(jwk: str | JWKDict) -> AllowedECKeys:
            obj = _parse_jwk(jwk)

            if obj.get("kty") != "EC":
                raise InvalidKeyError("Not an Elliptic curve key") from None

            if "x" not in obj or "y" not in obj:
                raise InvalidKeyError("Not an Elliptic curve key") from None

            x = base64url_decode(obj.get("x"))
            y = base64url_decode(obj.get("y"))
            curve = obj.get("crv")

            curve_obj = ECAlgorithm._ec_resolve_curve(curve, x, y)
            public_numbers = EllipticCurvePublicNumbers(
                x=int.from_bytes(x, byteorder="big"),
                y=int.from_bytes(y, byteorder="big"),
                curve=curve_obj,
            )

            if "d" not in obj:
                return public_numbers.public_key()

            return ECAlgorithm._ec_private_key(obj, public_numbers, x, curve)

        @staticmethod
        def _ec_resolve_curve(
            curve: str, x: bytes, y: bytes
        ) -> EllipticCurve:
            """Map the JWK ``crv`` field to the matching cryptography curve,
            validating that the coordinates have the expected length."""
            if curve == "P-256":
                if len(x) == len(y) == 32:
                    return SECP256R1()
                raise InvalidKeyError(
                    "Coords should be 32 bytes for curve P-256"
                ) from None
            if curve == "P-384":
                if len(x) == len(y) == 48:
                    return SECP384R1()
                raise InvalidKeyError(
                    "Coords should be 48 bytes for curve P-384"
                ) from None
            if curve == "P-521":
                if len(x) == len(y) == 66:
                    return SECP521R1()
                raise InvalidKeyError(
                    "Coords should be 66 bytes for curve P-521"
                ) from None
            if curve == "secp256k1":
                if len(x) == len(y) == 32:
                    return SECP256K1()
                raise InvalidKeyError(
                    "Coords should be 32 bytes for curve secp256k1"
                )
            raise InvalidKeyError(f"Invalid curve: {curve}")

        @staticmethod
        def _ec_private_key(
            obj: JWKDict,
            public_numbers: EllipticCurvePublicNumbers,
            x: bytes,
            curve: str,
        ) -> EllipticCurvePrivateKey:
            """Decode the private ``d`` component from the JWK and assemble the private key."""
            d = base64url_decode(obj.get("d"))
            if len(d) != len(x):
                raise InvalidKeyError(
                    "D should be {} bytes for curve {}", len(x), curve
                )
            return EllipticCurvePrivateNumbers(
                int.from_bytes(d, byteorder="big"), public_numbers
            ).private_key()
