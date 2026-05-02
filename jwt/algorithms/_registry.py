"""Default algorithm registry and the cryptography-required allow-list."""
from __future__ import annotations

from . import _names
from ._base import Algorithm
from ._crypto import has_crypto
from .hmac import HMACAlgorithm
from .none import NoneAlgorithm

if has_crypto:
    from ._crypto import SECP256K1, SECP256R1, SECP384R1, SECP521R1
    from .ec import ECAlgorithm
    from .okp import OKPAlgorithm
    from .rsa import RSAAlgorithm, RSAPSSAlgorithm


requires_cryptography = {
    _names.RS256,
    _names.RS384,
    _names.RS512,
    _names.ES256,
    _names.ES256K,
    _names.ES384,
    _names.ES521,
    _names.ES512,
    _names.PS256,
    _names.PS384,
    _names.PS512,
    _names.EDDSA,
}


def get_default_algorithms() -> dict[str, Algorithm]:
    """Returns the algorithms that are implemented by the library."""
    default_algorithms: dict[str, Algorithm] = {
        _names.NONE: NoneAlgorithm(),
        _names.HS256: HMACAlgorithm(HMACAlgorithm.SHA256),
        _names.HS384: HMACAlgorithm(HMACAlgorithm.SHA384),
        _names.HS512: HMACAlgorithm(HMACAlgorithm.SHA512),
    }

    if has_crypto:
        default_algorithms.update(
            {
                _names.RS256: RSAAlgorithm(RSAAlgorithm.SHA256),
                _names.RS384: RSAAlgorithm(RSAAlgorithm.SHA384),
                _names.RS512: RSAAlgorithm(RSAAlgorithm.SHA512),
                _names.ES256: ECAlgorithm(ECAlgorithm.SHA256, SECP256R1),
                _names.ES256K: ECAlgorithm(ECAlgorithm.SHA256, SECP256K1),
                _names.ES384: ECAlgorithm(ECAlgorithm.SHA384, SECP384R1),
                _names.ES521: ECAlgorithm(ECAlgorithm.SHA512, SECP521R1),
                _names.ES512: ECAlgorithm(
                    ECAlgorithm.SHA512, SECP521R1
                ),  # Backward compat for #219 fix
                _names.PS256: RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256),
                _names.PS384: RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384),
                _names.PS512: RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512),
                _names.EDDSA: OKPAlgorithm(),
            }
        )

    return default_algorithms
