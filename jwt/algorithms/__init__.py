"""Algorithm implementations and registry.

The previous single-file ``jwt/algorithms.py`` was split into this package as
part of the re-engineering project (refactoring R9). All public names from
the original module remain importable via ``from jwt.algorithms import X``;
the per-algorithm definitions just live in dedicated modules now.
"""
from __future__ import annotations

from ._base import Algorithm, _parse_jwk
from ._crypto import (
    AllowedECKeys,
    AllowedKeys,
    AllowedOKPKeys,
    AllowedPrivateKeys,
    AllowedPublicKeys,
    AllowedRSAKeys,
    has_crypto,
)
from ._registry import get_default_algorithms, requires_cryptography
from .hmac import HMACAlgorithm
from .none import NoneAlgorithm

if has_crypto:
    from .ec import ECAlgorithm
    from .okp import OKPAlgorithm
    from .rsa import RSAAlgorithm, RSAPSSAlgorithm
