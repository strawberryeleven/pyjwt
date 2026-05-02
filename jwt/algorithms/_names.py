"""Algorithm-name constants.

Exposes the closed set of algorithm-name strings supported by the library
as module-level constants. References elsewhere in the package use these
constants instead of the raw string literals so a typo is caught at import
time rather than producing a silent runtime mismatch.

The on-the-wire ``alg`` header value is still a string (per RFC 7518); only
the in-code references are named.
"""
from __future__ import annotations

# Unsigned tokens
NONE = "none"

# Symmetric (HMAC) — RFC 7518 §3.2
HS256 = "HS256"
HS384 = "HS384"
HS512 = "HS512"

# RSA PKCS#1 v1.5 — RFC 7518 §3.3
RS256 = "RS256"
RS384 = "RS384"
RS512 = "RS512"

# RSA PSS — RFC 7518 §3.5
PS256 = "PS256"
PS384 = "PS384"
PS512 = "PS512"

# Elliptic Curve (ECDSA) — RFC 7518 §3.4
ES256 = "ES256"
ES256K = "ES256K"
ES384 = "ES384"
ES512 = "ES512"
ES521 = "ES521"  # Backward-compat alias for the original mistyped name (#219)

# Edwards Curve — RFC 8037
EDDSA = "EdDSA"
