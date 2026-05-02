from __future__ import annotations

import binascii
import json
import warnings
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from ._internal import DecodedToken, warn_deprecated_kwargs
from .algorithms import (
    Algorithm,
    get_default_algorithms,
    has_crypto,
    requires_cryptography,
)
from .api_jwk import PyJWK
from .exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
)
from .utils import base64url_decode, base64url_encode
from .warnings import InsecureKeyLengthWarning

if TYPE_CHECKING:
    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys
    from .types import SigOptions

_ALGORITHM_UNSET = object()


class AlgorithmRegistry:
    """Mapping from algorithm name to :class:`Algorithm` instance.

    Extracted from :class:`PyJWS` so the JWS class can focus on framing and
    signature verification. ``PyJWS`` holds an ``AlgorithmRegistry`` as a
    collaborator and delegates its registry-related public methods to it.
    """

    def __init__(self, algorithms: Sequence[str] | None = None) -> None:
        self._algorithms = get_default_algorithms()
        self._valid_algs = (
            set(algorithms) if algorithms is not None else set(self._algorithms)
        )

        # Drop algorithms that are not on the whitelist.
        for key in list(self._algorithms.keys()):
            if key not in self._valid_algs:
                del self._algorithms[key]

    def register(self, alg_id: str, alg_obj: Algorithm) -> None:
        """Add a new :class:`Algorithm` to the registry."""
        if alg_id in self._algorithms:
            raise ValueError("Algorithm already has a handler.")
        if not isinstance(alg_obj, Algorithm):
            raise TypeError("Object is not of type `Algorithm`")
        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister(self, alg_id: str) -> None:
        """Remove an :class:`Algorithm` from the registry."""
        if alg_id not in self._algorithms:
            raise KeyError(
                "The specified algorithm could not be removed"
                " because it is not registered."
            )
        del self._algorithms[alg_id]
        self._valid_algs.remove(alg_id)

    def names(self) -> list[str]:
        """Return the list of supported algorithm names."""
        return list(self._valid_algs)

    def get(self, alg_name: str) -> Algorithm:
        """Return the :class:`Algorithm` instance registered under ``alg_name``."""
        try:
            return self._algorithms[alg_name]
        except KeyError as e:
            if not has_crypto and alg_name in requires_cryptography:
                raise NotImplementedError(
                    f"Algorithm '{alg_name}' could not be found. Do you have cryptography installed?"
                ) from e
            raise NotImplementedError("Algorithm not supported") from e


class PyJWS:
    header_typ = "JWT"

    def __init__(
        self,
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
    ) -> None:
        self._registry = AlgorithmRegistry(algorithms)

        self.options: SigOptions = self._get_default_options()
        if options is not None:
            self.options = {**self.options, **options}

    @staticmethod
    def _get_default_options() -> SigOptions:
        return {"verify_signature": True, "enforce_minimum_key_length": False}

    def register_algorithm(self, alg_id: str, alg_obj: Algorithm) -> None:
        """Register an :class:`Algorithm` for use when creating and verifying tokens."""
        self._registry.register(alg_id, alg_obj)

    def unregister_algorithm(self, alg_id: str) -> None:
        """Unregister an :class:`Algorithm`. Raises ``KeyError`` if not registered."""
        self._registry.unregister(alg_id)

    def get_algorithms(self) -> list[str]:
        """Return the list of supported values for the ``alg`` parameter."""
        return self._registry.names()

    def get_algorithm_by_name(self, alg_name: str) -> Algorithm:
        """Return the matching :class:`Algorithm` for the given ``alg`` name."""
        return self._registry.get(alg_name)

    def encode(
        self,
        payload: bytes,
        key: AllowedPrivateKeys | PyJWK | str | bytes,
        algorithm: str | None = _ALGORITHM_UNSET,  # type: ignore[assignment]
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        is_payload_detached: bool = False,
        sort_headers: bool = True,
    ) -> str:
        algorithm_ = self._resolve_algorithm(algorithm, headers, key)
        is_payload_detached = self._resolve_payload_detachment(
            headers, is_payload_detached
        )

        header = self._build_header(algorithm_, headers, is_payload_detached)

        json_header = json.dumps(
            header, separators=(",", ":"), cls=json_encoder, sort_keys=sort_headers
        ).encode()
        header_segment = base64url_encode(json_header)
        payload_segment = (
            payload if is_payload_detached else base64url_encode(payload)
        )
        signing_input = b".".join([header_segment, payload_segment])

        alg_obj = self.get_algorithm_by_name(algorithm_)
        if isinstance(key, PyJWK):
            key = key.key
        key = alg_obj.prepare_key(key)

        self._enforce_key_length(alg_obj, key)

        signature = alg_obj.sign(signing_input, key)
        signature_segment = base64url_encode(signature)

        # Detached payloads are emitted with an empty middle segment.
        final_payload = b"" if is_payload_detached else payload_segment
        return b".".join(
            [header_segment, final_payload, signature_segment]
        ).decode("utf-8")

    @staticmethod
    def _resolve_algorithm(
        algorithm: Any,
        headers: dict[str, Any] | None,
        key: Any,
    ) -> str:
        """Resolve the algorithm name from four possible sources, in priority order:
        explicit ``headers["alg"]`` (highest), explicit ``algorithm`` parameter,
        ``key.algorithm_name`` if ``key`` is a :class:`PyJWK`, fixed default."""
        if algorithm is _ALGORITHM_UNSET:
            algorithm_name = (
                key.algorithm_name if isinstance(key, PyJWK) else "HS256"
            )
        elif algorithm is None:
            algorithm_name = (
                key.algorithm_name if isinstance(key, PyJWK) else "none"
            )
        else:
            algorithm_name = algorithm

        if headers:
            header_alg = headers.get("alg")
            if header_alg:
                algorithm_name = header_alg

        return algorithm_name

    @staticmethod
    def _resolve_payload_detachment(
        headers: dict[str, Any] | None, is_payload_detached: bool
    ) -> bool:
        """``b64: false`` in the headers implies a detached payload."""
        if headers and headers.get("b64") is False:
            return True
        return is_payload_detached

    def _build_header(
        self,
        algorithm_name: str,
        headers: dict[str, Any] | None,
        is_payload_detached: bool,
    ) -> dict[str, Any]:
        """Construct the JOSE header dict, applying user-supplied overrides and the detachment flag."""
        header: dict[str, Any] = {"typ": self.header_typ, "alg": algorithm_name}

        if headers:
            self._validate_headers(headers, encoding=True)
            header.update(headers)

        if not header["typ"]:
            del header["typ"]

        if is_payload_detached:
            header["b64"] = False
        elif "b64" in header:
            # True is the standard value for b64, so no need for it
            del header["b64"]

        return header

    def _enforce_key_length(self, alg_obj: Algorithm, key: Any) -> None:
        """Raise (when ``enforce_minimum_key_length`` is set) or warn when the key is short."""
        key_length_msg = alg_obj.check_key_length(key)
        if not key_length_msg:
            return
        if self.options.get("enforce_minimum_key_length", False):
            raise InvalidKeyError(key_length_msg)
        warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=3)

    def decode_complete(
        self,
        jwt: str | bytes,
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
        detached_payload: bytes | None = None,
        **kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        warn_deprecated_kwargs("decode_complete", kwargs)
        merged_options: SigOptions
        if options is None:
            merged_options = self.options
        else:
            merged_options = {**self.options, **options}

        verify_signature = merged_options["verify_signature"]

        if verify_signature and not algorithms and not isinstance(key, PyJWK):
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )

        decoded = self._load(jwt)

        self._validate_headers(decoded.header)

        payload = decoded.payload
        signing_input = decoded.signing_input

        if decoded.header.get("b64", True) is False:
            if detached_payload is None:
                raise DecodeError(
                    'It is required that you pass in a value for the "detached_payload" argument to decode a message having the b64 header set to false.'
                )
            payload = detached_payload
            signing_input = b".".join([signing_input.rsplit(b".", 1)[0], payload])

        if verify_signature:
            self._verify_signature(
                signing_input, decoded.header, decoded.signature, key, algorithms
            )

        return {
            "payload": payload,
            "header": decoded.header,
            "signature": decoded.signature,
        }

    def decode(
        self,
        jwt: str | bytes,
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
        detached_payload: bytes | None = None,
        **kwargs: dict[str, Any],
    ) -> Any:
        warn_deprecated_kwargs("decode", kwargs)
        decoded = self.decode_complete(
            jwt, key, algorithms, options, detached_payload=detached_payload
        )
        return decoded["payload"]

    def get_unverified_header(self, jwt: str | bytes) -> dict[str, Any]:
        """Returns back the JWT header parameters as a `dict`

        Note: The signature is not verified so the header parameters
        should not be fully trusted until signature verification is complete
        """
        headers = self._load(jwt).header
        self._validate_headers(headers)

        return headers

    def _load(self, jwt: str | bytes) -> DecodedToken:
        if isinstance(jwt, str):
            jwt = jwt.encode("utf-8")

        if not isinstance(jwt, bytes):
            raise DecodeError(f"Invalid token type. Token must be a {bytes}")

        try:
            signing_input, crypto_segment = jwt.rsplit(b".", 1)
            header_segment, payload_segment = signing_input.split(b".", 1)
        except ValueError as err:
            raise DecodeError("Not enough segments") from err

        try:
            header_data = base64url_decode(header_segment)
        except (TypeError, binascii.Error) as err:
            raise DecodeError("Invalid header padding") from err

        try:
            header: dict[str, Any] = json.loads(header_data)
        except ValueError as e:
            raise DecodeError(f"Invalid header string: {e}") from e

        if not isinstance(header, dict):
            raise DecodeError("Invalid header string: must be a json object")

        try:
            payload = base64url_decode(payload_segment)
        except (TypeError, binascii.Error) as err:
            raise DecodeError("Invalid payload padding") from err

        try:
            signature = base64url_decode(crypto_segment)
        except (TypeError, binascii.Error) as err:
            raise DecodeError("Invalid crypto padding") from err

        return DecodedToken(
            payload=payload,
            signing_input=signing_input,
            header=header,
            signature=signature,
        )

    def _verify_signature(
        self,
        signing_input: bytes,
        header: dict[str, Any],
        signature: bytes,
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
    ) -> None:
        if algorithms is None and isinstance(key, PyJWK):
            algorithms = [key.algorithm_name]
        try:
            alg = header["alg"]
        except KeyError:
            raise InvalidAlgorithmError("Algorithm not specified") from None

        if not alg or (algorithms is not None and alg not in algorithms):
            raise InvalidAlgorithmError("The specified alg value is not allowed")

        if isinstance(key, PyJWK):
            alg_obj = key.Algorithm
            prepared_key = key.key
        else:
            try:
                alg_obj = self.get_algorithm_by_name(alg)
            except NotImplementedError as e:
                raise InvalidAlgorithmError("Algorithm not supported") from e
            prepared_key = alg_obj.prepare_key(key)

        key_length_msg = alg_obj.check_key_length(prepared_key)
        if key_length_msg:
            if self.options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            else:
                warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=4)

        if not alg_obj.verify(signing_input, prepared_key, signature):
            raise InvalidSignatureError("Signature verification failed")

    # Extensions that PyJWT actually understands and supports
    _supported_crit: set[str] = {"b64"}

    def _validate_headers(
        self, headers: dict[str, Any], *, encoding: bool = False
    ) -> None:
        if "kid" in headers:
            self._validate_kid(headers["kid"])
        if not encoding and "crit" in headers:
            self._validate_crit(headers)

    def _validate_kid(self, kid: Any) -> None:
        if not isinstance(kid, str):
            raise InvalidTokenError("Key ID header parameter must be a string")

    def _validate_crit(self, headers: dict[str, Any]) -> None:
        crit = headers["crit"]
        if not isinstance(crit, list) or len(crit) == 0:
            raise InvalidTokenError("Invalid 'crit' header: must be a non-empty list")
        for ext in crit:
            if not isinstance(ext, str):
                raise InvalidTokenError("Invalid 'crit' header: values must be strings")
            if ext not in self._supported_crit:
                raise InvalidTokenError(f"Unsupported critical extension: {ext}")
            if ext not in headers:
                raise InvalidTokenError(
                    f"Critical extension '{ext}' is missing from headers"
                )


_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
decode_complete = _jws_global_obj.decode_complete
decode = _jws_global_obj.decode
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header
