import time
from typing import Optional

from .api_jwk import PyJWKSet


class JWKSetWithTimestamp:
    def __init__(self, jwk_set: PyJWKSet):
        self.jwk_set = jwk_set
        self.timestamp = time.monotonic()

    def get_jwk_set(self) -> PyJWKSet:
        return self.jwk_set

    def get_timestamp(self) -> float:
        return self.timestamp


class JWKSetCache:
    def __init__(self, lifespan: float) -> None:
        self.jwk_set_with_timestamp: Optional[JWKSetWithTimestamp] = None
        self.lifespan = lifespan

    def put(self, jwk_set: PyJWKSet) -> None:
        if jwk_set is not None:
            self.jwk_set_with_timestamp = JWKSetWithTimestamp(jwk_set)
        else:
            # clear cache
            self.jwk_set_with_timestamp = None

    def get(self) -> Optional[PyJWKSet]:
        if self.jwk_set_with_timestamp is None or self.is_expired():
            return None

        return self.jwk_set_with_timestamp.get_jwk_set()

    def is_expired(self) -> bool:
        return (
            self.jwk_set_with_timestamp is not None
            and self.lifespan > -1
            and time.monotonic()
            > self.jwk_set_with_timestamp.get_timestamp() + self.lifespan
        )
