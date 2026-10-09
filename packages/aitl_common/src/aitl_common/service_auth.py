"""Service-to-service authentication on ``core-net`` (ARCHITECTURE.md §16, §25, §28).

Internal endpoints (e.g. ``/gateway/v1/internal/...``, ``/eval/internal/...``,
``/agent/internal/...``) accept only the named calling service's bearer token.

This is **not** the agent capability-token mechanism (PRD FR-019a). Capability
tokens are issued per execution by the Tool Gateway and bind decision context;
service tokens only authenticate one platform service to another. The two must
never be interchangeable.

Properties:
- Tokens are per-deployment secrets read from files produced by
  ``deploy/secrets/generate.sh``; nothing is hard-coded.
- Tokens must be at least 32 printable, non-whitespace ASCII characters;
  shorter or malformed tokens refuse to load.
- Comparison is constant-time over SHA-256 digests, and every configured caller
  is compared (no early exit), so neither token content nor caller identity is
  revealed through timing.
- Every failure (missing header, wrong scheme, unknown token, token of a caller
  not allowed on this endpoint) returns 401 with no detail about which check failed.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Annotated

from fastapi import Header, HTTPException, status

from aitl_common.logging import log_event

__all__ = [
    "MIN_TOKEN_LENGTH",
    "ServiceTokenStore",
    "require_service",
]

MIN_TOKEN_LENGTH = 32
_TOKEN_FORMAT = re.compile(r"^[\x21-\x7e]+$")
_SERVICE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_logger = logging.getLogger("aitl.service_auth")


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("ascii", errors="replace")).digest()


class ServiceTokenStore:
    """Holds the expected token digest of each calling service."""

    def __init__(self, tokens: Mapping[str, str]) -> None:
        if not tokens:
            raise ValueError("at least one caller token is required")
        digests: dict[str, bytes] = {}
        for caller, token in tokens.items():
            if not _SERVICE_NAME.fullmatch(caller):
                raise ValueError(f"invalid service name {caller!r}")
            if len(token) < MIN_TOKEN_LENGTH or not _TOKEN_FORMAT.fullmatch(token):
                raise ValueError(f"token for {caller!r} is too short or malformed")
            digests[caller] = _digest(token)
        if len(set(digests.values())) != len(digests):
            raise ValueError("each caller must have a distinct token")
        self._digests = digests

    @classmethod
    def from_directory(cls, directory: Path, callers: Iterable[str]) -> ServiceTokenStore:
        """Load ``<directory>/<caller>`` token files (one token per file)."""
        tokens: dict[str, str] = {}
        for caller in callers:
            path = directory / caller
            tokens[caller] = path.read_text(encoding="ascii").strip()
        return cls(tokens)

    @property
    def callers(self) -> frozenset[str]:
        return frozenset(self._digests)

    def authenticate(self, presented: str) -> str | None:
        """Return the caller whose token matches ``presented``, else ``None``.

        Every configured caller is compared, in constant time, regardless of
        earlier matches.
        """
        presented_digest = _digest(presented)
        matched: str | None = None
        for caller, expected in self._digests.items():
            if hmac.compare_digest(presented_digest, expected):
                matched = caller
        return matched


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="unauthorized",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_service(store: ServiceTokenStore, allowed_callers: Iterable[str]) -> Callable[..., str]:
    """Build a FastAPI dependency that admits only ``allowed_callers``.

    The dependency returns the authenticated caller's service name.
    """
    allowed = frozenset(allowed_callers)
    if not allowed:
        raise ValueError("allowed_callers must not be empty")
    unknown = allowed - store.callers
    if unknown:
        raise ValueError(f"no token configured for callers: {sorted(unknown)}")

    def dependency(authorization: Annotated[str | None, Header()] = None) -> str:
        if authorization is None:
            log_event(_logger, logging.WARNING, "service_auth.rejected", reason="missing")
            raise _unauthorized()
        scheme, _, credential = authorization.partition(" ")
        if scheme.lower() != "bearer" or not credential or " " in credential:
            log_event(_logger, logging.WARNING, "service_auth.rejected", reason="malformed")
            raise _unauthorized()
        caller = store.authenticate(credential)
        if caller is None or caller not in allowed:
            log_event(_logger, logging.WARNING, "service_auth.rejected", reason="not_permitted")
            raise _unauthorized()
        return caller

    return dependency
