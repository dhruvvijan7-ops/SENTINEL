from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_ACCESS_TOKEN_TYPE = "access"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


_DUMMY_HASH = pwd_context.hash("sentinel-timing-equalization-dummy-password-v1")


def dummy_bcrypt_check() -> None:
    """Run a bcrypt comparison against a fixed dummy hash.

    Callers use this when an email does not exist so that login latency does
    not reveal whether an account exists (account enumeration via timing).
    """
    pwd_context.verify("sentinel-timing-equalization-dummy-password-v1", _DUMMY_HASH)


def generate_opaque_token() -> tuple[str, str]:
    """Return (raw_token, sha256_hash). Only the hash may be persisted."""
    raw = secrets.token_urlsafe(48)
    return raw, hash_opaque_token(raw)


def hash_opaque_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def verify_opaque_token(raw_token: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_opaque_token(raw_token), stored_hash)


def create_access_token(
    user_id: str,
    *,
    session_id: str | None = None,
    expires_minutes: int | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    ttl = timedelta(
        minutes=expires_minutes or settings.access_token_expire_minutes
    )
    payload: dict[str, object] = {
        "sub": user_id,
        "jti": str(uuid4()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "typ": _ACCESS_TOKEN_TYPE,
    }
    if session_id is not None:
        payload["sid"] = session_id
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, object] | None:
    """Strictly decode and validate an access token.

    Enforces the signed algorithm, issuer, audience, expiry, and required
    claims. Returns the validated claims on success, otherwise None.
    """
    try:
        header_alg = jwt.get_unverified_header(token).get("alg")
        if header_alg != settings.jwt_algorithm:
            return None
        claims = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "jti", "typ"]},
        )
    except jwt.InvalidTokenError:
        return None

    if claims.get("typ") != _ACCESS_TOKEN_TYPE:
        return None
    if not claims.get("sub") or not claims.get("jti"):
        return None
    return claims