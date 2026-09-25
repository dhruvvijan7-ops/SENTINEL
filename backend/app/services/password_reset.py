from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.password_reset import PasswordResetToken
from app.services.auth import generate_opaque_token, hash_opaque_token


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def create_reset_token(
    db: Session,
    *,
    user_id: str,
    ip_address: str | None,
    user_agent: str | None,
) -> tuple[str, PasswordResetToken]:
    """Issue a single-use password-reset credential.

    Any previously un-used reset tokens for the user are revoked so only one
    reset link is valid at a time. Returns (raw_token, row).
    """
    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user_id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.revoked_at.is_(None),
        )
        .values(revoked_at=_now())
    )
    raw, token_hash = generate_opaque_token()
    row = PasswordResetToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=_now() + timedelta(minutes=settings.reset_token_expire_minutes),
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(row)
    db.flush()
    return raw, row


def consume_reset_token(
    db: Session,
    raw_token: str,
    *,
    ip_address: str | None,
    user_agent: str | None,
) -> PasswordResetToken | None:
    """Validate, mark consumed, and return the token row if redeemable.

    Returns None for unknown, expired, already-used, or revoked tokens so
    callers can return a generic failure without leaking state.
    """
    row = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == hash_opaque_token(raw_token))
        .first()
    )
    if row is None or row.used_at is not None or row.revoked_at is not None:
        return None
    if _ensure_utc(row.expires_at) <= _now():
        row.revoked_at = _now()
        db.add(row)
        db.flush()
        return None
    row.used_at = _now()
    row.ip_address = row.ip_address or ip_address
    row.user_agent = row.user_agent or user_agent
    db.add(row)
    db.flush()
    return row