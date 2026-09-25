from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.auth_session import AuthSession
from app.services.auth import generate_opaque_token, hash_opaque_token


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def create_session(
    db: Session,
    *,
    user_id: str,
    ip_address: str | None,
    user_agent: str | None,
) -> tuple[str, AuthSession]:
    """Create a new refresh-token session. Returns (raw_refresh_token, session)."""
    raw, token_hash = generate_opaque_token()
    session = AuthSession(
        user_id=user_id,
        session_token_hash=token_hash,
        family_id=str(uuid4()),
        last_used_at=_now(),
        expires_at=_now() + timedelta(days=settings.refresh_token_expire_days),
        ip_address=ip_address,
        user_agent=user_agent,
        user_agent_hash=_hash_ua(user_agent),
    )
    db.add(session)
    db.flush()
    return raw, session


def find_session_by_token_hash(db: Session, token_hash: str) -> AuthSession | None:
    return db.query(AuthSession).filter(AuthSession.session_token_hash == token_hash).first()


def find_active_session_by_id(db: Session, session_id: str, user_id: str) -> AuthSession | None:
    session = (
        db.query(AuthSession)
        .filter(
            AuthSession.id == session_id,
            AuthSession.user_id == user_id,
            AuthSession.revoked_at.is_(None),
        )
        .first()
    )
    if session is None:
        return None
    if _ensure_utc(session.expires_at) <= _now():
        return None
    return session


def touch_session(db: Session, session: AuthSession) -> None:
    """Record last use without a write-heavy update on every request."""
    now = _now()
    if session.last_used_at is None or (now - _ensure_utc(session.last_used_at)) >= timedelta(minutes=5):
        session.last_used_at = now
        db.add(session)


def revoke_session(db: Session, session: AuthSession) -> None:
    if session.revoked_at is None:
        session.revoked_at = _now()
        db.add(session)


def revoke_user_sessions(db: Session, user_id: str) -> int:
    result = db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=_now())
    )
    return result.rowcount or 0


def revoke_family(db: Session, family_id: str) -> int:
    result = db.execute(
        update(AuthSession)
        .where(AuthSession.family_id == family_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=_now())
    )
    return result.rowcount or 0


def rotate_session(
    db: Session,
    session: AuthSession,
    *,
    ip_address: str | None,
    user_agent: str | None,
) -> tuple[str, AuthSession]:
    """Consume `session` and mint a successor in the same family.

    Returns (raw_new_refresh_token, new_session). The consumed session is
    recorded as revoked so replay of the old token can be detected.
    """
    revoke_session(db, session)
    raw_refresh, token_hash = generate_opaque_token()
    new = AuthSession(
        user_id=session.user_id,
        session_token_hash=token_hash,
        family_id=session.family_id,
        last_used_at=_now(),
        expires_at=_now() + timedelta(days=settings.refresh_token_expire_days),
        ip_address=ip_address,
        user_agent=user_agent,
        user_agent_hash=_hash_ua(user_agent),
    )
    db.add(new)
    db.flush()
    return raw_refresh, new


def _hash_ua(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    import hashlib

    return hashlib.sha256(user_agent.encode("utf-8")).hexdigest()