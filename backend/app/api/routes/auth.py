from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.models.user import User
from app.services.audit import AuditService
from app.services.audit_enums import AuditAction, AuditResult
from app.services.auth import (
    create_access_token,
    dummy_bcrypt_check,
    hash_opaque_token,
    hash_password,
    verify_password,
)
from app.services.password_reset import consume_reset_token, create_reset_token
from app.services.rate_limit import (
    FORGOT_ACCOUNT,
    FORGOT_IP,
    LOGIN_ACCOUNT,
    LOGIN_IP,
    REFRESH_IP,
    REGISTER_IP,
    RESET_IP,
    LimitSpec,
    limiter,
)
from app.services.sessions import (
    create_session,
    find_session_by_token_hash,
    revoke_family,
    revoke_session,
    revoke_user_sessions,
    rotate_session,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class AuthUserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: str
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20, max_length=256)
    new_password: str = Field(min_length=8, max_length=128)


class RegisterResponse(BaseModel):
    user: AuthUserResponse
    message: str


class LoginResponse(BaseModel):
    user: AuthUserResponse
    message: str


class MessageResponse(BaseModel):
    message: str


class ForgotPasswordResponse(MessageResponse):
    debug_reset_token: str | None = None


_GENERIC_LOGIN_ERROR = "Invalid email or password."
_GENERIC_RESET_ERROR = "The reset link is invalid or has expired."
_RATE_LIMIT_ERROR = "Too many requests. Please try again later."


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _get_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_ua(request: Request) -> str | None:
    ua = request.headers.get("user-agent")
    return ua[:512] if ua else None


def _account_key(kind: str, email: str) -> str:
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


def _ip_key(kind: str, ip: str | None) -> str:
    return f"{kind}:{ip or 'unknown'}"


def _enforce_limit(
    db: Session,
    request: Request,
    key: str,
    spec: LimitSpec,
    *,
    context: str,
) -> None:
    if not limiter.allow(key, spec):
        ip = _get_ip(request)
        audit = AuditService(db)
        audit.record(
            action=AuditAction.RATE_LIMIT_TRIGGERED,
            result=AuditResult.FAILURE,
            ip_address=ip,
            user_agent=_get_ua(request),
            description=context,
            metadata={"limit_key": key},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_RATE_LIMIT_ERROR,
        )


def _set_auth_cookies(
    response: Response,
    *,
    access_token: str,
    refresh_raw: str,
) -> None:
    refresh_expires = _now() + timedelta(days=settings.refresh_token_expire_days)
    response.set_cookie(
        key=settings.cookie_access_name,
        value=access_token,
        max_age=settings.access_token_expire_minutes * 60,
        path="/api",
        domain=settings.cookie_domain,
        secure=settings.cookie_secure,
        httponly=True,
        samesite=settings.cookie_samesite,
    )
    response.set_cookie(
        key=settings.cookie_refresh_name,
        value=refresh_raw,
        max_age=settings.refresh_token_expire_days * 86400,
        expires=refresh_expires,
        path="/api/auth",
        domain=settings.cookie_domain,
        secure=settings.cookie_secure,
        httponly=True,
        samesite=settings.cookie_samesite,
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(
        key=settings.cookie_access_name,
        path="/api",
        domain=settings.cookie_domain,
    )
    response.delete_cookie(
        key=settings.cookie_refresh_name,
        path="/api/auth",
        domain=settings.cookie_domain,
    )


def _auth_user_response(user: User) -> AuthUserResponse:
    return AuthUserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
    )


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> RegisterResponse:
    _enforce_limit(db, request, _ip_key("register", _get_ip(request)), REGISTER_IP, context="register")

    audit = AuditService(db)
    ip = _get_ip(request)
    ua = _get_ua(request)

    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        name=payload.name,
    )
    db.add(user)
    db.flush()

    audit.record(
        action=AuditAction.REGISTRATION,
        result=AuditResult.SUCCESS,
        actor_user_id=user.id,
        actor_email=user.email,
        resource_type="USER",
        resource_id=user.id,
        ip_address=ip,
        user_agent=ua,
        metadata={"name": user.name},
    )

    db.commit()
    db.refresh(user)

    response.delete_cookie(
        key=settings.cookie_access_name,
        path="/api",
        domain=settings.cookie_domain,
    )
    response.delete_cookie(
        key=settings.cookie_refresh_name,
        path="/api/auth",
        domain=settings.cookie_domain,
    )

    return RegisterResponse(
        user=_auth_user_response(user),
        message="Account created. Please sign in.",
    )


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    ip = _get_ip(request)
    _enforce_limit(db, request, _ip_key("login", ip), LOGIN_IP, context="login")
    _enforce_limit(
        db,
        request,
        _account_key("login", payload.email),
        LOGIN_ACCOUNT,
        context="login",
    )

    audit = AuditService(db)
    ua = _get_ua(request)
    user = db.scalar(select(User).where(User.email == payload.email))

    if user is None or not verify_password(payload.password, user.hashed_password):
        if user is None:
            dummy_bcrypt_check()
        audit.record(
            action=AuditAction.LOGIN_FAILED,
            result=AuditResult.FAILURE,
            actor_email=payload.email,
            ip_address=ip,
            user_agent=ua,
            description="Invalid credentials.",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_GENERIC_LOGIN_ERROR,
        )

    if not user.is_active:
        audit.record(
            action=AuditAction.LOGIN_FAILED,
            result=AuditResult.FAILURE,
            actor_user_id=user.id,
            actor_email=user.email,
            ip_address=ip,
            user_agent=ua,
            description="Account deactivated.",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated.",
        )

    refresh_raw, session = create_session(
        db,
        user_id=user.id,
        ip_address=ip,
        user_agent=ua,
    )
    access_token = create_access_token(user.id, session_id=session.id)

    audit.record(
        action=AuditAction.LOGIN_SUCCESS,
        result=AuditResult.SUCCESS,
        actor_user_id=user.id,
        actor_email=user.email,
        ip_address=ip,
        user_agent=ua,
        metadata={"session_id": session.id},
    )
    db.commit()

    _set_auth_cookies(
        response,
        access_token=access_token,
        refresh_raw=refresh_raw,
    )

    return LoginResponse(
        user=_auth_user_response(user),
        message="Signed in.",
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageResponse:
    audit = AuditService(db)
    session_id = getattr(request.state, "session_id", None)
    session_metadata: dict[str, object] = {}
    if session_id is not None:
        from app.models.auth_session import AuthSession

        session = db.get(AuthSession, session_id)
        if session is not None and session.revoked_at is None:
            revoke_session(db, session)
            session_metadata["session_id"] = session.id

    audit.record(
        action=AuditAction.LOGOUT,
        result=AuditResult.SUCCESS,
        actor_user_id=current_user.id,
        actor_email=current_user.email,
        ip_address=_get_ip(request),
        user_agent=_get_ua(request),
        metadata=session_metadata,
    )

    _clear_auth_cookies(response)
    db.commit()
    return MessageResponse(message="Logged out successfully.")


@router.get("/me", response_model=AuthUserResponse)
def get_me(current_user: User = Depends(get_current_user)) -> AuthUserResponse:
    return _auth_user_response(current_user)


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> MessageResponse:
    ip = _get_ip(request)
    _enforce_limit(db, request, _ip_key("forgot", ip), FORGOT_IP, context="forgot_pw")
    _enforce_limit(
        db,
        request,
        _account_key("forgot", payload.email),
        FORGOT_ACCOUNT,
        context="forgot_pw",
    )

    audit = AuditService(db)
    ua = _get_ua(request)
    user = db.scalar(select(User).where(User.email == payload.email))

    generic_message = "If an account exists with that email, a reset link has been sent."

    if user is None:
        audit.record(
            action=AuditAction.PASSWORD_RESET_REQUESTED,
            result=AuditResult.SUCCESS,
            actor_email=payload.email,
            ip_address=ip,
            user_agent=ua,
            description="No account found.",
        )
        db.commit()
        return MessageResponse(message=generic_message)

    reset_raw, _reset_row = create_reset_token(
        db,
        user_id=user.id,
        ip_address=ip,
        user_agent=ua,
    )

    audit.record(
        action=AuditAction.PASSWORD_RESET_REQUESTED,
        result=AuditResult.SUCCESS,
        actor_user_id=user.id,
        actor_email=user.email,
        ip_address=ip,
        user_agent=ua,
    )
    db.commit()

    if settings.debug_reset_returns_token:
        # Development/test aid only. Never enabled in production (fail-fast
        # rejects it). The production flow requires email delivery, which is
        # out of scope here and documented in the hardening report.
        return ForgotPasswordResponse(
            message=generic_message,
            debug_reset_token=reset_raw,
        )

    return MessageResponse(message=generic_message)


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> MessageResponse:
    ip = _get_ip(request)
    _enforce_limit(db, request, _ip_key("reset", ip), RESET_IP, context="reset_pw")

    audit = AuditService(db)
    ua = _get_ua(request)

    token_row = consume_reset_token(
        db,
        payload.token,
        ip_address=ip,
        user_agent=ua,
    )

    if token_row is None:
        audit.record(
            action=AuditAction.PASSWORD_RESET_FAILED,
            result=AuditResult.FAILURE,
            ip_address=ip,
            user_agent=ua,
            description="Invalid, expired, or already-used reset token.",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_GENERIC_RESET_ERROR,
        )

    user = db.get(User, token_row.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_GENERIC_RESET_ERROR,
        )

    user.hashed_password = hash_password(payload.new_password)

    revoked_count = revoke_user_sessions(db, user.id)

    audit.record(
        action=AuditAction.PASSWORD_RESET_COMPLETED,
        result=AuditResult.SUCCESS,
        actor_user_id=user.id,
        actor_email=user.email,
        resource_type="USER",
        resource_id=user.id,
        ip_address=ip,
        user_agent=ua,
        metadata={"revoked_sessions": revoked_count},
    )
    audit.record(
        action=AuditAction.SESSION_REVOKED,
        result=AuditResult.SUCCESS,
        actor_user_id=user.id,
        actor_email=user.email,
        resource_type="USER",
        resource_id=user.id,
        ip_address=ip,
        user_agent=ua,
        description="All sessions revoked after password reset.",
    )

    _clear_auth_cookies(response)
    db.commit()

    return MessageResponse(message="Your password has been reset. Please sign in with your new password.")


@router.post("/refresh", response_model=MessageResponse)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> MessageResponse:
    ip = _get_ip(request)
    _enforce_limit(db, request, _ip_key("refresh", ip), REFRESH_IP, context="refresh")

    raw_refresh = request.cookies.get(settings.cookie_refresh_name)
    if raw_refresh is None:
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session.",
        )

    ua = _get_ua(request)
    stored = find_session_by_token_hash(db, hash_opaque_token(raw_refresh))

    if stored is None:
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session.",
        )

    if stored.revoked_at is not None:
        # The presented refresh token was already consumed (rotated). Reuse of
        # a rotated token is treated as possible theft: the whole family dies.
        family_id = stored.family_id
        family_count = revoke_family(db, stored.family_id)
        audit = AuditService(db)
        audit.record(
            action=AuditAction.REFRESH_TOKEN_REUSED,
            result=AuditResult.FAILURE,
            actor_user_id=stored.user_id,
            ip_address=ip,
            user_agent=ua,
            description="Rotated refresh token reused; session family revoked.",
            metadata={"session_id": stored.id, "family_id": family_id, "revoked_sessions": family_count},
        )
        db.commit()
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session.",
        )

    if _ensure_utc(stored.expires_at) <= _now():
        revoke_session(db, stored)
        db.commit()
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session.",
        )

    user = db.get(User, stored.user_id)
    if user is None or not user.is_active:
        revoke_session(db, stored)
        db.commit()
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session.",
        )

    new_refresh, new_session = rotate_session(
        db,
        stored,
        ip_address=ip,
        user_agent=ua,
    )
    access_token = create_access_token(user.id, session_id=new_session.id)

    audit = AuditService(db)
    audit.record(
        action=AuditAction.REFRESH_TOKEN_ROTATED,
        result=AuditResult.SUCCESS,
        actor_user_id=user.id,
        actor_email=user.email,
        ip_address=ip,
        user_agent=ua,
        metadata={"session_id": new_session.id, "family_id": new_session.family_id},
    )
    db.commit()

    _set_auth_cookies(
        response,
        access_token=access_token,
        refresh_raw=new_refresh,
    )

    return MessageResponse(message="Session refreshed.")