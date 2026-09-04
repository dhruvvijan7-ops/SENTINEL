from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.services.audit import AuditService
from app.services.audit_enums import AuditAction, AuditResult
from app.services.auth import create_access_token, decode_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


class AuthUserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str


class AuthResponse(BaseModel):
    user: AuthUserResponse
    token: str


class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


@router.post("/register", response_model=AuthResponse, status_code=201)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> AuthResponse:
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

    audit = AuditService(db)
    audit.record(
        action=AuditAction.REGISTRATION,
        result=AuditResult.SUCCESS,
        actor_user_id=user.id,
        actor_email=user.email,
        resource_type="USER",
        resource_id=user.id,
        ip_address=_get_ip(request),
        user_agent=_get_ua(request),
        metadata={"name": user.name},
    )

    db.commit()
    db.refresh(user)

    token = create_access_token(user.id)
    return AuthResponse(
        user=AuthUserResponse(id=user.id, email=user.email, name=user.name, role=user.role),
        token=token,
    )


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> AuthResponse:
    user = db.scalar(select(User).where(User.email == payload.email))

    audit = AuditService(db)
    ip = _get_ip(request)
    ua = _get_ua(request)

    if user is None or not verify_password(payload.password, user.hashed_password):
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
            detail="Invalid email or password.",
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

    audit.record(
        action=AuditAction.LOGIN_SUCCESS,
        result=AuditResult.SUCCESS,
        actor_user_id=user.id,
        actor_email=user.email,
        ip_address=ip,
        user_agent=ua,
    )
    db.commit()

    token = create_access_token(user.id)
    return AuthResponse(
        user=AuthUserResponse(id=user.id, email=user.email, name=user.name, role=user.role),
        token=token,
    )


@router.post("/logout")
def logout(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, str]:
    audit = AuditService(db)
    audit.record(
        action=AuditAction.LOGOUT,
        result=AuditResult.SUCCESS,
        actor_user_id=current_user.id,
        actor_email=current_user.email,
        ip_address=_get_ip(request),
        user_agent=_get_ua(request),
    )
    db.commit()
    return {"message": "Logged out successfully."}


@router.get("/me", response_model=AuthUserResponse)
def get_me(current_user: User = Depends(get_current_user)) -> AuthUserResponse:
    return AuthUserResponse(
        id=current_user.id,
        email=current_user.email,
        name=current_user.name,
        role=current_user.role,
    )


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    user = db.scalar(select(User).where(User.email == payload.email))

    audit = AuditService(db)
    ip = _get_ip(request)
    ua = _get_ua(request)

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
        return {"message": "If an account exists with that email, a reset link has been sent."}

    reset_token = create_access_token(user.id)

    audit.record(
        action=AuditAction.PASSWORD_RESET_REQUESTED,
        result=AuditResult.SUCCESS,
        actor_user_id=user.id,
        actor_email=user.email,
        ip_address=ip,
        user_agent=ua,
    )

    import logging
    logging.getLogger(__name__).info(
        "Password reset requested for %s — token: %s",
        payload.email,
        reset_token,
    )

    db.commit()
    return {"message": "If an account exists with that email, a reset link has been sent."}


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    user_id = decode_access_token(payload.token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        )

    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        )

    user.hashed_password = hash_password(payload.new_password)

    audit = AuditService(db)
    audit.record(
        action=AuditAction.PASSWORD_RESET_COMPLETED,
        result=AuditResult.SUCCESS,
        actor_user_id=user.id,
        actor_email=user.email,
        resource_type="USER",
        resource_id=user.id,
        ip_address=_get_ip(request),
        user_agent=_get_ua(request),
    )

    db.commit()

    return {"message": "Password has been reset successfully. You can now sign in."}


def _get_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_ua(request: Request | None) -> str | None:
    if request is None:
        return None
    ua = request.headers.get("user-agent")
    return ua[:512] if ua else None
