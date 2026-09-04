from __future__ import annotations

import math

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.core.database import get_db
from app.models.user import User
from app.schemas.users import UserCreateRequest, UserListResponse, UserResponse, UserUpdateRequest
from app.services.auth import hash_password
from app.services.audit import AuditService
from app.services.audit_enums import AuditAction, AuditResult

router = APIRouter(prefix="/users", tags=["users"])

_admin = require_role("admin")


@router.post("", response_model=UserResponse, status_code=201)
def create_user(
    payload: UserCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(_admin),
) -> User:
    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists.",
        )

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        name=payload.name,
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.flush()

    audit = AuditService(db)
    audit.record(
        action=AuditAction.USER_CREATED,
        result=AuditResult.SUCCESS,
        actor_user_id=admin.id,
        actor_email=admin.email,
        resource_type="USER",
        resource_id=user.id,
        ip_address=_get_ip(request),
        user_agent=_get_ua(request),
        metadata={
            "target_user_email": user.email,
            "target_user_name": user.name,
            "role": user.role,
        },
    )

    db.commit()
    db.refresh(user)
    return user


@router.get("", response_model=UserListResponse)
def list_users(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    search: str | None = Query(default=None),
    role: str | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    db: Session = Depends(get_db),
    _admin: User = Depends(_admin),
) -> UserListResponse:
    statement = select(User)

    if search:
        pattern = f"%{search}%"
        statement = statement.where(
            or_(
                User.name.ilike(pattern),
                User.email.ilike(pattern),
            )
        )

    if role is not None:
        statement = statement.where(User.role == role)

    if is_active is not None:
        statement = statement.where(User.is_active == is_active)

    count_statement = select(func.count()).select_from(statement.subquery())
    total = db.scalar(count_statement) or 0
    total_pages = max(1, math.ceil(total / page_size))

    statement = statement.order_by(User.created_at.desc())
    statement = statement.offset((page - 1) * page_size).limit(page_size)

    items = list(db.scalars(statement).all())

    return UserListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    _admin: User = Depends(_admin),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    return user


@router.patch("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(_admin),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    audit = AuditService(db)
    ip = _get_ip(request)
    ua = _get_ua(request)

    if payload.role is not None and payload.role != user.role:
        old_role = user.role
        user.role = payload.role
        audit.record(
            action=AuditAction.USER_ROLE_CHANGED,
            result=AuditResult.SUCCESS,
            actor_user_id=admin.id,
            actor_email=admin.email,
            resource_type="USER",
            resource_id=user.id,
            ip_address=ip,
            user_agent=ua,
            metadata={
                "old_role": old_role,
                "new_role": payload.role,
                "target_user_email": user.email,
            },
        )

    if payload.is_active is not None and payload.is_active != user.is_active:
        if not payload.is_active and user.role == "admin":
            admin_count = db.scalar(
                select(func.count())
                .select_from(User)
                .where(User.role == "admin", User.is_active == True)
            ) or 0
            if admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cannot deactivate the last active admin.",
                )

        if payload.role is None and user.role == "admin":
            active_admin_count = db.scalar(
                select(func.count())
                .select_from(User)
                .where(User.role == "admin", User.is_active == True, User.id != user.id)
            ) or 0
            if not payload.is_active and active_admin_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cannot deactivate the last active admin.",
                )

        old_active = user.is_active
        user.is_active = payload.is_active

        action = AuditAction.USER_ACTIVATED if payload.is_active else AuditAction.USER_DEACTIVATED
        audit.record(
            action=action,
            result=AuditResult.SUCCESS,
            actor_user_id=admin.id,
            actor_email=admin.email,
            resource_type="USER",
            resource_id=user.id,
            ip_address=ip,
            user_agent=ua,
            metadata={
                "old_active": old_active,
                "new_active": payload.is_active,
                "target_user_email": user.email,
            },
        )

    if not payload.role and payload.is_active is None:
        return user

    db.commit()
    db.refresh(user)
    return user


def _get_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_ua(request: Request) -> str | None:
    ua = request.headers.get("user-agent")
    return ua[:512] if ua else None
