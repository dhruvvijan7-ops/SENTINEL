from __future__ import annotations

import os
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure the application never attempts to reach an external database
# during tests. config.py calls load_dotenv(), which does not override
# already-present environment variables, so setting these before importing
# app.main keeps the import-time engine on SQLite.
os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_sentinelai.db")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-that-is-at-least-32-bytes-for-sentinel-auth")
os.environ.setdefault("JWT_ISSUER", "sentinel.api")
os.environ.setdefault("JWT_AUDIENCE", "sentinel.frontend")
os.environ.setdefault("DEBUG_RESET_RETURNS_TOKEN", "true")

from app.api.deps import get_current_user
from app.core.database import Base, get_db
from app.main import app
from app.models.user import User
from app.services.auth import create_access_token, hash_password
from app.services.rate_limit import limiter
from app.services.sessions import create_session

SQLITE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    SQLITE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)


@pytest.fixture(autouse=True)
def setup_db() -> Generator[None, None, None]:
    Base.metadata.create_all(bind=test_engine)
    limiter.reset()
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture()
def db() -> Generator[Session, None, None]:
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()


def _make_user(db: Session, *, email: str, password: str, name: str, role: str) -> User:
    user = User(
        email=email,
        hashed_password=hash_password(password),
        name=name,
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture()
def admin_user(db: Session) -> User:
    return _make_user(
        db,
        email="admin@sentinelai.local",
        password="adminpassword123",
        name="Test Admin",
        role="admin",
    )


@pytest.fixture()
def analyst_user(db: Session) -> User:
    return _make_user(
        db,
        email="analyst@sentinelai.local",
        password="analystpassword123",
        name="Test Analyst",
        role="analyst",
    )


def _session_token(db: Session, user: User) -> str:
    _raw, session = create_session(
        db,
        user_id=user.id,
        ip_address="127.0.0.1",
        user_agent="pytest",
    )
    db.commit()
    return create_access_token(user.id, session_id=session.id)


@pytest.fixture()
def admin_token(db: Session, admin_user: User) -> str:
    return _session_token(db, admin_user)


@pytest.fixture()
def analyst_token(db: Session, analyst_user: User) -> str:
    return _session_token(db, analyst_user)


@pytest.fixture()
def client(db: Session, admin_user: User) -> Generator[TestClient, None, None]:
    def _override_get_db() -> Generator[Session, None, None]:
        yield db

    def _override_get_current_user() -> User:
        return admin_user

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


@pytest.fixture()
def analyst_client(db: Session, analyst_user: User) -> Generator[TestClient, None, None]:
    def _override_get_db() -> Generator[Session, None, None]:
        yield db

    def _override_get_current_user() -> User:
        return analyst_user

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


@pytest.fixture()
def unauth_client(db: Session) -> Generator[TestClient, None, None]:
    def _override_get_db() -> Generator[Session, None, None]:
        yield db

    app.dependency_overrides[get_db] = _override_get_db

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()