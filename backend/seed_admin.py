"""Seed the admin user into the configured database.

Run from the backend directory with the desired DATABASE_URL set.
Example:  $env:DATABASE_URL="sqlite:///./sentinelai.db"; python seed_admin.py
"""
from __future__ import annotations

import os

from app.core.database import Base, SessionLocal, engine
from app.models.user import User
from app.services.auth import hash_password

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@sentinelai.local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin12345")
ADMIN_NAME = os.getenv("ADMIN_NAME", "Administrator")


def main() -> None:
    import app.models  # noqa: F401 - register models

    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        existing = db.query(User).where(User.email == ADMIN_EMAIL).first()
        if existing is not None:
            print(f"Admin user already exists: {ADMIN_EMAIL}")
            return

        user = User(
            email=ADMIN_EMAIL,
            hashed_password=hash_password(ADMIN_PASSWORD),
            name=ADMIN_NAME,
            role="admin",
            is_active=True,
        )
        db.add(user)
        db.commit()
        print(f"Admin user created: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")


if __name__ == "__main__":
    main()
