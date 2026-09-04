import re

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import alerts, analysis, audit, auth, detections, network, system, users
from app.core.config import settings
from app.core.database import Base, engine
import app.models  # noqa: F401 - registers SQLAlchemy models before table creation

Base.metadata.create_all(bind=engine)

ALLOWED_ORIGINS = [
    settings.frontend_origin,
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://[::1]:5173",
]
ALLOWED_ORIGIN_RE = re.compile(
    r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$"
)

app = FastAPI(title="Sentinel API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_RE.pattern,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(system.router, prefix="/api")
app.include_router(analysis.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(detections.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(network.router, prefix="/api")
