import re

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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

ALLOWED_METHODS = ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"]
ALLOWED_HEADERS = ["Content-Type", "Authorization", "X-Sentinel-Client", "Accept"]
EXPOSE_HEADERS = ["Content-Type", "Content-Length"]

app = FastAPI(title="Sentinel API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_RE.pattern,
    allow_credentials=True,
    allow_methods=ALLOWED_METHODS,
    allow_headers=ALLOWED_HEADERS,
    expose_headers=EXPOSE_HEADERS,
)


@app.middleware("http")
async def session_cookie_guard(request: Request, call_next):
    """CSRF defense-in-depth for cookie-authenticated API requests.

    Requests that carry a Sentinel session cookie and mutate server state must
    also present the application's custom client header. Browsers cannot attach
    arbitrary headers on cross-site requests without a CORS-approved preflight,
    so this (combined with SameSite=Lax) blocks cross-site form/fetch abuse.
    Read-only GET/HEAD/OPTIONS requests are not subject to the header check:
    SameSite=Lax prevents cross-site attachment except on top-level GET
    navigations, whose responses cannot be read cross-origin.
    """
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return await call_next(request)

    cookies = request.cookies
    has_session_cookie = (
        settings.cookie_access_name in cookies
        or settings.cookie_refresh_name in cookies
    )
    if has_session_cookie and request.url.path.startswith("/api"):
        if request.headers.get(settings.client_header_name) != settings.client_header_value:
            return JSONResponse(
                status_code=403,
                content={"detail": "Missing or invalid client header."},
            )
    return await call_next(request)


app.include_router(auth.router, prefix="/api")
app.include_router(system.router, prefix="/api")
app.include_router(analysis.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(detections.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(network.router, prefix="/api")
