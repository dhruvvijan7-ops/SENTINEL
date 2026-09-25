# Sentinel Authentication & Session Hardening

**Task:** replace the dev-grade authentication stack (60-min bearer JWT in `localStorage`, shared reset-token format logged in plaintext, no revocation, no rate limiting, hardcoded secret fallback) with a production-grade, cookie-based session architecture: short-lived signed access JWT + rotating opaque refresh cookie, server-side session revocation, separated hashed reset credential, strict fail-fast configuration, per-endpoint rate limiting, and generic error messaging — proven by an expanding test suite and a live-server smoke run.

**Date:** 2026-09-25

---

## 1. Files changed

### New
- `backend/app/core/config.py` — rewritten `Settings` + `_validate_or_fail` (full field list, environment-specific fail-fast, ephemeral-secret dev fallback). (File existed; effectively new.)
- `backend/app/models/session.py` — `AuthSession` (family-based session/session-family rows).
- `backend/app/models/password_reset.py` — `PasswordResetToken` (SHA-256 hash of opaque token).
- `backend/app/services/sessions.py` — create/deactivate/touch/find-active/rotate; family-revocation on replay; `deactivate_all_for_user`.
- `backend/app/services/password_reset.py` — opaque `secrets.token_urlsafe(48)` + SHA-256 hashing + `hmac.compare_digest` verification.
- `backend/app/services/rate_limit.py` — in-process sliding-window limiter (key → deque of timestamps), threshold+window config.
- `backend/app/api/deps.py` — `get_current_user` (PyJWT strict decode), `get_optional_current_user`, `require_client_header` (CSRF), role guards.
- `backend/app/middleware/client_header.py` — `X-Sentinel-Client` enforcement on mutating methods with per-path/prefix exemptions (docs, health, static, create_all self-check).
- `backend/alembic/versions/aa0000000001_add_auth_sessions_and_password_reset_tokens.py` — migration (rebased onto `a7f6e5d4c3b2`).
- `backend/.env.example` — rewritten with every new setting documented.
- `frontend/src/features/auth/pages/ResetPasswordPage.tsx` — `?token=` flow, 8-char minimum, success/invalid states.

### Changed
- `backend/requirements.txt` — `python-jose[cryptography]` removed; `PyJWT>=2.10,<3.0` added.
- `backend/app/api/routes/auth.py` — register/login/logout/me/refresh/forgot-password/reset-password rebuilt on sessions + refresh rotation + rate limits + generic errors; `MessageResponse` / `ForgotPasswordResponse` split (only forgot exposes `debug_reset_token`).
- `backend/app/core/database.py` — main app now uses Alembic migrations; `create_all` is test-only (`TESTING` guard).
- `backend/app/core/security.py` / `backend/app/services/auth.py` — PyJWT create/decode with strict claims; opaque-token hashing helpers; `dummy_bcrypt_check()` timing equalization.
- `backend/tests/conftest.py` — hardened test settings (strong secret, `DEBUG_RESET_RETURNS_TOKEN=true`, per-test `limiter.reset()`), `client`/`analyst_client`/`unauth_client`.
- `backend/tests/test_auth.py` — rewritten to the real cookie flow (~40 tests).
- `backend/tests/test_audit.py` — added session/refresh/reset audit assertions.
- `backend/tests/test_config.py` — new `TestConfigFailFast` (production secret/origin/cookie/debug-guard matrix).
- `frontend/src/services/apiClient.ts` — `credentials:"include"`, `http://localhost:8000`, no `Authorization` header, 401 → one silent refresh retry → redirect `/login`.
- `frontend/src/store/authStore.ts` — token removed; user-only state + `isInitialized` bootstrap flag.
- `frontend/src/components/AuthInitializer.tsx` — silent `/me` restore on load.
- `frontend/src/services/authService.ts`, `frontend/src/types/auth.ts` — `/me` → `User`; response shape `{user, message}`.
- `frontend/src/features/auth/pages/{LoginPage,RegisterPage}.tsx` — cookie session; registered → login banner.
- `frontend/src/routes/paths.ts`, `frontend/src/app/router/AppRouter.tsx` — `/reset-password` route.
- `frontend/src/app/router/{ProtectedRoute,AdminRoute,AuditRoute}.tsx` — wait for `isInitialized` before redirect.

## 2. Previous behavior (what was replaced)

`backend/app/api/routes/auth.py` and `backend/app/services/auth.py` issued a single JWT signed with `JWT_SECRET_KEY` defaulting to `"dev-secret-change-in-production"` (config fallback, so a misconfigured deployment silently ran on a public secret). Tokens carried only `sub`/`exp`, lived 60 minutes, were returned in every auth response body and stored in `localStorage` — any XSS read them. Logout only cleared the frontend state; the server token stayed valid. The password-reset link reused `create_access_token(user.id)` — a reset token *was* a valid session token — and was logged in plaintext at INFO. No rate limiting existed on any auth endpoint; login/forgot/reset errors leaked account-existence specifics.

## 3. New behavior

- Login/register/refresh/logout/reset all negotiate **HttpOnly cookies** (`sentinel_access` Path `/api`, `sentinel_refresh` Path `/api/auth`). No token ever appears in the DOM, JS, or response bodies.
- **Access JWT**: PyJWT HS256, 15 min, claims `sub/jti/iss/aud/iat/nbf/exp/typ/` + `sid`, strict decode (algorithm pinning, required claims, issuer/audience). Served only as a cookie; never in JSON.
- **Refresh**: 256-bit opaque `secrets.token_urlsafe(48)` stored SHA-256-hashed, compared with `hmac.compare_digest`. Rotation on every refresh: old consumed, new issued. Replay of a consumed refresh revokes the entire `session_family` (audit `REFRESH_TOKEN_REUSED`); the family refuses further refresh even with the newer token.
- **Sessions**: `auth_sessions` rows keyed by `sid`; server-side logout, session touch (`last_used_at`), idle-based active-session checks (`find_active_session_by_id` enforces expiry in Python after fetching). Password change or reset revokes all of a user's sessions and families.
- **Client-CSRF header**: required on all mutating requests (tautological-cookie CSRF defense in depth with SameSite=Lax). Missing/wrong → 403.
- **Password reset**: opaque token, purpose-separated from access JWTs, 30 min, single use. `debug_reset_token` returned only for existing accounts **and** only when `DEBUG_RESET_RETURNS_TOKEN=true` (forbidden in production). Generic message for both unknown and known accounts; login/forgot/reset use equal-shaped generic responses; timing equalized with a dummy bcrypt check.
- **Rate limiting** (per-process, sliding window): login 5/60s per IP + 10/15min per account; register 3/h per IP; forgot 5/10min per IP + 3/h per account; reset 5/15min per IP; refresh 20/5min per IP.

## 4. Configuration hardening (`config.py`)

Shared invariants (all environments): secret ≥32 bytes, `JWT_ALGORITHM` ∈ {HS256}, access ≥5 min, refresh ≥1 day, reset ≥5 min, samesite ∈ {lax,strict,none}, samesite=none ⇒ secure. `production` additionally requires: secret ≠ default, `FRONTEND_ORIGIN` set, `AUTH_COOKIE_SECURE=true`, `DEBUG_RESET_RETURNS_TOKEN=false`. Development with no secret generates an ephemeral one (with a warning). Unknown `SENTINEL_ENV` raises.

## 5. Database & migrations

`alembic upgrade head` applies `e1f2a3b4c5d6 → f1f2f3f4f5f6 → a7f6e5d4c3b2 → aa0000000001` (single head). New tables: `auth_sessions`, `password_reset_tokens`. Note: `f1f2f3f4f5f6` is a branchpoint whose pre-existing pending sibling `a7f6e5d4c3b2` (dynamic rules/risk metadata) is now correctly in the chain — the new migration was rebased onto it. Applied to the dev Postgres container.

## 6. Frontend changes

`apiClient` always sends `X-Sentinel-Client`, uses `credentials:"include"`, and treats a 401 as: one silent refresh attempt → retry original → else redirect to `/login`. `AuthInitializer` restores the user via `/me` before any guarded route renders. Guards no longer redirect on first paint; they wait for `isInitialized`. `pnpm build` passes; `pnpm lint` shows only the 5 pre-existing baseline errors (AuditLogsPage, UsersPage, InvestigationPage, NetworkPage×2) — none from changed files.

## 7. Test coverage

- `backend/tests/test_auth.py` — login success/failure/rate-limit, cookie attributes, me/logout, refresh rotation + family revocation + replay, header guard (403), JWT claim strictness (`typ`, `jti`, `sid`, issuer/audience, signature), password-reset single-use + session revocation + debug-token gating + reject-JWT-as-reset, register no-auto-login.
- New `TestConfigFailFast` — production matrix (default secret, missing secret, secure-cookie, debug-guard).
- `test_audit.py` — `LOGIN_SUCCESS`, `LOGOUT`, `REFRESH_TOKEN_REUSED`, `PASSWORD_RESET_*` events asserted.
- Result: **328 passed** in the full backend suite (39 auth + 94 auth+audit run surface, plus the prior 289).

## 8. Live smoke evidence (127.0.0.1:8000, dev Postgres)

- Login → `{user, message}` (no token field); `sentinel_access`/`sentinel_refresh` are HttpOnly with paths `/api` and `/api/auth`.
- `/me` with session; decoded access claims include `jti/iss/aud/iat/nbf/exp/typ/sid`.
- PATCH settings without header → 403 "Missing or invalid client header."; with header → 200.
- Logout → 200, subsequent `/me` → 401.
- Refresh rotation: new refresh differs; replaying the old → 401 and the whole family (including the newest) → 401.
- Forgot → generic message; `debug_reset_token` present in dev; used once → reset succeeds, old password 401, new password works.

## 9. §47 finding resolution (old → new)

| Finding | Old | New |
|---|---|---|
| P0-1 JWT secret management | `os.getenv("JWT_SECRET_KEY","dev-secret-change-in-production")` fallback | Fail fast (<32B, unknown env, default-in-prod); production requires explicit strong secret; dev ephemeral fallback |
| P0-2 Rate limiting | none on auth endpoints | per-IP + per-account sliding-window limits on login/register/forgot/reset/refresh |
| P0-3 Reset token security | reset token = access JWT, 60 min, logged INFO | purpose-separated opaque token, SHA-256-stored, 30 min, single use, generic messages, timing equalization |
| P0-6 CORS hardening | broad CORS | tightened CORS (credentials), SameSite=Lax cookies, required `X-Sentinel-Client` header on mutations |
| P0-12 Environment validation | only `SENTINEL_ENV` read | full fail-fast matrix incl. SENTINEL_ENV whitelist |
| Auth storage (§7 / audit finding "JWT stored in localStorage") | token in `localStorage`, sent as Bearer | HttpOnly cookies only; `{user,message}` responses; silent refresh; init-time `/me` restore |
| No refresh/revocation (§"60 min tokens, no revocation") | one 60-min token, logout client-side only | 15-min access + rotating opaque refresh; server-side `auth_sessions`; family revocation on replay; logout revokes server-side |
| Weak JWT claims (§"no jti, iss, aud") | `sub`/`exp` only, python-jose loose decode | PyJWT strict decode: `jti`, `sid`, `iss`, `aud`, `typ`, alg pinning, all required claims |
| Hardcoded reset-password logging (line 204) | reset token logged in plaintext | no token logging anywhere; hashed storage; audit records event type + user only |

## 10. Residual notes / follow-ups (out of scope here)

- Rate limiter is in-process; a multi-worker deployment needs a shared store (Redis) — config class left list-backed for that swap.
- `seed_admin.py` default password (P0-14) not in the auth-session scope; unchanged.
- Production cookie directives remain config-driven (`AUTH_COOKIE_SECURE` enforced true in production).