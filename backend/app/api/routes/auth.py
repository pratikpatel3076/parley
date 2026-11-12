import base64
from datetime import datetime, timedelta

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rate_limit import login_limiter, register_limiter
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    dummy_auth_hash,
    hash_auth_secret,
    hash_refresh_token,
    utcnow,
    verify_auth_secret,
)
from app.core.timeutils import iso_utc
from app.db.database import get_db
from app.models import Session, User
from app.schemas.auth import LoginRequest, RegisterRequest

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

ACCESS_COOKIE_PATH = "/"
REFRESH_COOKIE_PATH = "/api/v1/auth"
# No Domain attribute is set, so both cookies are host-only. The delete path
# must mirror every attribute used when setting, or browsers keep the cookie.
COOKIE_DOMAIN: str | None = None


def _cookie_options(path: str) -> dict[str, object]:
    return {
        "path": path,
        "domain": COOKIE_DOMAIN,
        "secure": settings.COOKIE_SECURE,
        "httponly": True,
        "samesite": "lax",
    }


def _client_key(request: Request, scope: str) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{scope}:{host}"


def _enforce_rate_limit(limiter, key: str) -> None:
    if not limiter.allow(key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
            headers={
                "Retry-After": str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
            },
        )


def _user_payload(user: User) -> dict[str, str]:
    return {
        "id": user.id,
        "username": user.username,
        "public_key": base64.b64encode(user.public_key).decode("ascii"),
        "created_at": iso_utc(user.created_at),
    }


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
) -> None:
    response.set_cookie(
        "parley_access",
        access_token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        **_cookie_options(ACCESS_COOKIE_PATH),
    )
    # Path=/api/v1/auth covers both /refresh and /logout.
    response.set_cookie(
        "parley_refresh",
        refresh_token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86_400,
        **_cookie_options(REFRESH_COOKIE_PATH),
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(
        "parley_access",
        **_cookie_options(ACCESS_COOKIE_PATH),
    )
    response.delete_cookie(
        "parley_refresh",
        **_cookie_options(REFRESH_COOKIE_PATH),
    )


def _new_session(user_id: str) -> tuple[Session, str]:
    raw_refresh = create_refresh_token()
    session = Session(
        user_id=user_id,
        refresh_token_hash=hash_refresh_token(raw_refresh),
        expires_at=utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    return session, raw_refresh


def _reject_refresh(*, clear_cookies: bool) -> Response:
    """Return a uniform 401, clearing cookies unless a peer may hold new ones."""
    rejected = JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": "Invalid refresh token"},
    )
    if clear_cookies:
        _clear_auth_cookies(rejected)
    return rejected


def _within_reuse_grace(session: Session, *, now: datetime) -> bool:
    if session.revoked_reason != "rotated" or session.rotated_at is None:
        return False
    return now - session.rotated_at <= timedelta(
        seconds=settings.REFRESH_REUSE_GRACE_SECONDS
    )


async def _reject_revoked_session(
    db: AsyncSession,
    session: Session,
    *,
    now: datetime,
) -> Response:
    """Apply the revoked-session rules for a presented refresh token.

    A rotated token replayed inside the grace window is assumed to be a
    concurrent request from another tab: reject it, revoke nothing, and leave
    cookies alone because the browser may already hold the replacement pair.
    Outside the window it is a theft signal, so every live session is revoked.
    """
    if _within_reuse_grace(session, now=now):
        return _reject_refresh(clear_cookies=False)

    if session.revoked_reason == "rotated" and session.rotated_at is not None:
        await db.execute(
            update(Session)
            .where(
                Session.user_id == session.user_id,
                Session.revoked.is_(False),
            )
            .values(revoked=True, revoked_reason="reuse_detected")
        )
        await db.commit()

    return _reject_refresh(clear_cookies=True)


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict[str, dict[str, str]]:
    _enforce_rate_limit(register_limiter, _client_key(request, "register"))

    existing = await db.scalar(select(User).where(User.username == payload.username))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username is already taken",
        )

    user = User(
        username=payload.username,
        auth_hash=hash_auth_secret(payload.authSecret),
        public_key=base64.b64decode(payload.publicKey, validate=True),
    )
    db.add(user)
    try:
        await db.flush()
        session, raw_refresh = _new_session(user.id)
        db.add(session)
        await db.flush()
        access_token = create_access_token(user.id, session.id)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username is already taken",
        ) from None

    _set_auth_cookies(response, access_token, raw_refresh)
    return {"user": _user_payload(user)}


@router.post("/login")
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict[str, dict[str, str]]:
    _enforce_rate_limit(login_limiter, _client_key(request, "login"))

    user = await db.scalar(select(User).where(User.username == payload.username))
    stored_hash = user.auth_hash if user is not None else dummy_auth_hash()
    secret_ok = verify_auth_secret(payload.authSecret, stored_hash)
    if user is None or not secret_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    session, raw_refresh = _new_session(user.id)
    db.add(session)
    await db.flush()
    access_token = create_access_token(user.id, session.id)
    await db.commit()

    _set_auth_cookies(response, access_token, raw_refresh)
    return {"user": _user_payload(user)}


@router.post("/refresh", response_model=None)
async def refresh(
    response: Response,
    parley_refresh: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> Response | dict[str, str]:
    if not parley_refresh:
        return _reject_refresh(clear_cookies=True)

    token_hash = hash_refresh_token(parley_refresh)
    session = await db.scalar(
        select(Session).where(Session.refresh_token_hash == token_hash)
    )
    if session is None:
        return _reject_refresh(clear_cookies=True)

    session_id = session.id
    session_user_id = session.user_id

    now = utcnow()
    if session.revoked:
        return await _reject_revoked_session(db, session, now=now)

    if session.expires_at <= now:
        session.revoked = True
        session.revoked_reason = "expired"
        await db.commit()
        return _reject_refresh(clear_cookies=True)

    user = await db.get(User, session_user_id)
    if user is None:
        session.revoked = True
        session.revoked_reason = "user_deleted"
        await db.commit()
        return _reject_refresh(clear_cookies=True)

    # Single-use rotation. Only one concurrent request can flip revoked 0 -> 1;
    # every other request re-reads the row and follows the reuse rules above.
    rotated = await db.execute(
        update(Session)
        .where(Session.id == session_id, Session.revoked.is_(False))
        .values(
            revoked=True,
            revoked_reason="rotated",
            rotated_at=now,
        )
    )
    if rotated.rowcount != 1:
        await db.rollback()
        current = await db.get(Session, session_id)
        if current is None:
            return _reject_refresh(clear_cookies=True)
        return await _reject_revoked_session(db, current, now=now)

    new_session, raw_refresh = _new_session(user.id)
    db.add(new_session)
    await db.flush()
    access_token = create_access_token(user.id, new_session.id)
    await db.commit()

    _set_auth_cookies(response, access_token, raw_refresh)
    return {"status": "ok"}


@router.post("/logout")
async def logout(
    response: Response,
    parley_access: str | None = Cookie(default=None),
    parley_refresh: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Revoke what we can, clear both cookies, and never require a session.

    Logout is idempotent: callers with no cookies, an expired access token, or
    only a refresh cookie still get 200. A valid access token and a valid
    refresh token are each resolved independently, so a refresh session is
    revoked even when the access cookie is missing or expired.
    """
    revoked = False

    if parley_access:
        payload = decode_access_token(parley_access)
        if payload is not None:
            session = await db.get(Session, payload["sid"])
            if session is not None and not session.revoked:
                session.revoked = True
                session.revoked_reason = "logout"
                revoked = True

    if parley_refresh:
        stored = await db.scalar(
            select(Session).where(
                Session.refresh_token_hash == hash_refresh_token(parley_refresh)
            )
        )
        if stored is not None and not stored.revoked:
            stored.revoked = True
            stored.revoked_reason = "logout"
            revoked = True

    if revoked:
        await db.commit()
    _clear_auth_cookies(response)
    return {"status": "ok"}
