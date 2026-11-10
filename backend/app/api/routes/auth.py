import base64
from datetime import timedelta

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthContext, get_auth_context
from app.core.config import settings
from app.core.rate_limit import login_limiter, register_limiter
from app.core.security import (
    create_access_token,
    create_refresh_token,
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
        path="/",
        secure=settings.COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )
    response.set_cookie(
        "parley_refresh",
        refresh_token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86_400,
        path="/api/v1/auth",
        secure=settings.COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(
        "parley_access",
        path="/",
        secure=settings.COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )
    response.delete_cookie(
        "parley_refresh",
        path="/api/v1/auth",
        secure=settings.COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )


def _new_session(user_id: str) -> tuple[Session, str]:
    raw_refresh = create_refresh_token()
    session = Session(
        user_id=user_id,
        refresh_token_hash=hash_refresh_token(raw_refresh),
        expires_at=utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    return session, raw_refresh


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


@router.post("/refresh")
async def refresh(
    response: Response,
    parley_refresh: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    if not parley_refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    token_hash = hash_refresh_token(parley_refresh)
    session = await db.scalar(
        select(Session).where(Session.refresh_token_hash == token_hash)
    )
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if session.revoked:
        # A rotated token came back. Treat it as a theft signal and revoke every
        # session for this user, including the current replacement.
        await db.execute(
            update(Session)
            .where(Session.user_id == session.user_id)
            .values(revoked=True)
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if session.expires_at <= utcnow():
        session.revoked = True
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user = await db.get(User, session.user_id)
    if user is None:
        session.revoked = True
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    session.revoked = True
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
    context: AuthContext = Depends(get_auth_context),
    parley_refresh: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    context.session.revoked = True
    if parley_refresh:
        stored = await db.scalar(
            select(Session).where(
                Session.refresh_token_hash == hash_refresh_token(parley_refresh)
            )
        )
        if stored is not None:
            stored.revoked = True
    await db.commit()
    _clear_auth_cookies(response)
    return {"status": "ok"}
