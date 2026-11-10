from dataclasses import dataclass

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token, utcnow
from app.db.database import get_db
from app.models import Session, User


@dataclass
class AuthContext:
    user: User
    session: Session


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Cookie"},
    )


async def get_auth_context(
    parley_access: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> AuthContext:
    if not parley_access:
        raise _unauthorized()

    payload = decode_access_token(parley_access)
    if payload is None:
        raise _unauthorized()

    session = await db.get(Session, payload["sid"])
    if session is None or session.revoked or session.expires_at <= utcnow():
        raise _unauthorized()

    user = await db.get(User, payload["sub"])
    if user is None or session.user_id != user.id:
        raise _unauthorized()

    return AuthContext(user=user, session=session)


async def get_current_user(
    context: AuthContext = Depends(get_auth_context),
) -> User:
    return context.user
