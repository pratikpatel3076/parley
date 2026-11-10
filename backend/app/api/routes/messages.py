import base64
import binascii
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthContext, get_auth_context
from app.core.security import utcnow
from app.core.timeutils import iso_utc, to_naive_utc
from app.db.database import get_db
from app.models import Message, User
from app.schemas.message import MessageCreateRequest

router = APIRouter(prefix="/api/v1/messages", tags=["messages"])
PAGE_SIZE = 100


def _encode_cursor(message: Message) -> str:
    raw = f"{message.created_at.isoformat()}|{message.id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        created_at_text, message_id = raw.split("|", 1)
        created_at = datetime.fromisoformat(created_at_text)
        if created_at.tzinfo is not None:
            created_at = to_naive_utc(created_at)
        message_id = str(uuid.UUID(message_id))
    except (ValueError, UnicodeDecodeError, binascii.Error):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor",
        ) from None
    return created_at, message_id


def _apply_cursor(statement, after: str | None):
    if not after:
        return statement
    created_at, message_id = _decode_cursor(after)
    return statement.where(
        or_(
            Message.created_at > created_at,
            and_(
                Message.created_at == created_at,
                Message.id > message_id,
            ),
        )
    )


async def _usernames(db: AsyncSession, messages: list[Message]) -> dict[str, str]:
    ids = {message.sender_id for message in messages}
    ids.update(message.recipient_id for message in messages)
    if not ids:
        return {}
    rows = await db.execute(select(User.id, User.username).where(User.id.in_(ids)))
    return dict(rows.all())


def _message_payload(
    message: Message,
    usernames: dict[str, str],
) -> dict[str, object]:
    return {
        "id": message.id,
        "sender": usernames.get(message.sender_id, "unknown"),
        "recipient": usernames.get(message.recipient_id, "unknown"),
        "nonce": base64.b64encode(message.nonce).decode("ascii"),
        "ciphertext": base64.b64encode(message.ciphertext).decode("ascii"),
        "client_ts": iso_utc(message.client_ts),
        "created_at": iso_utc(message.created_at),
        "acked_at": iso_utc(message.acked_at) if message.acked_at else None,
    }


@router.post("", status_code=status.HTTP_201_CREATED)
async def send_message(
    payload: MessageCreateRequest,
    context: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    recipient = await db.scalar(
        select(User).where(User.username == payload.recipient)
    )
    if recipient is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found",
        )
    if recipient.id == context.user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot send a message to yourself",
        )

    message = Message(
        sender_id=context.user.id,
        recipient_id=recipient.id,
        nonce=base64.b64decode(payload.nonce, validate=True),
        ciphertext=base64.b64decode(payload.ciphertext, validate=True),
        client_ts=to_naive_utc(payload.client_ts),
    )
    db.add(message)
    await db.flush()
    await db.commit()

    return {"id": message.id, "created_at": iso_utc(message.created_at)}


@router.get("/inbox")
async def inbox(
    after: str | None = Query(default=None),
    context: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    statement = select(Message).where(
        Message.recipient_id == context.user.id
    )
    statement = _apply_cursor(statement, after)
    statement = statement.order_by(
        Message.created_at.asc(),
        Message.id.asc(),
    ).limit(PAGE_SIZE)
    messages = list((await db.scalars(statement)).all())
    usernames = await _usernames(db, messages)
    next_cursor = _encode_cursor(messages[-1]) if messages else after
    return {
        "messages": [
            _message_payload(message, usernames) for message in messages
        ],
        "next_cursor": next_cursor,
    }


@router.get("/sent")
async def sent(
    after: str | None = Query(default=None),
    context: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    statement = select(Message).where(Message.sender_id == context.user.id)
    statement = _apply_cursor(statement, after)
    statement = statement.order_by(
        Message.created_at.asc(),
        Message.id.asc(),
    ).limit(PAGE_SIZE)
    messages = list((await db.scalars(statement)).all())
    usernames = await _usernames(db, messages)
    next_cursor = _encode_cursor(messages[-1]) if messages else after
    return {
        "messages": [
            _message_payload(message, usernames) for message in messages
        ],
        "next_cursor": next_cursor,
    }


@router.post("/{message_id}/ack")
async def acknowledge_message(
    message_id: str,
    context: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str | None]:
    try:
        uuid.UUID(message_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        ) from None

    message = await db.get(Message, message_id)
    if message is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )
    if message.recipient_id != context.user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the recipient can acknowledge this message",
        )

    if message.acked_at is None:
        message.acked_at = utcnow()
        await db.commit()

    return {
        "id": message.id,
        "acked_at": iso_utc(message.acked_at) if message.acked_at else None,
    }
