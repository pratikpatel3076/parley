import uuid
from datetime import datetime

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from app.core.config import settings
from app.schemas.auth import decode_canonical_base64, validate_username


class MessageCreateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    recipient: str = Field(
        validation_alias=AliasChoices("recipient", "to")
    )
    client_message_id: str = Field(
        validation_alias=AliasChoices(
            "client_message_id",
            "clientMessageId",
        )
    )
    nonce: str
    ciphertext: str
    client_ts: datetime = Field(
        validation_alias=AliasChoices("client_ts", "clientTs")
    )

    @field_validator("recipient")
    @classmethod
    def check_recipient(cls, value: str) -> str:
        return validate_username(value)

    @field_validator("client_message_id")
    @classmethod
    def check_client_message_id(cls, value: str) -> str:
        try:
            parsed = uuid.UUID(value)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError(
                "client_message_id must be a UUIDv4 string"
            ) from exc
        if parsed.version != 4 or str(parsed) != value:
            raise ValueError(
                "client_message_id must be a canonical lowercase UUIDv4 string"
            )
        return value

    @field_validator("nonce")
    @classmethod
    def check_nonce(cls, value: str) -> str:
        decode_canonical_base64(value, field="nonce", exact_bytes=24)
        return value

    @field_validator("ciphertext")
    @classmethod
    def check_ciphertext(cls, value: str) -> str:
        decode_canonical_base64(
            value,
            field="ciphertext",
            max_bytes=settings.MAX_CIPHERTEXT_BYTES,
        )
        return value
