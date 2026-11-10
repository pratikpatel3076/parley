import base64
import binascii
import re

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

USERNAME_PATTERN = re.compile(r"^[a-z0-9_]{3,32}$")


def validate_username(value: str) -> str:
    if not USERNAME_PATTERN.fullmatch(value):
        raise ValueError(
            "username must be 3-32 lowercase ASCII characters matching "
            "^[a-z0-9_]{3,32}$"
        )
    return value


def decode_canonical_base64(
    value: str,
    *,
    field: str,
    exact_bytes: int | None = None,
    max_bytes: int | None = None,
) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} must be valid standard base64") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError(f"{field} must use canonical padded base64")
    if exact_bytes is not None and len(raw) != exact_bytes:
        raise ValueError(f"{field} must decode to exactly {exact_bytes} bytes")
    if max_bytes is not None and len(raw) > max_bytes:
        raise ValueError(f"{field} must decode to at most {max_bytes} bytes")
    return raw


class RegisterRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    username: str
    authSecret: str = Field(
        validation_alias=AliasChoices("authSecret", "auth_secret")
    )
    publicKey: str = Field(
        validation_alias=AliasChoices("publicKey", "public_key")
    )

    @field_validator("username")
    @classmethod
    def check_username(cls, value: str) -> str:
        return validate_username(value)

    @field_validator("authSecret")
    @classmethod
    def check_auth_secret(cls, value: str) -> str:
        decode_canonical_base64(value, field="authSecret", exact_bytes=32)
        return value

    @field_validator("publicKey")
    @classmethod
    def check_public_key(cls, value: str) -> str:
        decode_canonical_base64(value, field="publicKey", exact_bytes=32)
        return value


class LoginRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    username: str
    authSecret: str = Field(
        validation_alias=AliasChoices("authSecret", "auth_secret")
    )

    @field_validator("username")
    @classmethod
    def check_username(cls, value: str) -> str:
        return validate_username(value)

    @field_validator("authSecret")
    @classmethod
    def check_auth_secret(cls, value: str) -> str:
        decode_canonical_base64(value, field="authSecret", exact_bytes=32)
        return value
