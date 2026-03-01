import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

from fastapi import HTTPException, status
from jose import JWTError, jwt
from passlib.hash import bcrypt

from app.settings import get_settings

settings = get_settings()
PASSWORD_TOO_LONG_MSG = "Password too long (bcrypt limit is 72 bytes). Use a shorter password."


def validate_password_for_bcrypt(password: str) -> bytes:
    """
    Validate password length for bcrypt (max 72 bytes when UTF-8 encoded).
    Returns the raw UTF-8 bytes if valid, otherwise raises ValueError.
    """
    raw = password.encode("utf-8")
    length = len(raw)
    if length == 0:
        raise ValueError("Password must not be empty")
    if length > 72:
        raise ValueError(PASSWORD_TOO_LONG_MSG)
    return raw


def hash_password(password: str) -> str:
    raw = validate_password_for_bcrypt(password)
    return bcrypt.hash(raw)


def verify_password(password: str, password_hash: str) -> bool:
    raw = validate_password_for_bcrypt(password)
    return bcrypt.verify(raw, password_hash)


def create_jwt(payload: dict[str, Any]) -> str:
    to_encode = payload.copy()
    expire_minutes = settings.jwt_expires_minutes
    exp = datetime.now(UTC) + timedelta(minutes=expire_minutes)
    to_encode.update({'exp': exp})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm='HS256')


def decode_jwt(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.jwt_secret, algorithms=['HS256'])


def hash_api_key(raw_key: str) -> tuple[str, str, str]:
    """Return (hash, prefix, last4). Hash uses HMAC-SHA256 with SERVER_KEY."""
    server_key = settings.server_key.encode()
    digest = hmac.new(server_key, raw_key.encode(), hashlib.sha256).hexdigest()
    prefix = raw_key[:8]
    last4 = raw_key[-4:]
    return digest, prefix, last4


def generate_api_key() -> str:
    return f"ms_live_{secrets.token_urlsafe(32)}"


def constant_time_compare(val1: str, val2: str) -> bool:
    return hmac.compare_digest(val1, val2)
