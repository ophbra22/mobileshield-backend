from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.deps import get_db, get_current_user
from app.db.models import ApiKey, User
from app.security import (
    PASSWORD_TOO_LONG_MSG,
    create_jwt,
    generate_api_key,
    hash_api_key,
    hash_password,
    validate_password_for_bcrypt,
    verify_password,
)
from app.auth import enforce_generic_rate_limit
from app.settings import get_settings

settings = get_settings()

router = APIRouter(prefix='/v1/auth', tags=['auth'])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)

    @classmethod
    def model_validate(cls, value):
        obj = super().model_validate(value)
        byte_len = len(obj.password.encode('utf-8'))
        if byte_len < 8:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Password too short (minimum 8 characters).')
        if byte_len > 72:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=PASSWORD_TOO_LONG_MSG)
        return obj


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)

    @classmethod
    def model_validate(cls, value):
        obj = super().model_validate(value)
        byte_len = len(obj.password.encode('utf-8'))
        if byte_len < 8:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Password too short (minimum 8 characters).')
        if byte_len > 72:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=PASSWORD_TOO_LONG_MSG)
        return obj


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'
    user: dict
    api_key: str | None = None


def _create_default_key(db: Session, user: User) -> str:
    raw = generate_api_key()
    key_hash, prefix, last4 = hash_api_key(raw)
    api_key = ApiKey(user_id=user.id, name='default', key_hash=key_hash, key_prefix=prefix, last4=last4, is_active=True)
    db.add(api_key)
    db.commit()
    return raw


@router.post('/register', response_model=AuthResponse)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    enforce_generic_rate_limit(db, 'auth_register', request.client.host if request.client else 'unknown', 10)
    existing = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Email already registered')
    try:
        # validate explicitly to give clear feedback before hashing
        validate_password_for_bcrypt(payload.password)
        password_hash = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    user = User(email=payload.email.lower(), password_hash=password_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    raw_key = _create_default_key(db, user)
    token = create_jwt({'sub': user.id})
    return AuthResponse(access_token=token, user={'id': user.id, 'email': user.email}, api_key=raw_key)


@router.post('/login', response_model=AuthResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    enforce_generic_rate_limit(db, 'auth_login', request.client.host if request.client else 'unknown', 10)
    user = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid credentials')
    try:
        valid = verify_password(payload.password, user.password_hash)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid credentials')
    token = create_jwt({'sub': user.id})
    return AuthResponse(access_token=token, user={'id': user.id, 'email': user.email}, api_key=None)


@router.get('/me')
def me(user: User = Depends(get_current_user)):
    return {'id': user.id, 'email': user.email}
