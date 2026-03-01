from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.deps import get_db, get_current_user
from app.db.models import ApiKey, User
from app.security import generate_api_key, hash_api_key

router = APIRouter(prefix='/v1/keys', tags=['keys'])


class CreateKeyRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class KeyResponse(BaseModel):
    id: int
    name: str
    created_at: str
    is_active: bool
    key_prefix: str
    last4: str
    api_key: str | None = None


@router.get('', response_model=list[KeyResponse])
def list_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    keys = db.execute(select(ApiKey).where(ApiKey.user_id == user.id)).scalars().all()
    return [
        KeyResponse(
            id=k.id,
            name=k.name,
            created_at=k.created_at.isoformat(),
            is_active=k.is_active and not k.revoked_at,
            key_prefix=k.key_prefix,
            last4=k.last4,
        )
        for k in keys
    ]


@router.post('', response_model=KeyResponse)
def create_key(payload: CreateKeyRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    raw = generate_api_key()
    key_hash, prefix, last4 = hash_api_key(raw)
    key = ApiKey(user_id=user.id, name=payload.name, key_hash=key_hash, key_prefix=prefix, last4=last4, is_active=True)
    db.add(key)
    db.commit()
    db.refresh(key)
    return KeyResponse(
        id=key.id,
        name=key.name,
        created_at=key.created_at.isoformat(),
        is_active=True,
        key_prefix=prefix,
        last4=last4,
        api_key=raw,
    )


@router.post('/{key_id}/revoke')
def revoke_key(key_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    key = db.get(ApiKey, key_id)
    if not key or key.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Key not found')
    key.is_active = False
    key.revoked_at = key.revoked_at or key.created_at
    db.commit()
    return {'revoked': True}
