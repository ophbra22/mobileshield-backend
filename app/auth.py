from datetime import UTC, datetime

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.deps import get_db
from app.db.models import ApiKey, ApiKeyUsage, RateLimitWindow, User
from app.settings import get_settings
from app.security import constant_time_compare, decode_jwt, hash_api_key


settings = get_settings()


def _enforce_rate_limit(db: Session, api_key: ApiKey) -> None:
    window_start = datetime.now(UTC).replace(second=0, microsecond=0)

    try:
        usage = db.execute(
            select(ApiKeyUsage)
            .where(ApiKeyUsage.api_key_id == api_key.id, ApiKeyUsage.window_start == window_start)
            .with_for_update()
        ).scalar_one_or_none()

        if usage is None:
            usage = ApiKeyUsage(api_key_id=api_key.id, window_start=window_start, count=1)
            db.add(usage)
            db.flush()
        else:
            usage.count += 1

        if usage.count > settings.rate_limit_per_minute:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail='Rate limit exceeded for this API key. Please retry next minute.',
            )
        db.commit()
    except IntegrityError:
        db.rollback()
        usage = db.execute(
            select(ApiKeyUsage)
            .where(ApiKeyUsage.api_key_id == api_key.id, ApiKeyUsage.window_start == window_start)
            .with_for_update()
        ).scalar_one()
        usage.count += 1
        if usage.count > settings.rate_limit_per_minute:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail='Rate limit exceeded for this API key. Please retry next minute.',
            )
        db.commit()


def require_api_key(x_api_key: str | None = Header(default=None, alias='X-API-Key'), db: Session = Depends(get_db)) -> ApiKey:
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Missing X-API-Key header.')

    api_key = db.execute(select(ApiKey).where(ApiKey.key_prefix == x_api_key[:8])).scalar_one_or_none()
    if not api_key or not api_key.is_active or api_key.revoked_at:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid API key.')
    key_hash_candidate, _, _ = hash_api_key(x_api_key)
    if not constant_time_compare(key_hash_candidate, api_key.key_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid API key.')

    _enforce_rate_limit(db, api_key)
    return api_key


def require_admin_token(x_admin_token: str | None = Header(default=None, alias='X-Admin-Token')) -> None:
    # Dev-only administrative endpoint. Replace with hardened IAM in production.
    if not settings.enable_admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Not found')
    if not settings.admin_token or x_admin_token != settings.admin_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Unauthorized')


def require_admin_ip_allowlist(request: Request) -> None:
    if not settings.enable_admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Not found')
    if settings.admin_allow_ips:
        allowed = {ip.strip() for ip in settings.admin_allow_ips.split(',') if ip.strip()}
        client_ip = (request.client.host if request.client else '') or ''
        if allowed and client_ip not in allowed:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Unauthorized')


def enforce_generic_rate_limit(db: Session, scope: str, identity: str, limit: int) -> None:
    window_start = datetime.now(UTC).replace(second=0, microsecond=0)
    window = (
        db.execute(
            select(RateLimitWindow).where(
                RateLimitWindow.scope == scope,
                RateLimitWindow.identity == identity,
                RateLimitWindow.window_start == window_start,
            ).with_for_update()
        ).scalar_one_or_none()
    )
    if window is None:
        window = RateLimitWindow(scope=scope, identity=identity, window_start=window_start, count=1)
        db.add(window)
    else:
        window.count += 1
    if window.count > limit:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail='Rate limit exceeded.')
    db.commit()


def resolve_identity(
    request: Request, db: Session
) -> tuple[User | None, ApiKey | None]:
    # Prefer API key
    api_key_header = request.headers.get('X-API-Key')
    if api_key_header:
        api_key = db.execute(select(ApiKey).where(ApiKey.key_prefix == api_key_header[:8])).scalar_one_or_none()
        if api_key and api_key.is_active and not api_key.revoked_at:
            key_hash_candidate, _, _ = hash_api_key(api_key_header)
            if constant_time_compare(key_hash_candidate, api_key.key_hash):
                _enforce_rate_limit(db, api_key)
                return None, api_key
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid API key.')
    # Else check JWT
    auth = request.headers.get('Authorization')
    if auth and auth.lower().startswith('bearer '):
        token = auth.split(' ', 1)[1]
        try:
            payload = decode_jwt(token)
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
        user_id = payload.get('sub')
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User not found')
        return user, None
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Missing credentials')
