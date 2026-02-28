from datetime import UTC, datetime

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.deps import get_db
from app.db.models import ApiKey, ApiKeyUsage
from app.settings import get_settings


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

    api_key = db.execute(select(ApiKey).where(ApiKey.key == x_api_key)).scalar_one_or_none()
    if api_key is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid API key.')
    if not api_key.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='API key is inactive.')

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
