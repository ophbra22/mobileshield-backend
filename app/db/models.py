from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class User(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    api_keys: Mapped[list['ApiKey']] = relationship(back_populates='user', cascade='all, delete-orphan')
    scans: Mapped[list['Scan']] = relationship(back_populates='user')


class Scan(Base):
    __tablename__ = 'scans'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    normalized_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    final_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    signals: Mapped[dict] = mapped_column(JSON, nullable=False)
    breakdown: Mapped[list[dict]] = mapped_column(JSON, nullable=False, server_default='[]')
    reputation: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reputation_score_hint: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True, index=True)
    api_key_id: Mapped[int | None] = mapped_column(ForeignKey('api_keys.id'), nullable=True, index=True)

    user: Mapped['User | None'] = relationship(back_populates='scans')
    api_key: Mapped['ApiKey | None'] = relationship(back_populates='scans')


class ApiKey(Base):
    __tablename__ = 'api_keys'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    last4: Mapped[str] = mapped_column(String(4), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default='true')
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User | None] = relationship(back_populates='api_keys')
    usage: Mapped[list['ApiKeyUsage']] = relationship(back_populates='api_key', cascade='all, delete-orphan')
    scans: Mapped[list['Scan']] = relationship(back_populates='api_key')


class ApiKeyUsage(Base):
    __tablename__ = 'api_key_usage'
    __table_args__ = (UniqueConstraint('api_key_id', 'window_start', name='uq_api_key_window_start'),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_key_id: Mapped[int] = mapped_column(ForeignKey('api_keys.id', ondelete='CASCADE'), nullable=False, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    api_key: Mapped[ApiKey] = relationship(back_populates='usage')


class RateLimitWindow(Base):
    __tablename__ = 'rate_limit_windows'
    __table_args__ = (UniqueConstraint('scope', 'identity', 'window_start', name='uq_scope_identity_window'),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String(64), nullable=False)
    identity: Mapped[str] = mapped_column(String(255), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class DomainReputationCache(Base):
    __tablename__ = 'domain_reputation_cache'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    reputation: Mapped[str] = mapped_column(String(32), nullable=False, default='unknown')
    sources: Mapped[dict] = mapped_column(JSON, nullable=False)
    signals: Mapped[dict] = mapped_column(JSON, nullable=False)
    score_hint: Mapped[int | None] = mapped_column(Integer, nullable=True)
