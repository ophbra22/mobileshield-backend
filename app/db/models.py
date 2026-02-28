from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


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


class ApiKey(Base):
    __tablename__ = 'api_keys'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default='true')

    usage: Mapped[list['ApiKeyUsage']] = relationship(back_populates='api_key', cascade='all, delete-orphan')


class ApiKeyUsage(Base):
    __tablename__ = 'api_key_usage'
    __table_args__ = (UniqueConstraint('api_key_id', 'window_start', name='uq_api_key_window_start'),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_key_id: Mapped[int] = mapped_column(ForeignKey('api_keys.id', ondelete='CASCADE'), nullable=False, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    api_key: Mapped[ApiKey] = relationship(back_populates='usage')


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
