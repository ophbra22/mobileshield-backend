from __future__ import annotations

from datetime import UTC, datetime, timedelta
import socket
from typing import Any, Tuple

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import DomainReputationCache

BLOCKLISTED_DOMAINS = {
    'evil.com',
    'phishingsite.com',
    'malware.test',
}


def _fetch_domain_age_days(domain: str) -> int | None:
    """Best-effort WHOIS via public RDAP; returns age in days or None."""
    try:
        resp = requests.get(f'https://rdap.org/domain/{domain}', timeout=(2, 3))
        if not resp.ok:
            return None
        data = resp.json()
        events = data.get('events') or []
        created = None
        for ev in events:
            if ev.get('eventAction') in {'registration', 'creation'}:
                created = ev.get('eventDate')
                break
        if not created:
            return None
        created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
        return max((datetime.now(UTC) - created_dt).days, 0)
    except Exception:
        return None


def _dns_resolution_ok(domain: str) -> tuple[bool, bool]:
    """Return (resolved, nxdomain)."""
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo(domain, None)
        return True, False
    except socket.gaierror:
        return False, True
    except Exception:
        return False, False


def _ttl_for_reputation(rep: str) -> int:
    if rep in {'suspicious', 'malicious'}:
        return 24 * 3600
    if rep == 'benign':
        return 24 * 3600
    return 6 * 3600


def get_or_compute_domain_reputation(
    db: Session, domain: str
) -> Tuple[DomainReputationCache, dict[str, Any], int, list[str]]:
    if not domain:
        dummy = DomainReputationCache(
            domain='',
            checked_at=datetime.now(UTC),
            ttl_seconds=_ttl_for_reputation('unknown'),
            reputation='unknown',
            sources={},
            signals={},
            score_hint=0,
        )
        return dummy, {}, 0, []

    now = datetime.now(UTC)
    cached = db.execute(select(DomainReputationCache).where(DomainReputationCache.domain == domain)).scalar_one_or_none()
    if cached:
        expiry = cached.checked_at + timedelta(seconds=cached.ttl_seconds)
        if expiry > now:
            sources = cached.sources or {}
            return cached, cached.signals or {}, cached.score_hint or 0, sources.get('reasons', [])

    score_hint = 0
    reasons: list[str] = []
    signals: dict[str, Any] = {}
    reputation = 'unknown'
    sources: dict[str, Any] = {}

    # DNS
    resolved, nxdomain = _dns_resolution_ok(domain)
    signals['dns_resolved'] = resolved
    signals['dns_nxdomain'] = nxdomain
    if nxdomain:
        score_hint += 10
        reputation = 'suspicious'
        reasons.append('Domain does not resolve (NXDOMAIN).')

    # WHOIS age via RDAP
    age_days = _fetch_domain_age_days(domain)
    signals['domain_age_days'] = age_days
    if age_days is not None:
        if age_days < 30:
            score_hint += 25
            reasons.append('Domain is newly registered (<30 days).')
            reputation = 'suspicious'
        elif age_days < 90:
            score_hint += 10
            reasons.append('Domain is young (30-90 days).')
            reputation = 'suspicious'

    # Blocklist
    if domain in BLOCKLISTED_DOMAINS:
        score_hint += 35
        reputation = 'malicious'
        reasons.append('Domain appears on internal blocklist.')

    if reputation == 'unknown' and score_hint == 0 and resolved:
        reputation = 'benign'
    elif reputation == 'unknown' and score_hint > 0:
        reputation = 'suspicious'

    sources['reasons'] = reasons
    ttl_seconds = _ttl_for_reputation(reputation)

    if cached:
        cached.checked_at = now
        cached.ttl_seconds = ttl_seconds
        cached.reputation = reputation
        cached.sources = sources
        cached.signals = signals
        cached.score_hint = score_hint
    else:
        cached = DomainReputationCache(
            domain=domain,
            checked_at=now,
            ttl_seconds=ttl_seconds,
            reputation=reputation,
            sources=sources,
            signals=signals,
            score_hint=score_hint,
        )
        db.add(cached)
    db.commit()
    return cached, signals, score_hint, reasons
