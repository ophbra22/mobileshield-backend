from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import os
import socket
import threading
from typing import Any, Tuple

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import DomainReputationCache
from app.settings import get_settings

settings = get_settings()

BLOCKLISTED_DOMAINS = {
    'evil.com',
    'phishingsite.com',
    'malware.test',
}

_ALLOWLIST_CACHE: set[str] = set()
_ALLOWLIST_META: dict[str, Any] = {}
_ALLOWLIST_LOCK = threading.Lock()


def _write_cache(domains: set[str]) -> None:
    if not settings.allowlist_cache_path:
        return
    try:
        with open(settings.allowlist_cache_path, 'w', encoding='utf-8') as f:
            for d in sorted(domains):
                f.write(d + '\n')
    except Exception:
        pass


def _load_cache_from_disk() -> set[str]:
    if not os.path.exists(settings.allowlist_cache_path):
        return set()
    try:
        with open(settings.allowlist_cache_path, 'r', encoding='utf-8') as f:
            lines = {line.strip().lower() for line in f if line.strip()}
        return lines
    except Exception:
        return set()


def _fetch_source_local_popular() -> set[str]:
    # minimal trusted list; can be extended
    return {'google.com', 'microsoft.com', 'apple.com', 'paypal.com', 'github.com', 'cloudflare.com'}


def _fetch_source_remote(url: str) -> set[str]:
    try:
        resp = requests.get(url, timeout=(3, 5))
        if not resp.ok or len(resp.content) > 500_000:
            return set()
        text = resp.text
        lines = [l.strip().lower() for l in text.splitlines() if l and not l.startswith('#')]
        domains = {l for l in lines if '.' in l and len(l) < 80}
        return set(list(domains)[:5000])
    except Exception:
        return set()


def refresh_allowlist_async() -> None:
    def worker():
        sources = [s.strip() for s in settings.allowlist_sources.split(',') if s.strip()]
        new_set: set[str] = set()
        for src in sources:
            if src == 'local_popular':
                new_set |= _fetch_source_local_popular()
            elif src.startswith('http'):
                new_set |= _fetch_source_remote(src)
            elif src == 'remote_popular':
                # placeholder remote url (can be updated)
                new_set |= _fetch_source_remote('https://raw.githubusercontent.com/psf/black/main/.gitignore')
        if new_set:
            _write_cache(new_set)
            with _ALLOWLIST_LOCK:
                _ALLOWLIST_CACHE.clear()
                _ALLOWLIST_CACHE.update(new_set)
                _ALLOWLIST_META['fetched_at'] = datetime.now(UTC)
                _ALLOWLIST_META['count'] = len(new_set)
                _ALLOWLIST_META['sha256'] = hashlib.sha256('\n'.join(sorted(new_set)).encode()).hexdigest()

    threading.Thread(target=worker, daemon=True).start()


def get_allowlist() -> set[str]:
    with _ALLOWLIST_LOCK:
        if _ALLOWLIST_CACHE:
            return set(_ALLOWLIST_CACHE)
    cache = _load_cache_from_disk()
    if cache:
        with _ALLOWLIST_LOCK:
            _ALLOWLIST_CACHE.update(cache)
    else:
        # initial minimal
        _ALLOWLIST_CACHE.update(_fetch_source_local_popular())
    return set(_ALLOWLIST_CACHE)


def allowlist_hit(domain: str) -> tuple[bool, str | None]:
    al = get_allowlist()
    if domain.lower() in al:
        return True, 'allowlist'
    return False, None


# Trigger background refresh after helpers are defined
if settings.allowlist_enabled:
    try:
        refresh_allowlist_async()
    except Exception:
        pass


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
