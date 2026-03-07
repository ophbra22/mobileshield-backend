from __future__ import annotations

from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests

from app.detection.config import DEFAULT_CONFIG
from app.detection.models import RedirectHop, RedirectResult, URLParts

NETWORK_TIMEOUT = (3, 5)


def _resolve_dns(hostname: str) -> tuple[Optional[str], Optional[str]]:
    import socket

    try:
        info = socket.getaddrinfo(hostname, None)
        if not info:
            return None, None
        family = info[0][0]
        ip = info[0][4][0]
        version = 'ipv6' if family == socket.AF_INET6 else 'ipv4'
        return ip, version
    except Exception:
        return None, None


def follow_redirects(url: str, parts: URLParts, max_hops: int = 6, config=DEFAULT_CONFIG) -> RedirectResult:
    chain: List[RedirectHop] = []
    final_url = url
    final_status: Optional[int] = None
    error: Optional[str] = None
    ssrf_blocked = False
    ssrf_reason: Optional[str] = None
    content_type: Optional[str] = None
    dns_ip: Optional[str] = None
    dns_ip_version: Optional[str] = None

    with requests.Session() as session:
        headers = {'User-Agent': 'MobileShieldAI/1.0'}
        current = url
        for hop in range(max_hops + 1):
            parsed = urlparse(current)
            hostname = (parsed.hostname or '').lower().rstrip('.')
            if not hostname:
                error = 'missing hostname'
                break

            ip, ip_version = _resolve_dns(hostname)
            if hop == 0:
                dns_ip, dns_ip_version = ip, ip_version

            chain.append(RedirectHop(url=current, status=None, ip=ip, ip_version=ip_version))

            try:
                resp = session.head(current, allow_redirects=False, timeout=NETWORK_TIMEOUT, headers=headers)
                if resp.status_code >= 400 or resp.status_code in (405, 403):
                    resp = session.get(current, allow_redirects=False, timeout=NETWORK_TIMEOUT, headers=headers, stream=True)
            except requests.RequestException as exc:
                error = str(exc)
                break

            status = resp.status_code
            content_type = resp.headers.get('Content-Type', '').split(';')[0].lower() or None
            chain[-1].status = status

            if status in (301, 302, 303, 307, 308) and 'Location' in resp.headers and hop < max_hops:
                next_url = urljoin(current, resp.headers['Location'])
                if next_url == current:
                    final_url = current
                    final_status = status
                    break
                current = next_url
                continue

            final_url = resp.url
            final_status = status
            break

    import tldextract

    final_parts = urlparse(final_url)
    final_registrable = tldextract.extract(final_parts.hostname or '').registered_domain or (final_parts.hostname or '')
    domain_changed = parts.registrable_domain != final_registrable and bool(final_registrable)

    return RedirectResult(
        final_url=final_url,
        final_status=final_status,
        redirect_hops=max(len(chain) - 1, 0),
        chain=chain,
        domain_changed=domain_changed,
        used_shortener=parts.registrable_domain in config.shortener_domains,
        error=error,
        ssrf_blocked=ssrf_blocked,
        ssrf_reason=ssrf_reason,
        content_type=content_type,
        dns_ip=dns_ip,
        dns_ip_version=dns_ip_version,
    )
