from __future__ import annotations

from urllib.parse import urlparse, urlunparse

import tldextract

from app.detection.models import URLParts


def normalize_url(raw_url: str) -> URLParts:
    candidate = raw_url.strip()
    if '://' not in candidate:
        candidate = f'https://{candidate}'

    parsed = urlparse(candidate)
    scheme = parsed.scheme.lower() or 'https'
    if scheme not in {'http', 'https'}:
        raise ValueError('Only http and https URLs are allowed.')

    hostname = (parsed.hostname or '').lower().rstrip('.')
    port = parsed.port
    netloc = hostname
    if port and not ((scheme == 'http' and port == 80) or (scheme == 'https' and port == 443)):
        netloc = f'{hostname}:{port}'

    path = parsed.path or '/'
    normalized = parsed._replace(scheme=scheme, netloc=netloc, path=path, params='', fragment='')
    normalized_url = urlunparse(normalized)

    extracted = tldextract.extract(hostname)
    registrable = extracted.registered_domain or hostname
    subdomain = extracted.subdomain
    tld = extracted.suffix

    return URLParts(
        submitted_url=raw_url,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        registrable_domain=registrable,
        subdomain=subdomain,
        path=path,
        query=parsed.query or '',
        tld=tld,
        port=port,
    )
