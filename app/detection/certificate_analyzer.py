from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from app.detection.models import CertificateAnalysis


def fetch_certificate(url: str) -> CertificateAnalysis:
    parsed = urlparse(url)
    if parsed.scheme != 'https' or not parsed.hostname:
        return CertificateAnalysis(
            issuer=None,
            subject=None,
            valid_from=None,
            valid_to=None,
            valid_now=None,
            hostname_matches=True,
            error=None,
        )
    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except Exception as exc:  # pragma: no cover - network/ssl errors
        return CertificateAnalysis(
            issuer=None,
            subject=None,
            valid_from=None,
            valid_to=None,
            valid_now=None,
            hostname_matches=False,
            error=str(exc),
        )

    not_before = cert.get('notBefore')
    not_after = cert.get('notAfter')
    issuer = _flatten_name(cert.get('issuer'))
    subject = _flatten_name(cert.get('subject'))

    nb_dt: Optional[datetime] = None
    na_dt: Optional[datetime] = None
    try:
        nb_dt = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z') if not_before else None
        na_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z') if not_after else None
    except Exception:
        nb_dt = None
        na_dt = None

    valid_now: Optional[bool] = None
    if nb_dt and na_dt:
        now = datetime.now(timezone.utc)
        valid_now = nb_dt.replace(tzinfo=timezone.utc) <= now <= na_dt.replace(tzinfo=timezone.utc)

    hostname_matches = True  # SSL layer already validated SNI

    return CertificateAnalysis(
        issuer=issuer,
        subject=subject,
        valid_from=not_before,
        valid_to=not_after,
        valid_now=valid_now,
        hostname_matches=hostname_matches,
        error=None,
    )


def _flatten_name(name_obj) -> Optional[str]:
    if not name_obj:
        return None
    if isinstance(name_obj, str):
        return name_obj
    if isinstance(name_obj, tuple):
        return ' '.join(str(x) for x in name_obj)
    if isinstance(name_obj, list):
        flat = []
        for item in name_obj:
            if isinstance(item, tuple):
                flat.extend([str(x) for x in item])
            else:
                flat.append(str(item))
        return ' '.join(flat)
    return str(name_obj)
