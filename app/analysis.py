from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

import requests
import tldextract
from sqlalchemy.orm import Session

from app.brand import analyze_brand, is_official_domain
from app.reputation import get_or_compute_domain_reputation

SHORTENER_DOMAINS = {
    'bit.ly',
    't.co',
    'tinyurl.com',
    'goo.gl',
    'is.gd',
    'ow.ly',
    'buff.ly',
    'shorturl.at',
    'rebrand.ly',
    'cutt.ly',
}

PHISHING_PATH_KEYWORDS = {
    'login',
    'verify',
    'secure',
    'account',
    'update',
    'password',
    'wallet',
    'confirm',
}

BRAND_BAIT_TOKENS = {
    'paypal',
    'apple',
    'microsoft',
    'google',
    'amazon',
    'bank',
    'chase',
    'coinbase',
    'meta',
}

DOWNLOAD_CONTENT_HINTS = {
    'application/octet-stream',
    'application/x-msdownload',
    'application/vnd.android.package-archive',
    'application/zip',
}


@dataclass
class AnalysisResult:
    normalized_url: str
    domain: str
    final_url: str | None
    redirect_hops: int
    risk_score: int
    verdict: str
    confidence: str
    reasons: list[str]
    signals: dict
    breakdown: list[dict] = field(default_factory=list)
    reputation: str | None = None
    scan_id: int | None = None


def normalize_url(raw_url: str) -> str:
    candidate = raw_url.strip()
    if '://' not in candidate:
        candidate = f'https://{candidate}'

    parsed = urlparse(candidate)
    scheme = parsed.scheme.lower() or 'https'
    if scheme not in {'http', 'https'}:
        raise ValueError('Only http and https URLs are allowed.')
    hostname = (parsed.hostname or '').lower()
    port = parsed.port

    netloc = hostname
    if port and not ((scheme == 'http' and port == 80) or (scheme == 'https' and port == 443)):
        netloc = f'{hostname}:{port}'

    path = parsed.path or '/'
    normalized = parsed._replace(scheme=scheme, netloc=netloc, path=path, params='', fragment='')
    return urlunparse(normalized)


def _registered_domain(url: str) -> str:
    extracted = tldextract.extract(url)
    return extracted.registered_domain or extracted.fqdn or ''


def _resolve_redirects(url: str) -> dict:
    result = {
        'status_chain': [],
        'final_status': None,
        'content_type': None,
        'final_url': None,
        'redirect_hops': 0,
        'resolve_error': None,
    }

    with requests.Session() as session:
        headers = {'User-Agent': 'MobileShieldAI/1.0'}
        try:
            response = session.head(url, allow_redirects=True, timeout=(2, 4), headers=headers)
            if response.status_code in {403, 405}:
                response = session.get(url, allow_redirects=True, timeout=(2, 4), headers=headers, stream=True)

            history = [*response.history, response]
            result['status_chain'] = [item.status_code for item in history]
            result['final_status'] = response.status_code
            result['content_type'] = response.headers.get('Content-Type', '').split(';')[0].strip().lower() or None
            result['final_url'] = response.url
            result['redirect_hops'] = max(len(history) - 1, 0)
            response.close()
        except requests.RequestException as exc:
            result['resolve_error'] = str(exc)

    return result


def analyze_url(raw_url: str, db: Session) -> AnalysisResult:
    normalized_url = normalize_url(raw_url)
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ''
    domain = _registered_domain(normalized_url)

    redirect_data = _resolve_redirects(normalized_url)

    score = 0
    reasons: list[str] = []
    breakdown: list[dict] = []

    def add_rule(key: str, points: int, description: str) -> None:
        nonlocal score
        if points <= 0:
            return
        score += points
        breakdown.append({'key': key, 'points': points, 'description': description})

    is_shortener = domain in SHORTENER_DOMAINS
    has_punycode = 'xn--' in hostname
    has_http = parsed.scheme == 'http'
    path_lower = parsed.path.lower()
    has_phishing_keyword = any(token in path_lower for token in PHISHING_PATH_KEYWORDS)
    has_brand_bait = any(token in hostname for token in BRAND_BAIT_TOKENS)

    final_url = redirect_data['final_url']
    final_domain = _registered_domain(final_url) if final_url else ''
    redirect_domain_change = bool(final_domain and domain and final_domain != domain)

    if has_http:
        add_rule('insecure_http', 10, 'Uses insecure HTTP instead of HTTPS.')
        reasons.append('Uses insecure HTTP instead of HTTPS.')
    if is_shortener:
        add_rule('url_shortener', 25, 'Uses a URL shortener, which can hide the true destination.')
        reasons.append('Uses a URL shortener, which can hide the true destination.')
    if has_punycode:
        add_rule('punycode', 25, 'Contains punycode characters that can imitate trusted domains.')
        reasons.append('Contains punycode characters that can imitate trusted domains.')

    hops = int(redirect_data['redirect_hops'])
    if hops >= 3:
        hop_points = min((hops - 2) * 10, 20)
        add_rule('long_redirect_chain', hop_points, 'Redirect chain is unusually long and may obscure the final destination.')
        reasons.append('Redirect chain is unusually long and may obscure the final destination.')

    if has_phishing_keyword:
        add_rule('phishing_keywords', 10, 'URL path contains common phishing lure words like login or verify.')
        reasons.append('URL path contains common phishing lure words like login or verify.')
    if has_brand_bait and not is_official_domain(domain):
        add_rule('brand_bait', 10, 'Hostname contains brand-related bait terms often used in impersonation attacks.')
        reasons.append('Hostname contains brand-related bait terms often used in impersonation attacks.')
    if redirect_domain_change:
        add_rule('redirect_domain_change', 10, 'Redirects to a different registered domain than initially presented.')
        reasons.append('Redirects to a different registered domain than initially presented.')

    content_type = redirect_data['content_type']
    if content_type in DOWNLOAD_CONTENT_HINTS:
        add_rule('download_content_type', 15, 'Destination appears to serve a direct-download file type.')
        reasons.append('Destination appears to serve a direct-download file type.')

    if redirect_data['final_status'] is None:
        add_rule('missing_status', 20, 'Could not verify destination response status.')
        reasons.append('Could not verify destination response status.')
    if redirect_data['resolve_error']:
        add_rule('resolve_error', 15, 'Network resolution produced errors, increasing uncertainty and risk.')
        reasons.append('Network resolution produced errors, increasing uncertainty and risk.')

    # Domain reputation
    rep_cache, rep_signals, rep_score_hint, rep_reasons = get_or_compute_domain_reputation(db, domain)
    if rep_score_hint:
        add_rule(
            'domain_reputation',
            rep_score_hint,
            f"Domain reputation signals raised risk: {'; '.join(rep_reasons) if rep_reasons else 'score hint applied'}.",
        )
    reasons.extend(rep_reasons)

    # Brand lookalike
    lookalike = analyze_brand(domain or hostname)
    brand_signals = None
    if lookalike:
        add_rule('brand_lookalike', lookalike.score, 'Possible look-alike impersonation of %s.' % lookalike.brand)
        reasons.append(f"Possible look-alike impersonation of {lookalike.brand}.")
        brand_signals = {
            'lookalike_brand': lookalike.brand,
            'lookalike_score': lookalike.score,
            'lookalike_method': lookalike.method,
            'levenshtein_distance': lookalike.distance,
        }

    score = min(score, 100)

    if score >= 70:
        verdict = 'malicious'
    elif score >= 30:
        verdict = 'suspicious'
    else:
        verdict = 'safe'

    # confidence calculation with strong indicator guardrails
    strong_indicators = False
    domain_nxdomain = bool(rep_signals.get('dns_nxdomain') or rep_signals.get('domain_nxdomain'))
    lookalike_present = bool(brand_signals)
    phishing_path_present = has_phishing_keyword
    breakdown_keys = {item.get('key') for item in breakdown}
    if (
        domain_nxdomain
        or (lookalike_present and not rep_signals.get('official_domain_matched', False))
        or phishing_path_present
        or 'brand_lookalike' in breakdown_keys
        or 'phishing_keywords' in breakdown_keys
    ):
        strong_indicators = True

    if strong_indicators and score >= 60:
        confidence = 'high'
    elif strong_indicators and score >= 30:
        confidence = 'medium'
    elif redirect_data['final_status'] is None or redirect_data['resolve_error']:
        confidence = 'low'
    elif score >= 70 or len(reasons) >= 4:
        confidence = 'high'
    else:
        confidence = 'medium'

    if confidence == 'low' and verdict == 'safe':
        verdict = 'suspicious'
        delta = 30 - score if score < 30 else 0
        add_rule('low_confidence_guardrail', delta, 'Low confidence forces suspicious verdict.')
        reasons.append('Limited network confidence prevented a safe classification.')

    score = min(score, 100)

    signals = {
        'scheme': parsed.scheme,
        'hostname': hostname,
        'domain': domain,
        'final_domain': final_domain,
        'status_chain': redirect_data['status_chain'],
        'final_status': redirect_data['final_status'],
        'content_type': content_type,
        'is_shortener': is_shortener,
        'has_punycode': has_punycode,
        'phishing_keyword_in_path': has_phishing_keyword,
        'brand_bait_in_hostname': has_brand_bait and not is_official_domain(domain),
        'redirect_domain_change': redirect_domain_change,
        'redirect_hops': hops,
        'resolve_error': redirect_data['resolve_error'],
        'domain_reputation': {
            'status': rep_cache.reputation,
            'score_hint': rep_score_hint,
            'signals': rep_signals,
            'reasons': rep_reasons,
        },
        'domain_nxdomain': domain_nxdomain,
    }
    if brand_signals:
        signals['brand_lookalike'] = brand_signals

    return AnalysisResult(
        normalized_url=normalized_url,
        domain=domain or hostname,
        final_url=final_url,
        redirect_hops=hops,
        risk_score=score,
        verdict=verdict,
        confidence=confidence,
        reasons=reasons,
        signals=signals,
        breakdown=breakdown,
        reputation=rep_cache.reputation,
    )
