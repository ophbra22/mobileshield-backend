from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import tldextract
from sqlalchemy.orm import Session

from app.brand import analyze_brand, is_official_domain, detect_brand_impersonation, detect_typosquat, BRAND_KEYWORDS
from app.reputation import get_or_compute_domain_reputation, allowlist_hit

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
    'rb.gy',
    'did.li',
    'm-r.pw',
    'snip.ly',
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
    'appleid',
    'microsoft',
    'google',
    'amazon',
    'bank',
    'chase',
    'coinbase',
    'meta',
    'instagram',
    'facebook',
    # Israeli banks & payments
    'leumi',
    'leumibank',
    'hapoalim',
    'poalim',
    'discount',
    'mizrahi',
    'tefahot',
    'yahav',
    'beinleumi',
    'otzar',
    'mercantile',
    'massad',
    'cal',
    'max',
    'isracard',
}

DOWNLOAD_CONTENT_HINTS = {
    'application/octet-stream',
    'application/x-msdownload',
    'application/vnd.android.package-archive',
    'application/zip',
}

TRACKING_MALWARE_PATTERNS = {'doubleclick.net', 'clicktracker', 'malware', 'phishing'}
MAX_REDIRECTS = 6
NETWORK_TIMEOUT = (5, 5)  # connect, read seconds
HTML_TIMEOUT = (3, 5)

PUBLIC_HOSTING_RDS = {
    'wpengine.com',
    'herokuapp.com',
    'netlify.app',
    'vercel.app',
    'github.io',
    'firebaseapp.com',
    'web.app',
    'pages.dev',
    'workers.dev',
    'azurewebsites.net',
    'cloudfront.net',
    's3.amazonaws.com',
    'storage.googleapis.com',
    'onrender.com',
    'fly.dev',
}

BLOCKLIST_DOMAINS = {
    'carmelltunnel.com',
    'mypostali-il.co',
    '6cn.live',
    'ihiyev.com',
    'ups-fl.com',
}

PHISHING_THRESHOLD = 45
SUSPICIOUS_THRESHOLD = 20


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
    outbound: dict | None = None
    https: dict | None = None
    redirect_chain: list[dict] | None = None


def normalize_url(raw_url: str) -> str:
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
    return urlunparse(normalized)


def compute_registrable(hostname: str) -> str:
    extracted = tldextract.extract(hostname)
    return extracted.registered_domain or extracted.fqdn or hostname


def is_allowlisted(hostname: str, registrable: str) -> tuple[bool, str | None]:
    hit, source = allowlist_hit(registrable)
    if hit:
        return True, source
    hit2, source2 = allowlist_hit(hostname)
    if hit2:
        return True, source2
    return False, None


class _LinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_name = None
        if tag in {'a', 'link'}:
            attr_name = 'href'
        elif tag in {'script', 'img', 'iframe'}:
            attr_name = 'src'
        elif tag == 'form':
            attr_name = 'action'
        if not attr_name:
            return
        for name, value in attrs:
            if name == attr_name and value:
                absolute = urljoin(self.base_url, value)
                self.links.append(absolute)


def _registered_domain(url: str) -> str:
    extracted = tldextract.extract(url)
    return extracted.registered_domain or extracted.fqdn or ''


def _token_hits(text: str, tokens: Iterable[str]) -> list[str]:
    lowered = text.lower()
    hits = []
    for token in tokens:
        if token in lowered:
            hits.append(token)
    return hits


def _resolve_dns(hostname: str) -> tuple[str | None, str | None]:
    try:
        info = socket.getaddrinfo(hostname, None)
        if not info:
            return None, None
        family = info[0][0]
        ip = info[0][4][0]
        version = 'ipv6' if family == socket.AF_INET6 else 'ipv4'
        return ip, version
    except socket.gaierror:
        return None, None
    except Exception:
        return None, None


def _resolve_redirects(url: str) -> dict:
    result = {
        'status_chain': [],
        'final_status': None,
        'content_type': None,
        'final_url': None,
        'redirect_hops': 0,
        'resolve_error': None,
        'redirect_chain': [],
        'dns_ip': None,
        'dns_ip_version': None,
    }

    with requests.Session() as session:
        headers = {'User-Agent': 'MobileShieldAI/1.0'}
        try:
            current_url = url
            hops = 0
            while hops <= MAX_REDIRECTS:
                response = session.get(current_url, allow_redirects=False, timeout=NETWORK_TIMEOUT, headers=headers, stream=True)
                status = response.status_code
                result['status_chain'].append(status)
                hostname = urlparse(current_url).hostname or ''
                ip, version = _resolve_dns(hostname)
                result['redirect_chain'].append(
                    {
                        'url': current_url,
                        'status': status,
                        'resolved_ip': ip,
                        'ip_version': version,
                    }
                )
                if status in (301, 302, 303, 307, 308) and 'Location' in response.headers and hops < MAX_REDIRECTS:
                    location = response.headers['Location']
                    current_url = urljoin(current_url, location)
                    hops += 1
                    response.close()
                    continue
                # final
                result['final_status'] = status
                result['content_type'] = response.headers.get('Content-Type', '').split(';')[0].strip().lower() or None
                result['final_url'] = response.url
                result['redirect_hops'] = hops
                result['dns_ip'] = ip
                result['dns_ip_version'] = version
                response.close()
                break
        except requests.RequestException as exc:
            result['resolve_error'] = str(exc)

    return result


def resolve_final_url(url: str, max_hops: int = 8) -> dict:
    """Follow redirects with HEAD fallback to GET. Returns chain and flags."""
    chain = []
    final_url = None
    final_status = None
    content_type = None
    error = None
    with requests.Session() as session:
        headers = {'User-Agent': 'MobileShieldAI/1.0'}
        current = url
        for hop in range(max_hops):
            try:
                resp = session.head(current, allow_redirects=False, timeout=NETWORK_TIMEOUT, headers=headers)
                if resp.status_code >= 400 or resp.status_code in (405, 403):
                    resp = session.get(current, allow_redirects=False, timeout=NETWORK_TIMEOUT, headers=headers, stream=True)
            except requests.RequestException as exc:
                error = str(exc)
                break
            status = resp.status_code
            ctype = resp.headers.get('Content-Type', '').split(';')[0].lower() or None
            chain.append({'url': current, 'status': status})
            if status in (301, 302, 303, 307, 308) and 'Location' in resp.headers:
                location = resp.headers['Location']
                next_url = urljoin(current, location)
                if next_url == current:
                    break
                current = next_url
                continue
            final_url = resp.url
            final_status = status
            content_type = ctype
            break
    return {
        'chain': chain,
        'final_url': final_url,
        'final_status': final_status,
        'content_type': content_type,
        'error': error,
        'redirect_hops': max(len(chain) - 1, 0),
    }


def analyze_url(raw_url: str, db: Session) -> AnalysisResult:
    normalized_url = normalize_url(raw_url)
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or '').lower().rstrip('.')
    domain = compute_registrable(hostname)

    # Hard blocklist
    if domain in BLOCKLIST_DOMAINS or hostname in BLOCKLIST_DOMAINS:
        return AnalysisResult(
            normalized_url=normalized_url,
            domain=domain,
            final_url=None,
            redirect_hops=0,
            risk_score=100,
            verdict='malicious',
            confidence='high',
            reasons=['Domain is on hard blocklist.'],
            signals={'blocklist': True},
            breakdown=[{'key': 'blocklist', 'points': 100, 'description': 'Hard blocklisted domain.'}],
        )

    redirect_data = resolve_final_url(normalized_url, max_hops=MAX_REDIRECTS)
    final_url = redirect_data.get('final_url') or normalized_url
    final_parsed = urlparse(final_url)
    final_domain = compute_registrable(final_parsed.hostname or '')
    cross_domain_redirect = domain != final_domain

    # HTML fetch & outbound links (single fetch)
    outbound_info = {'outbound_domains': [], 'outbound_samples': [], 'outbound_count': 0, 'html_form_signals': []}
    https_info: dict | None = None
    content_type = redirect_data['content_type']
    if redirect_data['final_status'] and redirect_data['final_status'] < 400 and content_type and 'text/html' in content_type:
        try:
            with requests.get(final_url, timeout=HTML_TIMEOUT, headers={'User-Agent': 'MobileShieldAI/1.0'}, allow_redirects=False) as resp:
                html_text = resp.text[:200_000]  # cap
                parser = _LinkExtractor(final_url)
                parser.feed(html_text)
                html_form_signals = []
                lower_html = html_text.lower()
                if '<form' in lower_html:
                    html_form_signals.append('form_present')
                sensitive_inputs = ['password', 'card', 'cc', 'credit', 'cvv', 'cvc', 'iban', 'swift', 'account', 'routing', 'otp', 'pin', 'ssn', 'id', 'login']
                for token in sensitive_inputs:
                    if f'name=\"{token}' in lower_html or f'id=\"{token}' in lower_html or f'{token}=\"' in lower_html:
                        html_form_signals.append(f'input_{token}')
                # brand claim in title/meta
                brand_claim = None
                if '<title' in lower_html:
                    start = lower_html.find('<title')
                    end = lower_html.find('</title>', start)
                    if end != -1:
                        title_text = lower_html[start:end]
                        for bk in BRAND_KEYWORDS:
                            if bk in title_text and bk not in domain:
                                brand_claim = bk
                                break
                unique_urls = []
                seen = set()
                for u in parser.links:
                    if u not in seen:
                        seen.add(u)
                        unique_urls.append(u)
                domains: set[str] = set()
                samples: list[str] = []
                for u in unique_urls:
                    d = _registered_domain(u)
                    if d:
                        domains.add(d)
                    if len(samples) < 20:
                        samples.append(u)
                outbound_info = {
                    'outbound_domains': sorted(list(domains))[:30],
                    'outbound_samples': samples,
                    'outbound_count': len(unique_urls),
                    'html_form_signals': html_form_signals,
                    'html_brand_claim': brand_claim,
                }
        except Exception:
            pass

    # HTTPS certificate details
    if final_parsed.scheme == 'https' and final_parsed.hostname:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((final_parsed.hostname, final_parsed.port or 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=final_parsed.hostname) as ssock:
                    cert = ssock.getpeercert()
            not_before = cert.get('notBefore')
            not_after = cert.get('notAfter')
            nb_dt = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z') if not_before else None
            na_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z') if not_after else None
            days_to_expiry = None
            valid_now = None
            if na_dt:
                days_to_expiry = (na_dt.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                valid_now = nb_dt <= datetime.now(timezone.utc) <= na_dt if nb_dt else datetime.now(timezone.utc) <= na_dt
            https_info = {
                'cert_subject': cert.get('subject'),
                'cert_issuer': cert.get('issuer'),
                'not_before': not_before,
                'not_after': not_after,
                'days_to_expiry': days_to_expiry,
                'valid_now': valid_now,
            }
        except Exception:
            https_info = {'error': 'cert_fetch_failed'}

    score = 0
    reasons: list[str] = []
    breakdown: list[dict] = []

    def add_rule(key: str, points: int, description: str) -> None:
        nonlocal score
        if points == 0:
            return
        score += points
        breakdown.append({'key': key, 'points': points, 'description': description})

    is_shortener = domain in SHORTENER_DOMAINS
    has_punycode = 'xn--' in hostname
    has_http = parsed.scheme == 'http'
    path_lower = parsed.path.lower()
    has_phishing_keyword = any(token in path_lower for token in PHISHING_PATH_KEYWORDS)
    has_brand_bait = any(token in hostname for token in BRAND_BAIT_TOKENS)
    brand_hits_subdomain = _token_hits(hostname.replace('.', '-'), BRAND_BAIT_TOKENS) or _token_hits(parsed.path, BRAND_BAIT_TOKENS)
    hosting_brand_impersonation = domain in PUBLIC_HOSTING_RDS and bool(brand_hits_subdomain) and not is_official_domain(final_domain or domain)
    brand_impersonation = detect_brand_impersonation(hostname, domain)
    digit_ratio = sum(ch.isdigit() for ch in hostname) / max(len(hostname), 1)
    many_hyphens = hostname.count('-') >= 3
    subdomain_parts = (hostname.split('.')[:-2]) if len(hostname.split('.')) > 2 else hostname.split('.')[:-1]
    long_subdomain_chain = len(subdomain_parts) >= 4
    has_at = '@' in raw_url
    extra_slashes = raw_url.split('://', 1)[1].count('//') > 0 if '://' in raw_url else False
    redirect_domain_change = cross_domain_redirect
    hops = int(redirect_data['redirect_hops'])

    allowlist_ok, allowlist_source = is_allowlisted(hostname, final_domain or domain)

    # scoring rules (deterministic)
    if is_shortener:
        add_rule('url_shortener', 12, 'Uses a URL shortener, which can hide the true destination.')
        reasons.append('Uses a URL shortener, which can hide the true destination.')
        if redirect_domain_change:
            add_rule('shortener_domain_mismatch', 10, 'Shortened link resolves to a different domain.')
    if has_punycode:
        add_rule('punycode', 14, 'Contains punycode/IDN characters that can imitate trusted domains.')
        reasons.append('Contains punycode/IDN characters that can imitate trusted domains.')
    if has_brand_bait and not is_official_domain(domain):
        add_rule('brand_bait', 10, 'Hostname contains brand-related bait terms often used in impersonation attacks.')
        reasons.append('Hostname contains brand-related bait terms often used in impersonation attacks.')
    if brand_impersonation.get('is_brand_in_subdomain') and brand_impersonation.get('is_registered_domain_suspicious'):
        add_rule('brand_subdomain_impersonation', 55, 'Brand keyword appears in subdomain but registered domain is unrelated (possible impersonation).')
        reasons.append('Brand keyword appears in subdomain but registered domain is unrelated (possible impersonation).')
    # Previously missed cases like leumibank.wpengine.com (brand token on public hosting). Treat as high risk.
    if hosting_brand_impersonation:
        add_rule('hosting_brand_impersonation', 60, 'Brand-like token hosted on public hosting domain (possible impersonation).')
        reasons.append('Brand-like token hosted on public hosting domain (possible impersonation).')
    if has_phishing_keyword:
        add_rule('phishing_keywords', 8, 'URL path contains common phishing lure words like login or verify.')
        reasons.append('URL path contains common phishing lure words like login or verify.')
    if redirect_domain_change:
        add_rule('redirect_domain_change', 10, 'Redirects to a different registered domain than initially presented.')
        reasons.append('Redirects to a different registered domain than initially presented.')
        add_rule('cross_domain_redirect', 20, 'Redirect chain crosses domains, increasing risk.')
        if brand_impersonation.get('is_brand_in_subdomain'):
            add_rule('cross_domain_brand_redirect', 10, 'Redirect plus brand cues increases risk.')
    if hops >= 3:
        add_rule('long_redirect_chain', 6, 'Redirect chain is long (>=3).')
        reasons.append('Redirect chain is unusually long and may obscure the final destination.')
    if hops >= 5:
        add_rule('very_long_redirect_chain', 10, 'Redirect chain is very long (>=5).')
    if has_http:
        add_rule('insecure_http', 8, 'Uses insecure HTTP instead of HTTPS.')
        reasons.append('Uses insecure HTTP instead of HTTPS.')
    if digit_ratio > 0.3:
        add_rule('digit_heavy_hostname', 6, 'Hostname contains an unusually high ratio of digits.')
        reasons.append('Hostname contains an unusually high ratio of digits.')
    if many_hyphens:
        add_rule('many_hyphens', 4, 'Hostname contains many hyphens, common in spoofing.')
    if long_subdomain_chain:
        add_rule('long_subdomain_chain', 6, 'Hostname has a very long subdomain chain.')
    if has_at:
        add_rule('at_symbol_in_url', 8, 'URL contains @ which can obscure the real destination.')
    if extra_slashes:
        add_rule('extra_slashes', 6, 'URL contains unexpected // which can be used to obfuscate.')
    if https_info and isinstance(https_info, dict):
        exp_days = https_info.get('days_to_expiry')
        if exp_days is not None:
            if exp_days < 0:
                add_rule('cert_expired', 6, 'HTTPS certificate is expired.')
                reasons.append('HTTPS certificate is expired.')
            elif exp_days < 7:
                add_rule('cert_expiring', 6, 'HTTPS certificate expires soon (<7 days).')
                reasons.append('HTTPS certificate expires soon.')
    if content_type in DOWNLOAD_CONTENT_HINTS:
        add_rule('download_content_type', 10, 'Destination appears to serve a direct-download file type.')
        reasons.append('Destination appears to serve a direct-download file type.')
    payment_form_flag = False
    if outbound_info.get('html_form_signals'):
        # lightweight, low weight unless combined with other flags
        add_rule('html_sensitive_form', 4, 'HTML includes forms/inputs that may collect credentials.')
        reasons.append('Page includes forms/inputs that may collect credentials.')
    # payment form indicators
    payment_tokens = ['card', 'cc', 'cvv', 'cvc', 'iban', 'swift', 'account', 'routing', 'otp', 'pin']
    if outbound_info.get('html_form_signals') and any(f'input_{t}' in outbound_info['html_form_signals'] for t in payment_tokens):
        add_rule('html_payment_form', 25, 'HTML appears to request payment or sensitive financial details.')
        reasons.append('Page appears to request payment or sensitive financial details.')
        payment_form_flag = True
    if outbound_info.get('html_brand_claim') and outbound_info['html_brand_claim'] not in domain:
        add_rule('html_brand_claim', 15, 'Page content references a brand that does not match the domain.')
        reasons.append('Page content references a brand that does not match the domain.')
    if redirect_data.get('final_status') is None:
        add_rule('missing_status', 10, 'Could not verify destination response status.')
        reasons.append('Could not verify destination response status.')
    if redirect_data.get('error'):
        add_rule('resolve_error', 8, 'Network resolution produced errors, increasing uncertainty and risk.')
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

    # Outbound tracking/malware hints
    if outbound_info.get('outbound_domains'):
        suspicious_out = [
            d for d in outbound_info['outbound_domains'] if any(pat in d for pat in TRACKING_MALWARE_PATTERNS)
        ]
        if suspicious_out:
            add_rule('suspicious_outbound', 6, 'Outbound links reference tracking or suspicious domains.')
            reasons.append('Outbound links reference tracking or suspicious domains.')

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

    # Typosquat detection
    typosquat_target, typosquat_distance, normalized_candidate = (None, None, '')
    if not allowlist_ok:
        typosquat_target, typosquat_distance, normalized_candidate = detect_typosquat(domain)
        if typosquat_target and typosquat_distance is not None:
            add_rule('typosquatting_domain', 30, f"Domain resembles {typosquat_target} (possible typosquat).")
            reasons.append(f"Domain resembles {typosquat_target} (possible typosquat).")
    if brand_impersonation.get('is_brand_in_subdomain') and typosquat_target:
        add_rule('brand_typosquat_combo', 20, 'Brand cues plus typosquatting significantly increase risk.')

    score = min(score, 100)

    domain_nxdomain = bool(rep_signals.get('dns_nxdomain') or rep_signals.get('domain_nxdomain'))
    lookalike_present = bool(brand_signals)
    phishing_path_present = has_phishing_keyword

    # Base verdict by score (used if no escalation overrides)
    if score >= PHISHING_THRESHOLD:
        verdict = 'malicious'
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = 'suspicious'
    else:
        verdict = 'safe'

    triggered_signals = []
    rule_fired = None

    # Escalation rules
    if domain_nxdomain:
        verdict = 'malicious'
        rule_fired = 'RULE_A_NXDOMAIN'
        triggered_signals.append('nxdomain')
    if not rule_fired and is_shortener and (redirect_data.get('error') or redirect_data.get('final_status') is None):
        verdict = 'malicious'
        rule_fired = 'RULE_B_SHORTENER_UNRESOLVED'
    if not rule_fired and cross_domain_redirect and (outbound_info.get('html_form_signals') or payment_form_flag):
        verdict = 'malicious'
        rule_fired = 'RULE_C_CROSS_DOMAIN_FORM'
    if (
        not rule_fired
        and rep_signals.get('domain_age_days') is not None
        and rep_signals.get('domain_age_days') < 30
        and (outbound_info.get('html_form_signals') or payment_form_flag or lookalike_present)
    ):
        verdict = 'malicious'
        rule_fired = 'RULE_D_NEW_DOMAIN_FORM_BRAND'
    if not rule_fired and lookalike_present and (outbound_info.get('html_form_signals') or payment_form_flag):
        verdict = 'malicious'
        rule_fired = 'RULE_E_BRAND_FORM'
    if (
        not rule_fired
        and is_shortener
        and allowlist_ok
        and final_domain
        and (hostname.endswith('.' + final_domain) or final_domain == domain)
    ):
        verdict = 'safe'
        score = min(score, 10)
        rule_fired = 'RULE_F_SHORTENER_ALLOWLIST'

    # allowlist cap (non-critical)
    critical_flags = any(
        [
            hosting_brand_impersonation,
            brand_impersonation.get('is_brand_in_subdomain') and brand_impersonation.get('is_registered_domain_suspicious'),
            typosquat_target,
            payment_form_flag,
            cross_domain_redirect,
        ]
    )
    if allowlist_ok and not critical_flags and parsed.scheme == 'https' and rule_fired is None:
        score = min(score, 15)
        if verdict == 'malicious':
            verdict = 'suspicious'
        rule_fired = rule_fired or 'ALLOWLIST_CAP'

    # Confidence simple
    strong_count = sum(
        [
            hosting_brand_impersonation,
            domain_nxdomain,
            lookalike_present and not rep_signals.get('official_domain_matched', False),
            phishing_path_present,
            bool(outbound_info.get('html_form_signals')),
            cross_domain_redirect,
        ]
    )
    if strong_count >= 2 or score >= 70:
        confidence = 'high'
    elif strong_count == 1:
        confidence = 'medium'
    else:
        confidence = 'low' if redirect_data.get('final_status') is None or redirect_data.get('error') else 'medium'

    score = min(score, 100)

    signals = {
        'scheme': parsed.scheme,
        'hostname': hostname,
        'domain': domain,
        'final_domain': final_domain,
        'status_chain': [c.get('status') for c in redirect_data.get('chain', [])],
        'redirect_chain': redirect_data.get('chain', []),
        'dns_resolved': {'ip': redirect_data.get('dns_ip'), 'ip_version': redirect_data.get('dns_ip_version')},
        'final_status': redirect_data.get('final_status'),
        'content_type': content_type,
        'is_shortener': is_shortener,
        'has_punycode': has_punycode,
        'phishing_keyword_in_path': has_phishing_keyword,
        'brand_bait_in_hostname': has_brand_bait and not is_official_domain(domain),
        'redirect_domain_change': redirect_domain_change,
        'redirect_hops': hops,
        'resolve_error': redirect_data.get('error'),
        'domain_reputation': {
            'status': rep_cache.reputation,
            'score_hint': rep_score_hint,
            'signals': rep_signals,
            'reasons': rep_reasons,
        },
        'domain_nxdomain': domain_nxdomain,
        'outbound': outbound_info,
        'https': https_info or {},
        'flags': {
            'is_shortener': is_shortener,
            'has_punycode': has_punycode,
            'brand_bait': has_brand_bait and not is_official_domain(domain),
            'suspicious_tld': False,
            'many_redirects': hops >= 3,
            'domain_mismatch': redirect_domain_change,
        },
        'brand_impersonation': brand_impersonation,
        'allowlist_hit': allowlist_ok,
        'allowlist_source': allowlist_source,
        'typosquat': {
            'target': typosquat_target,
            'distance': typosquat_distance,
            'candidate': normalized_candidate,
        },
        'rule_fired': rule_fired,
        'triggered_signals': triggered_signals,
        'cross_domain_redirect': cross_domain_redirect,
        'final_registrable_domain': final_domain,
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
        outbound=outbound_info,
        https=https_info,
        redirect_chain=redirect_data.get('redirect_chain'),
    )
