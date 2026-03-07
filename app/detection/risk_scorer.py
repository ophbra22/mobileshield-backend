from __future__ import annotations

import tldextract

from app.detection.config import DEFAULT_CONFIG, DetectionConfig
from app.detection.models import (
    BrandAnalysis,
    CertificateAnalysis,
    ContentAnalysis,
    DomainAnalysis,
    RedirectResult,
    ReputationAnalysis,
    ScoreComponent,
    ServerAnalysis,
    URLParts,
)

PUBLIC_HOSTING_SUFFIXES = {
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

DOWNLOAD_CONTENT_HINTS = {
    'application/octet-stream',
    'application/x-msdownload',
    'application/vnd.android.package-archive',
    'application/zip',
}


class ScoreResult:
    def __init__(self):
        self.components: list[ScoreComponent] = []
        self.total: int = 0
        self.strong: list[str] = []
        self.medium: list[str] = []
        self.low: list[str] = []

    def add(self, component: ScoreComponent) -> None:
        if component.points == 0:
            return
        self.components.append(component)
        self.total += component.points
        if component.level == 'strong':
            self.strong.append(component.key)
        elif component.level == 'medium':
            self.medium.append(component.key)
        elif component.level == 'low':
            self.low.append(component.key)


def score_risk(
    parts: URLParts,
    redirect: RedirectResult,
    domain: DomainAnalysis,
    reputation: ReputationAnalysis,
    tls: CertificateAnalysis,
    content: ContentAnalysis,
    brand: BrandAnalysis,
    server: ServerAnalysis,
    config: DetectionConfig = DEFAULT_CONFIG,
) -> ScoreResult:
    result = ScoreResult()
    weights = config.weights

    def add_if(condition: bool, key: str, reason: str):
        if not condition:
            return
        weight = weights.get(key)
        if not weight:
            return
        result.add(ScoreComponent(key=key, points=weight.points, level=weight.level, reason=reason))

    # URL/Domain signals
    add_if(domain.is_ip_literal, 'ip_literal', 'URL host is an IP address instead of a domain.')
    add_if(domain.suspicious_tld and not domain.trusted, 'suspicious_tld', 'Top-level domain has high abuse rates.')
    add_if((domain.hyphen_count >= 3 or domain.excessive_subdomains), 'hyphen_abuse', 'Excessive subdomains/hyphens.')
    add_if(domain.long_path or domain.long_query, 'long_path_query', 'Unusually long path or query string.')
    add_if(bool(domain.phishing_keywords), 'phishing_keyword', 'Phishing lure keyword present in path/query.')
    add_if(bool(domain.lure_keywords), 'lure_keyword', 'Lure/urgency wording present.')
    add_if(domain.has_punycode, 'punycode', 'IDN/punycode detected which can hide lookalikes.')
    add_if(domain.obfuscated, 'obfuscated_chars', 'Encoded or obfuscated characters detected in URL.')
    add_if(domain.has_at, 'at_symbol', '@ symbol appears before path.')
    add_if(parts.scheme == 'http', 'http_scheme', 'Uses HTTP instead of HTTPS.')

    # Redirects (small risk per requirements)
    final_host = tldextract.extract(redirect.final_url).registered_domain or redirect.final_url
    domain_changed = redirect.domain_changed or (final_host and final_host != parts.registrable_domain)
    add_if(redirect.redirect_hops > 0, 'redirect_chain', 'Redirect present.')
    add_if(redirect.redirect_hops > 5, 'redirect_chain_long', 'Redirect chain is very long (>5).')
    add_if(domain_changed, 'redirect_domain_change', 'Redirect chain ends on a different domain.')
    add_if(redirect.used_shortener, 'shortener', 'Known URL shortener used.')
    add_if(redirect.used_shortener and (redirect.final_status is None or redirect.error), 'shortener_unresolved', 'Shortened URL failed to resolve cleanly.')

    # Domain reputation
    if reputation.domain_age_days is not None:
        add_if(reputation.domain_age_days < 30, 'domain_age_new', 'Domain is newly registered (<30 days).')
        add_if(30 <= reputation.domain_age_days < 90, 'domain_age_young', 'Domain is young (<90 days).')
    add_if(bool(reputation.signals.get('dns_nxdomain')), 'nxdomain', 'Domain does not resolve (NXDOMAIN).')

    # Brand impersonation / lookalike
    add_if(brand.impersonates_brand and not domain.trusted, 'brand_impersonation', 'Brand keyword appears on unrelated domain.')
    add_if(bool(brand.lookalike_score) and not domain.trusted, 'lookalike', 'Domain resembles a protected brand.')
    add_if(brand.brand_in_subdomain and _is_public_hosting(parts.registrable_domain), 'public_hosting_brand', 'Brand cues on public hosting platform.')

    # Content
    add_if(content.credential_form and not domain.trusted, 'credential_form_untrusted', 'Page contains a credential form on an untrusted domain.')
    add_if(content.payment_form and not domain.trusted, 'payment_form', 'Page requests payment details on an untrusted domain.')
    if content.brand_claim and brand.brand and brand.brand not in (parts.registrable_domain or ''):
        add_if(True, 'content_brand_mismatch', 'Page content references a brand that differs from the domain.')
    add_if(content.content_type in DOWNLOAD_CONTENT_HINTS, 'download_content', 'Destination looks like a direct download.')

    # TLS / certificate
    add_if(tls.hostname_matches is False, 'cert_mismatch', 'TLS certificate does not match the hostname.')
    add_if(tls.valid_now is False or tls.error, 'cert_invalid', 'TLS certificate is invalid or expired.')

    # Server indicators (avoid double-counting IP literal)
    add_if(server.is_private and not domain.trusted and not domain.is_ip_literal, 'ip_literal', 'Resolved IP is private/reserved.')

    # Marketing tracker discount: initial domain is tracker and final domain benign-ish
    initial_reg = tldextract.extract(redirect.chain[0].url).registered_domain if redirect.chain else None
    tracker_hit = initial_reg in config.marketing_tracker_domains if initial_reg else False
    final_benignish = (
        not domain.suspicious_tld
        and not brand.impersonates_brand
        and not content.credential_form
        and not content.payment_form
    )
    if tracker_hit and final_benignish:
        add_if(True, 'marketing_tracker_discount', 'Redirect uses a known marketing tracker to a normal destination.')

    # Benign final destination discount
    if (
        parts.scheme == 'https'
        and tls.valid_now is not False
        and tls.hostname_matches is not False
        and not tls.error
        and not brand.impersonates_brand
        and not content.credential_form
        and not content.payment_form
        and not domain.is_ip_literal
    ):
        add_if(True, 'benign_final_destination', 'Final destination is HTTPS with valid/ok cert and no spoof indicators.')

    # Allowlist discount (applied once and only if no strong evidence)
    if domain.trusted and not brand.impersonates_brand and not redirect.used_shortener:
        weight = weights.get('allowlist_discount')
        if weight:
            result.add(ScoreComponent(key='allowlist_discount', points=weight.points, level=weight.level, reason=weight.description))

    result.total = max(0, min(result.total, 100))
    return result


def _is_public_hosting(registrable: str) -> bool:
    reg = registrable.lower()
    return reg in PUBLIC_HOSTING_SUFFIXES or any(reg.endswith('.' + suffix) for suffix in PUBLIC_HOSTING_SUFFIXES)
