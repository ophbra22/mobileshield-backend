from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set

from app.detection.models import SignalLevel


@dataclass(frozen=True)
class ScoreWeight:
    points: int
    level: SignalLevel
    description: str


@dataclass(frozen=True)
class Thresholds:
    legitimate_max: int = 25
    suspicious_max: int = 59  # 60+ => phishing


@dataclass(frozen=True)
class DetectionConfig:
    thresholds: Thresholds
    suspicious_tlds: Set[str]
    shortener_domains: Set[str]
    marketing_tracker_domains: Set[str]
    phishing_keywords: Set[str]
    lure_keywords: Set[str]
    brand_keywords: Set[str]
    trusted_roots: Set[str]
    weights: Dict[str, ScoreWeight]


DEFAULT_SUSPICIOUS_TLDS: Set[str] = {
    'pw',
    'top',
    'xyz',
    'click',
    'loan',
    'work',
    'gq',
    'ml',
    'cf',
    'tk',
    'cam',
    'quest',
    'zip',
    'review',
    'country',
    'link',
    'info',
}

DEFAULT_SHORTENERS: Set[str] = {
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
    'lnkd.in',
    'trib.al',
    's.id',
    'clk.sh',
    'tiny.one',
    't.ly',
}

DEFAULT_MARKETING_TRACKERS: Set[str] = {
    'w.ems.to',
    'ems.to',
    'em.mtr.cool',
    'go.pardot.com',
    'r20.rs6.net',
    'mandrillapp.com',
    'sendgrid.net',
    'mailchimp.com',
    'cmail20.com',
    'lnk.click',
    'links.govdelivery.com',
    'trk.msgsndr.com',
    'urldefense.proofpoint.com',
    'links.sfmc-content.com',
    'trk.mail.ru',
    'click.mlsend.com',
}

DEFAULT_TRUSTED_ROOTS: Set[str] = {
    'google.com',
    'youtube.com',
    'apple.com',
    'icloud.com',
    'microsoft.com',
    'live.com',
    'outlook.com',
    'office.com',
    'amazon.com',
    'amazon.co.uk',
    'paypal.com',
    'facebook.com',
    'instagram.com',
    'whatsapp.com',
    'whatsapp.net',
    'telegram.org',
    'binance.com',
    'github.com',
    'linkedin.com',
    'cloudflare.com',
    'openai.com',
    'wikipedia.org',
    'appleid.apple.com',
}

DEFAULT_PHISHING_KEYWORDS: Set[str] = {
    'login',
    'verify',
    'secure',
    'account',
    'password',
    'reset',
    'update',
    'confirm',
    'wallet',
    'bank',
    'signin',
}

DEFAULT_LURE_KEYWORDS: Set[str] = {
    'billing',
    'invoice',
    'orders',
    'order',
    'complete',
    'tracking',
    'payment',
    'support',
    'otp',
}

DEFAULT_BRAND_KEYWORDS: Set[str] = {
    'google',
    'apple',
    'microsoft',
    'amazon',
    'paypal',
    'facebook',
    'instagram',
    'meta',
    'whatsapp',
    'telegram',
    'binance',
    'chase',
    'boa',
    'wellsfargo',
    'bankofamerica',
    'citibank',
    'hsbc',
    'capitalone',
    'stripe',
    'cashapp',
    'venmo',
}

DEFAULT_WEIGHTS: Dict[str, ScoreWeight] = {
    'ip_literal': ScoreWeight(35, 'strong', 'URL host is an IP address'),
    'suspicious_tld': ScoreWeight(16, 'medium', 'Abused or low-reputation TLD'),
    'hyphen_abuse': ScoreWeight(8, 'low', 'Excessive hyphens/subdomains'),
    'long_path_query': ScoreWeight(6, 'low', 'Unusually long path/query'),
    'phishing_keyword': ScoreWeight(10, 'medium', 'Phishing keyword present'),
    'lure_keyword': ScoreWeight(6, 'low', 'Lure keyword present'),
    'punycode': ScoreWeight(18, 'strong', 'Punycode / IDN that can hide lookalikes'),
    'obfuscated_chars': ScoreWeight(8, 'medium', 'Encoded/obfuscated characters'),
    'at_symbol': ScoreWeight(6, 'low', '@ symbol may hide destination'),
    'http_scheme': ScoreWeight(6, 'low', 'Uses HTTP instead of HTTPS'),
    'redirect_chain': ScoreWeight(3, 'low', 'Redirect present'),
    'redirect_chain_long': ScoreWeight(10, 'medium', 'Redirect chain is very long (>5)'),
    'redirect_domain_change': ScoreWeight(6, 'medium', 'Redirect ends on different domain'),
    'shortener': ScoreWeight(10, 'medium', 'Known URL shortener'),
    'shortener_unresolved': ScoreWeight(20, 'medium', 'Shortener failed to resolve'),
    'domain_age_new': ScoreWeight(12, 'medium', 'Domain is newly registered'),
    'domain_age_young': ScoreWeight(6, 'low', 'Domain is young'),
    'nxdomain': ScoreWeight(25, 'strong', 'Domain does not resolve'),
    'brand_impersonation': ScoreWeight(40, 'strong', 'Brand keyword on unrelated domain'),
    'lookalike': ScoreWeight(30, 'strong', 'Brand lookalike/typosquat'),
    'credential_form_untrusted': ScoreWeight(28, 'strong', 'Credential form on untrusted domain'),
    'payment_form': ScoreWeight(22, 'strong', 'Payment/financial fields on untrusted domain'),
    'content_brand_mismatch': ScoreWeight(15, 'medium', 'Page content references mismatched brand'),
    'cert_mismatch': ScoreWeight(18, 'strong', 'TLS certificate does not match host'),
    'cert_invalid': ScoreWeight(10, 'medium', 'TLS certificate expired/invalid'),
    'download_content': ScoreWeight(12, 'medium', 'Direct download content type'),
    'public_hosting_brand': ScoreWeight(25, 'strong', 'Brand hosted on public/shared platform'),
    'allowlist_discount': ScoreWeight(-25, 'info', 'Trusted domain allowlist discount'),
    'marketing_tracker_discount': ScoreWeight(-12, 'info', 'Redirect uses common marketing tracker to a normal site'),
    'benign_final_destination': ScoreWeight(-10, 'info', 'Final destination appears legitimate and low-risk'),
}


DEFAULT_CONFIG = DetectionConfig(
    thresholds=Thresholds(),
    suspicious_tlds=DEFAULT_SUSPICIOUS_TLDS,
    shortener_domains=DEFAULT_SHORTENERS,
    marketing_tracker_domains=DEFAULT_MARKETING_TRACKERS,
    phishing_keywords=DEFAULT_PHISHING_KEYWORDS,
    lure_keywords=DEFAULT_LURE_KEYWORDS,
    brand_keywords=DEFAULT_BRAND_KEYWORDS,
    trusted_roots=DEFAULT_TRUSTED_ROOTS,
    weights=DEFAULT_WEIGHTS,
)
