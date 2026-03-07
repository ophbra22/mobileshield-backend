from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

SignalLevel = Literal['strong', 'medium', 'low', 'info']
Confidence = Literal['low', 'medium', 'high']
ClassificationStatus = Literal['legitimate', 'suspicious', 'phishing']


@dataclass
class ScoreComponent:
    key: str
    points: int
    level: SignalLevel
    reason: str


@dataclass
class TechnicalDetails:
    submitted_url: str
    normalized_url: str
    final_url: Optional[str]
    redirect_count: int
    ip_address: Optional[str]
    geo: Optional[str]
    domain_age_days: Optional[int]
    first_seen: Optional[str]
    certificate_issuer: Optional[str]
    certificate_valid_from: Optional[str]
    certificate_valid_to: Optional[str]
    hostname_match: bool


@dataclass
class DetectionResult:
    status: ClassificationStatus
    score: int
    risk_score: int
    confidence: Confidence
    reasons: List[str]
    breakdown: List[Dict[str, Any]]
    technical_details: TechnicalDetails
    signals: Dict[str, Any] = field(default_factory=dict)
    # Legacy/compat fields for existing API consumers
    normalized_url: str = ''
    domain: str = ''
    final_url: Optional[str] = None
    resolved_domain: Optional[str] = None
    redirect_hops: int = 0
    verdict: str = ''
    risk_reasons: List[str] = field(default_factory=list)
    reputation: Optional[str] = None
    is_shortener: Optional[bool] = None


@dataclass
class URLParts:
    submitted_url: str
    normalized_url: str
    scheme: str
    hostname: str
    registrable_domain: str
    subdomain: str
    path: str
    query: str
    tld: str
    port: Optional[int]


@dataclass
class RedirectHop:
    url: str
    status: Optional[int]
    ip: Optional[str]
    ip_version: Optional[str]


@dataclass
class RedirectResult:
    final_url: str
    final_status: Optional[int]
    redirect_hops: int
    chain: List[RedirectHop]
    domain_changed: bool
    used_shortener: bool
    error: Optional[str]
    ssrf_blocked: bool
    ssrf_reason: Optional[str]
    content_type: Optional[str]
    dns_ip: Optional[str]
    dns_ip_version: Optional[str]


@dataclass
class DomainAnalysis:
    is_ip_literal: bool
    suspicious_tld: bool
    hyphen_count: int
    subdomain_depth: int
    excessive_subdomains: bool
    has_punycode: bool
    has_at: bool
    has_encoded_chars: bool
    obfuscated: bool
    phishing_keywords: List[str]
    lure_keywords: List[str]
    long_path: bool
    long_query: bool
    suspicious_path: bool
    hostname_length: int
    tld: str
    trusted: bool


@dataclass
class ReputationAnalysis:
    reputation: str
    score_hint: int
    reasons: List[str]
    signals: Dict[str, Any]
    domain_age_days: Optional[int]
    first_seen: Optional[str] = None


@dataclass
class CertificateAnalysis:
    issuer: Optional[str]
    subject: Optional[str]
    valid_from: Optional[str]
    valid_to: Optional[str]
    valid_now: Optional[bool]
    hostname_matches: bool
    error: Optional[str] = None


@dataclass
class ContentAnalysis:
    fetched: bool
    content_type: Optional[str]
    has_form: bool
    credential_form: bool
    payment_form: bool
    brand_claim: Optional[str]
    outbound_domains: List[str]
    outbound_count: int
    outbound_samples: List[str]


@dataclass
class BrandAnalysis:
    impersonates_brand: bool
    brand: Optional[str]
    lookalike_score: Optional[int]
    method: Optional[str]
    typosquat_target: Optional[str]
    typosquat_distance: Optional[int]
    official_domain: bool
    brand_keyword_hits: List[str]
    brand_in_subdomain: bool


@dataclass
class ServerAnalysis:
    ip: Optional[str]
    ip_version: Optional[str]
    is_private: bool
    geo: Optional[str] = None
