from __future__ import annotations

from sqlalchemy.orm import Session

from app.detection.brand_spoof_detector import analyze_brand_signals
from app.detection.certificate_analyzer import fetch_certificate
from app.detection.classifier import classify
from app.detection.config import DEFAULT_CONFIG, DetectionConfig
from app.detection.content_analyzer import analyze_content
from app.detection.domain_analyzer import analyze_domain
from app.detection.models import DetectionResult, TechnicalDetails
from app.detection.redirect_analyzer import follow_redirects
from app.detection.risk_scorer import score_risk
from app.detection.server_analyzer import analyze_server
from app.detection.url_normalizer import normalize_url
from app.detection.explanation_builder import build_reasons
from app.reputation import get_or_compute_domain_reputation


def run_detection(raw_url: str, db: Session, resolver=follow_redirects, config: DetectionConfig = DEFAULT_CONFIG) -> DetectionResult:
    # Normalize input
    initial_parts = normalize_url(raw_url)

    # Redirect analysis
    redirect_result = resolver(initial_parts.normalized_url, initial_parts, max_hops=6, config=config) if callable(resolver) else follow_redirects(initial_parts.normalized_url, initial_parts, max_hops=6, config=config)
    final_parts = normalize_url(redirect_result.final_url)

    # Domain analysis on final destination
    domain_analysis = analyze_domain(final_parts, raw_url, config=config)

    # Reputation
    rep_cache, rep_signals, rep_score_hint, rep_reasons = get_or_compute_domain_reputation(db, final_parts.registrable_domain)
    reputation = rep_cache.reputation

    # TLS / certificate
    certificate = fetch_certificate(redirect_result.final_url)

    # Server info
    server = analyze_server(redirect_result.dns_ip, redirect_result.dns_ip_version)

    # Content analysis (best-effort)
    content = analyze_content(redirect_result.final_url, redirect_result.content_type)

    # Brand spoofing
    brand = analyze_brand_signals(final_parts, config=config)

    # Risk scoring
    score_result = score_risk(
        parts=final_parts,
        redirect=redirect_result,
        domain=domain_analysis,
        reputation=_to_reputation(rep_cache, rep_signals, rep_score_hint, rep_reasons),
        tls=certificate,
        content=content,
        brand=brand,
        server=server,
        config=config,
    )

    status, confidence = classify(score_result, config=config)

    # Safe-case override: benign final business destination with no spoof indicators should not be phishing
    safe_case = (
        final_parts.scheme == 'https'
        and certificate.valid_now is not False
        and certificate.hostname_matches is not False
        and certificate.error is None
        and not brand.impersonates_brand
        and not content.credential_form
        and not content.payment_form
        and not domain_analysis.is_ip_literal
    )
    if safe_case and status == 'phishing':
        status = 'suspicious' if score_result.total > config.thresholds.legitimate_max else 'legitimate'
        confidence = 'medium' if score_result.total > config.thresholds.legitimate_max else 'low'

    reasons = build_reasons(score_result.components)

    technical_details = TechnicalDetails(
        submitted_url=raw_url,
        normalized_url=initial_parts.normalized_url,
        final_url=redirect_result.final_url,
        redirect_count=redirect_result.redirect_hops,
        ip_address=redirect_result.dns_ip,
        geo=server.geo,
        domain_age_days=rep_signals.get('domain_age_days'),
        first_seen=None,
        certificate_issuer=certificate.issuer,
        certificate_valid_from=certificate.valid_from,
        certificate_valid_to=certificate.valid_to,
        hostname_match=certificate.hostname_matches,
    )

    signals = {
        'url': {
            'submitted': raw_url,
            'normalized': initial_parts.normalized_url,
            'final': redirect_result.final_url,
            'hostname': final_parts.hostname,
            'registrable_domain': final_parts.registrable_domain,
            'tld': final_parts.tld,
        },
        'redirect_hops': redirect_result.redirect_hops,
        'redirect': {
            'hops': redirect_result.redirect_hops,
            'chain': [hop.__dict__ for hop in redirect_result.chain],
            'domain_changed': redirect_result.domain_changed,
            'used_shortener': redirect_result.used_shortener,
            'error': redirect_result.error,
            'final_status': redirect_result.final_status,
            'content_type': redirect_result.content_type,
        },
        'domain': domain_analysis.__dict__,
        'reputation': {
            'reputation': reputation,
            'score_hint': rep_score_hint,
            'signals': rep_signals,
            'reasons': rep_reasons,
        },
        'certificate': certificate.__dict__,
        'content': content.__dict__,
        'brand': brand.__dict__,
        'server': server.__dict__,
        'strong_signals': list(set(score_result.strong)),
        'medium_signals': list(set(score_result.medium)),
        'weak_signals': list(set(score_result.low)),
    }

    # Map to required structured output
    verdict = status
    risk_score = min(max(score_result.total, 0), 100)
    if safe_case and verdict != 'phishing':
        risk_score = min(risk_score, config.thresholds.suspicious_max)
    if verdict == 'legitimate':
        risk_score = min(risk_score, config.thresholds.legitimate_max)

    breakdown = [c.__dict__ for c in score_result.components]

    return DetectionResult(
        status=status,
        score=risk_score,
        risk_score=risk_score,
        confidence=confidence,
        reasons=reasons,
        breakdown=breakdown,
        technical_details=technical_details,
        signals=signals,
        normalized_url=initial_parts.normalized_url,
        domain=final_parts.registrable_domain,
        final_url=redirect_result.final_url,
        resolved_domain=final_parts.registrable_domain,
        redirect_hops=redirect_result.redirect_hops,
        verdict=verdict,
        risk_reasons=reasons,
        reputation=reputation,
        is_shortener=redirect_result.used_shortener,
    )


def _to_reputation(cache, signals, score_hint, reasons):
    from app.detection.models import ReputationAnalysis

    return ReputationAnalysis(
        reputation=cache.reputation if cache else 'unknown',
        score_hint=score_hint or 0,
        reasons=reasons or [],
        signals=signals or {},
        domain_age_days=signals.get('domain_age_days'),
        first_seen=None,
    )
