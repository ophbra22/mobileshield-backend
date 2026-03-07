from types import SimpleNamespace

from app.analysis import analyze_url
from app.detection.models import RedirectResult, RedirectHop, CertificateAnalysis, ContentAnalysis


def _resolver(url, parts, max_hops=6, config=None):
    return RedirectResult(
        final_url=url,
        final_status=200,
        redirect_hops=0,
        chain=[RedirectHop(url=url, status=200, ip='1.1.1.1', ip_version='ipv4')],
        domain_changed=False,
        used_shortener=False,
        error=None,
        ssrf_blocked=False,
        ssrf_reason=None,
        content_type='text/html',
        dns_ip='1.1.1.1',
        dns_ip_version='ipv4',
    )


def test_analyze_smoke(monkeypatch):
    monkeypatch.setattr('app.detection.engine.fetch_certificate', lambda url: CertificateAnalysis(None, None, None, None, None, True, None))
    monkeypatch.setattr(
        'app.detection.engine.analyze_content',
        lambda url, ctype: ContentAnalysis(
            fetched=False,
            content_type=ctype,
            has_form=False,
            credential_form=False,
            payment_form=False,
            brand_claim=None,
            outbound_domains=[],
            outbound_count=0,
            outbound_samples=[],
        ),
    )
    monkeypatch.setattr(
        'app.detection.engine.get_or_compute_domain_reputation',
        lambda db, domain: (SimpleNamespace(reputation='benign'), {'domain_age_days': 365, 'dns_nxdomain': False}, 0, []),
    )
    res = analyze_url("https://example.com", SimpleNamespace(), resolver=_resolver)
    assert res.normalized_url
    assert res.signals.get("redirect") is not None
    assert res.breakdown is not None
