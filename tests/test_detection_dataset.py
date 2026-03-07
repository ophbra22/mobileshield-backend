from types import SimpleNamespace

import pytest

from app.analysis import analyze_url
from app.detection.models import RedirectResult, RedirectHop, CertificateAnalysis, ContentAnalysis


def _stub_reputation(domain: str):
    domain_l = domain.lower()
    age = 400
    if any(token in domain_l for token in ['xyz', 'biz', 'alert', 'reset', 'security-check', 'newbrand', 'neutral']):
        age = 5
    signals = {'domain_age_days': age, 'dns_nxdomain': False, 'domain_nxdomain': False}
    cache = SimpleNamespace(reputation='benign' if age > 30 else 'suspicious', score_hint=0, signals=signals)
    return cache, signals, 0, []


def _make_redirect(url: str, parts, final_url: str | None = None, hops: int = 0, status: int = 200, used_shortener: bool = False):
    import tldextract

    final = final_url or url
    chain = [RedirectHop(url=url, status=status, ip='1.1.1.1', ip_version='ipv4')]
    final_reg = tldextract.extract(final).registered_domain or final
    domain_changed = parts.registrable_domain != final_reg
    return RedirectResult(
        final_url=final,
        final_status=status,
        redirect_hops=hops,
        chain=chain,
        domain_changed=domain_changed,
        used_shortener=used_shortener,
        error=None,
        ssrf_blocked=False,
        ssrf_reason=None,
        content_type='text/html',
        dns_ip='1.1.1.1',
        dns_ip_version='ipv4',
    )


@pytest.fixture(autouse=True)
def patch_dependencies(monkeypatch):
    # Reputation stub (avoid network)
    monkeypatch.setattr('app.detection.engine.get_or_compute_domain_reputation', lambda db, domain: _stub_reputation(domain))

    # TLS stub: valid for https, none for http
    def fake_cert(url: str):
        if url.startswith('https://'):
            return CertificateAnalysis(
                issuer='Test CA',
                subject='CN=test',
                valid_from='2024',
                valid_to='2026',
                valid_now=True,
                hostname_matches=True,
                error=None,
            )
        return CertificateAnalysis(
            issuer=None,
            subject=None,
            valid_from=None,
            valid_to=None,
            valid_now=None,
            hostname_matches=False,
            error=None,
        )

    monkeypatch.setattr('app.detection.engine.fetch_certificate', fake_cert)

    # Content stub
    def fake_content(url: str, ctype: str | None):
        lower = url.lower()
        has_form = any(tok in lower for tok in ['login', 'verify', 'reset', 'password'])
        credential_form = has_form
        payment_form = 'payment' in lower
        return ContentAnalysis(
            fetched=True,
            content_type=ctype,
            has_form=has_form,
            credential_form=credential_form,
            payment_form=payment_form,
            brand_claim=lower if has_form else None,
            outbound_domains=[],
            outbound_count=0,
            outbound_samples=[],
        )

    monkeypatch.setattr('app.detection.engine.analyze_content', fake_content)


def _resolver_for(final_url: str | None = None, used_shortener: bool = False):
    def _inner(url, parts, max_hops=6, config=None):
        return _make_redirect(url, parts, final_url=final_url or url, hops=1 if final_url else 0, used_shortener=used_shortener)
    return _inner


DATASET = [
    # Legitimate
    ('https://google.com', 'legitimate', _resolver_for()),
    ('https://accounts.google.com', 'legitimate', _resolver_for()),
    ('https://apple.com', 'legitimate', _resolver_for()),
    ('https://support.microsoft.com', 'legitimate', _resolver_for()),
    ('https://facebook.com', 'legitimate', _resolver_for()),
    ('https://www.binance.com', 'legitimate', _resolver_for()),
    # Marketing tracker redirect -> should stay legitimate
    ('https://w.ems.to/iRIA1SC', 'legitimate', _resolver_for(final_url='https://www.maniajeans.co.il')),
    # Suspicious
    ('http://t.ly/abc', 'suspicious', _resolver_for(final_url='https://apple.com', used_shortener=True)),
    ('https://tracking.newbrand.click/u/123', 'suspicious', _resolver_for()),
    ('https://neutral-redirect.xyz/login', 'suspicious', _resolver_for()),
    # Phishing
    ('https://goog1e-login-check.com', 'phishing', _resolver_for()),
    ('https://paypa1-security-login.net', 'phishing', _resolver_for()),
    ('http://192.168.1.10/login', 'phishing', _resolver_for()),
    ('https://amazon.com.security-check-user-login.co', 'phishing', _resolver_for()),
    ('https://verify-account-alert.example.xyz/login', 'phishing', _resolver_for()),
    ('https://microsoft-password-reset-confirm.biz', 'phishing', _resolver_for()),
]


class DummySession:
    """Minimal stub for SQLAlchemy session in tests."""

    def __getattr__(self, name):
        def _noop(*args, **kwargs):
            return None

        return _noop


@pytest.mark.parametrize('url,expected,resolver', DATASET)
def test_detection_dataset(url, expected, resolver):
    res = analyze_url(url, DummySession(), resolver=resolver)
    assert res.status == expected
    assert 0 <= res.risk_score <= 100
    if expected != 'legitimate':
        assert res.reasons, f"Expected reasons for {url}"
        assert res.confidence in {'medium', 'high', 'low'}
    if expected == 'phishing':
        assert res.risk_score >= 60
    if expected == 'legitimate':
        assert res.risk_score <= 25
