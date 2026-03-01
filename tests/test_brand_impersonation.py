from types import SimpleNamespace

import pytest

from app import analysis


def stub_redirect(final_url: str):
    return {
        'chain': [{'url': final_url, 'status': 200}],
        'final_status': 200,
        'content_type': 'text/html',
        'final_url': final_url,
        'redirect_hops': 0,
        'error': None,
    }


class DummyResp:
    def __init__(self, text: str):
        self.text = text

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


@pytest.fixture(autouse=True)
def stub_common(monkeypatch):
    monkeypatch.setattr(analysis, "_resolve_dns", lambda hostname: (None, None))
    monkeypatch.setattr(
        analysis,
        "get_or_compute_domain_reputation",
        lambda db, domain: (SimpleNamespace(reputation='unknown'), {}, None, []),
    )


def test_leumibank_typosquat_hosting_high_risk(monkeypatch):
    monkeypatch.setattr(analysis, "resolve_final_url", lambda url, max_hops=8: stub_redirect(url))
    html = '<html><title>כניסה לאתר לאומי</title><form><input name="password"></form></html>'
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: DummyResp(html))
    res = analysis.analyze_url("http://leumibank.wpenigne.com", db=SimpleNamespace())
    assert res.risk_score >= 60
    assert res.verdict in ("malicious", "suspicious")
    keys = {b["key"] for b in res.breakdown}
    assert "brand_subdomain_impersonation" in keys or "typosquatting_domain" in keys


def test_example_safe(monkeypatch):
    monkeypatch.setattr(analysis, "resolve_final_url", lambda url, max_hops=8: stub_redirect(url))
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: DummyResp("<html><body>hello</body></html>"))
    res = analysis.analyze_url("https://example.com", db=SimpleNamespace())
    assert res.risk_score < 30
    assert res.verdict == "safe"


def test_tinyurl_not_safe(monkeypatch):
    # simulate redirect to other domain
    def mock_redirect(url):
        data = stub_redirect("http://final.example.com")
        data['chain'] = [{'url': url, 'status': 301}, {'url': 'http://final.example.com', 'status': 200}]
        data['redirect_hops'] = 1
        return data

    monkeypatch.setattr(analysis, "resolve_final_url", mock_redirect)
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: DummyResp("<html></html>"))
    res = analysis.analyze_url("http://tinyurl.com/test", db=SimpleNamespace())
    assert res.verdict in ("suspicious", "malicious")
    assert res.risk_score >= 25
