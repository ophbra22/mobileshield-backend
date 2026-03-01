from types import SimpleNamespace

import pytest

from app import analysis


def stub_redirect(url: str):
    return {
        'status_chain': [200],
        'final_status': 200,
        'content_type': 'text/html',
        'final_url': url,
        'redirect_hops': 0,
        'resolve_error': None,
        'redirect_chain': [],
        'dns_ip': None,
        'dns_ip_version': None,
    }


class DummyResp:
    def __init__(self, text: str):
        self.text = text

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


@pytest.fixture(autouse=True)
def stub_dependencies(monkeypatch):
    monkeypatch.setattr(analysis, "_resolve_redirects", stub_redirect)
    monkeypatch.setattr(
        analysis,
        "get_or_compute_domain_reputation",
        lambda db, domain: (SimpleNamespace(reputation='unknown'), {}, None, []),
    )
    monkeypatch.setattr(analysis, "_resolve_dns", lambda hostname: (None, None))


def test_brand_on_hosting_high_risk(monkeypatch):
    html = '<html><body><form><input type="password" name="password"></form></body></html>'
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: DummyResp(html))
    res = analysis.analyze_url("http://leumibank.wpengine.com", db=SimpleNamespace())
    assert res.risk_score >= 70
    assert res.verdict in ("malicious", "suspicious")
    assert any(item["key"] == "hosting_brand_impersonation" for item in res.breakdown)


def test_normal_hosting_not_high(monkeypatch):
    html = "<html><body><p>hello blog</p></body></html>"
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: DummyResp(html))
    res = analysis.analyze_url("https://myblog.wpengine.com", db=SimpleNamespace())
    assert res.risk_score < 50
    assert res.verdict != "malicious"


def test_punycode_increases_score(monkeypatch):
    html = "<html><body>ok</body></html>"
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: DummyResp(html))
    res = analysis.analyze_url("http://xn--example-9d0b.com", db=SimpleNamespace())
    assert any(item["key"] == "punycode" for item in res.breakdown)
    assert res.risk_score > 0
