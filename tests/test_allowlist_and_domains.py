from types import SimpleNamespace

import pytest

from app import analysis, reputation


def stub_redirect(url: str):
    return {
        'chain': [{'url': url, 'status': 200}],
        'final_status': 200,
        'content_type': 'text/html',
        'final_url': url,
        'redirect_hops': 0,
        'error': None,
    }


@pytest.fixture(autouse=True)
def stubs(monkeypatch):
    monkeypatch.setattr(analysis, "resolve_final_url", lambda url, max_hops=8: stub_redirect(url))
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: SimpleNamespace(text="<html></html>"))
    monkeypatch.setattr(
        analysis,
        "get_or_compute_domain_reputation",
        lambda db, domain: (SimpleNamespace(reputation='benign'), {}, 0, []),
    )
    monkeypatch.setattr(analysis, "_resolve_dns", lambda hostname: (None, None))


def test_domain_normalization_etld():
    res = analysis.normalize_url("HTTP://Sub.Google.COM./path")
    assert res.startswith("http://sub.google.com/")


def test_google_allowlisted_not_malicious():
    # ensure allowlist contains google
    reputation._ALLOWLIST_CACHE.add("google.com")
    res = analysis.analyze_url("https://google.com", db=SimpleNamespace())
    assert res.verdict != "malicious"
    assert res.risk_score <= 15


def test_hosting_brand_bait_high_risk(monkeypatch):
    html = "<html><body><form><input name='password'></form></body></html>"
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: SimpleNamespace(text=html))
    res = analysis.analyze_url("http://leumibank.wpengine.com", db=SimpleNamespace())
    assert res.risk_score >= 60
    assert res.verdict in ("malicious", "suspicious")


def test_shortener_domain_change_suspicious(monkeypatch):
    def mock_redirect(url):
        data = stub_redirect("http://final.example.com")
        data['redirect_hops'] = 1
        data['chain'] = [{'url': url, 'status': 301}, {'url': 'http://final.example.com', 'status': 200}]
        data['final_url'] = "http://final.example.com"
        return data

    monkeypatch.setattr(analysis, "resolve_final_url", mock_redirect)
    res = analysis.analyze_url("http://tinyurl.com/test", db=SimpleNamespace())
    assert res.verdict in ("suspicious", "malicious")
