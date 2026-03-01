from types import SimpleNamespace

import pytest

from app import analysis, reputation


def make_redirect(final_url=None, error=None, chain=None):
    if chain is None:
        chain = [{'url': final_url or 'http://example.com', 'status': 200}]
    return {
        'chain': chain,
        'final_status': chain[-1]['status'] if chain else None,
        'content_type': 'text/html',
        'final_url': final_url or chain[-1]['url'],
        'redirect_hops': max(len(chain) - 1, 0),
        'error': error,
    }


def rep_stub(nxdomain=False, age_days=365):
    signals = {'dns_nxdomain': nxdomain, 'domain_nxdomain': nxdomain, 'domain_age_days': age_days}
    return SimpleNamespace(reputation='unknown'), signals, 0, []


@pytest.fixture(autouse=True)
def clear_allowlist():
    reputation._ALLOWLIST_CACHE.add('google.com')
    yield


def test_shortener_unresolved_phishing(monkeypatch):
    monkeypatch.setattr(analysis, "resolve_final_url", lambda url, max_hops=8: make_redirect(final_url=None, error='timeout', chain=[]))
    monkeypatch.setattr(analysis, "get_or_compute_domain_reputation", lambda db, domain: rep_stub(False, 200))
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: SimpleNamespace(text=""))
    res = analysis.analyze_url("https://did.li", db=SimpleNamespace())
    assert res.verdict == 'malicious'


def test_nxdomain_escalates(monkeypatch):
    monkeypatch.setattr(analysis, "resolve_final_url", lambda url, max_hops=8: make_redirect(final_url=url))
    monkeypatch.setattr(analysis, "get_or_compute_domain_reputation", lambda db, domain: rep_stub(True, 5))
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: SimpleNamespace(text=""))
    res = analysis.analyze_url("https://6cn.live", db=SimpleNamespace())
    assert res.verdict == 'malicious'


def test_cross_domain_form_phishing(monkeypatch):
    chain = [{'url': 'http://snip.ly', 'status': 301}, {'url': 'http://evil.example.com', 'status': 200}]
    monkeypatch.setattr(analysis, "resolve_final_url", lambda url, max_hops=8: make_redirect(final_url='http://evil.example.com', chain=chain))
    monkeypatch.setattr(analysis, "get_or_compute_domain_reputation", lambda db, domain: rep_stub(False, 10))
    html = "<html><form><input name='password'></form></html>"
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: SimpleNamespace(text=html))
    res = analysis.analyze_url("http://snip.ly/abc", db=SimpleNamespace())
    assert res.verdict == 'malicious'


def test_google_allowlisted_safe(monkeypatch):
    monkeypatch.setattr(analysis, "resolve_final_url", lambda url, max_hops=8: make_redirect(final_url=url))
    monkeypatch.setattr(analysis, "get_or_compute_domain_reputation", lambda db, domain: rep_stub(False, 4000))
    monkeypatch.setattr(analysis.requests, "get", lambda *a, **k: SimpleNamespace(text="<html><form></form></html>"))
    res = analysis.analyze_url("https://google.com", db=SimpleNamespace())
    assert res.verdict != 'malicious'
    assert res.risk_score <= 15
