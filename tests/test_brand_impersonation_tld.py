from unittest import mock

from app.analysis import analyze_url


class DummySession:
    pass


def _rep_result(score_hint: int = 0):
    cache = mock.Mock()
    cache.reputation = 'unknown'
    cache.score_hint = score_hint
    cache.signals = {'dns_nxdomain': False, 'domain_nxdomain': False}
    cache.sources = {'reasons': []}
    return cache, cache.signals, score_hint, cache.sources['reasons']


def _make_resolver(final_url: str):
    return lambda url, max_hops=5: {
        'chain': [{'url': url, 'status': 301 if final_url != url else 200}],
        'final_url': final_url,
        'final_status': 200,
        'content_type': None,
        'error': None,
        'redirect_hops': 1 if final_url != url else 0,
        'ssrf_blocked': False,
        'ssrf_reason': None,
        'dns_ip': '1.1.1.1',
        'dns_ip_version': 'ipv4',
    }


def test_brand_impersonation_suspicious_tld_is_malicious(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    resolver = _make_resolver('https://etsy.orders-complete.sbs/login')
    res = analyze_url('https://etsy.orders-complete.sbs/login', DummySession(), resolver=resolver)
    assert res.status in {'SUSPICIOUS', 'MALICIOUS'}
    # Zero-miss guardrail should drive it to malicious due to brand + suspicious TLD
    assert res.risk_score >= 70 or res.status == 'MALICIOUS'
    assert any('brand' in r.lower() for r in res.reasons)


def test_brand_keyword_on_official_domain_not_flagged(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    resolver = _make_resolver('https://www.etsy.com/help')
    res = analyze_url('https://www.etsy.com/help', DummySession(), resolver=resolver)
    assert res.status == 'BENIGN' or res.risk_score < 25


def test_benign_without_signals(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    resolver = _make_resolver('https://example.com/')
    res = analyze_url('https://example.com/', DummySession(), resolver=resolver)
    assert res.status == 'BENIGN'


def test_brand_keyword_with_lure_forces_malicious(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    resolver = _make_resolver('https://paypal.secure-login.xyz/account')
    res = analyze_url('https://paypal.secure-login.xyz/account', DummySession(), resolver=resolver)
    assert res.status == 'MALICIOUS' or res.risk_score >= 70
    assert 'paypal' in ''.join(res.reasons).lower()
