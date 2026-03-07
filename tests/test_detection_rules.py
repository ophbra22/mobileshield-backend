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


def _resolver(final_url: str | None, status: int = 200, hops: int = 0, error: str | None = None):
    return lambda url, max_hops=5: {
        'chain': [{'url': url, 'status': status}],
        'final_url': final_url,
        'final_status': status if final_url else None,
        'content_type': None,
        'error': error,
        'redirect_hops': hops,
        'ssrf_blocked': False,
        'ssrf_reason': None,
        'dns_ip': '1.1.1.1',
        'dns_ip_version': 'ipv4',
    }


def test_shortener_resolves_to_trusted_domain_benign(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    res = analyze_url('http://bit.ly/xyz', DummySession(), resolver=_resolver('https://youtube.com/watch'))
    assert res.status == 'BENIGN'
    assert res.risk_score <= 20
    assert res.is_shortener is True


def test_shortener_unresolved_is_suspicious(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    res = analyze_url('http://bit.ly/xyz', DummySession(), resolver=_resolver(None, status=502, error='timeout'))
    assert res.status == 'SUSPICIOUS'
    assert res.risk_score >= 25


def test_shortener_to_ace_trusted(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    res = analyze_url('http://bit.ly/xyz', DummySession(), resolver=_resolver('https://www.ace.co.il/deals'))
    assert res.status == 'BENIGN'
    assert res.risk_score <= 20


def test_brand_impersonation_suspicious_tld_malicious(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    res = analyze_url('https://etsy.orders-complete.sbs', DummySession(), resolver=_resolver('https://etsy.orders-complete.sbs'))
    assert res.status == 'MALICIOUS'
    assert res.risk_score >= 80
    assert 'brand' in ' '.join(res.reasons).lower()


def test_punycode_suspicious(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    res = analyze_url('http://xn--paypal-123.top/login', DummySession(), resolver=_resolver('http://xn--paypal-123.top/login'))
    assert res.status in {'SUSPICIOUS', 'MALICIOUS'}


def test_brand_on_official_domain_not_auto_malicious(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    res = analyze_url('https://www.paypal.com/login', DummySession(), resolver=_resolver('https://www.paypal.com/login'))
    assert res.status != 'MALICIOUS'


def test_benign_domain_stays_benign(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    res = analyze_url('https://example.com', DummySession(), resolver=_resolver('https://example.com'))
    assert res.status == 'BENIGN'
