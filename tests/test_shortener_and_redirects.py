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


def test_shortener_unresolved_forced_suspicious(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    fake_resolver = lambda url, max_hops=5: {
        'chain': [],
        'final_url': None,
        'final_status': None,
        'content_type': None,
        'error': 'timeout',
        'redirect_hops': 0,
        'ssrf_blocked': False,
        'ssrf_reason': None,
    }
    res = analyze_url('http://bit.ly/abc', DummySession(), resolver=fake_resolver)
    assert res.status == 'SUSPICIOUS'
    assert res.risk_score >= 45
    assert any('shorten' in r.lower() for r in res.reasons)


def test_shortener_resolves_to_suspicious_destination(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    fake_resolver = lambda url, max_hops=5: {
        'chain': [{'url': url, 'status': 301}],
        'final_url': 'http://phish.click/login',
        'final_status': 200,
        'content_type': None,
        'error': None,
        'redirect_hops': 1,
        'ssrf_blocked': False,
        'ssrf_reason': None,
    }
    res = analyze_url('http://t.co/abc', DummySession(), resolver=fake_resolver)
    assert res.status in {'SUSPICIOUS', 'MALICIOUS'}
    assert res.resolved_domain == 'phish.click'
    assert any('abuse rates' in r.lower() for r in res.reasons)


def test_punycode_domain_raises_risk(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    fake_resolver = lambda url, max_hops=5: {
        'chain': [{'url': url, 'status': 200}],
        'final_url': url,
        'final_status': 200,
        'content_type': None,
        'error': None,
        'redirect_hops': 0,
        'ssrf_blocked': False,
        'ssrf_reason': None,
    }
    res = analyze_url('http://xn--paypal-123.com/login', DummySession(), resolver=fake_resolver)
    assert res.status in {'SUSPICIOUS', 'MALICIOUS'}
    assert any('punycode' in r.lower() for r in res.reasons)


def test_suspicious_tld_and_keywords(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))
    fake_resolver = lambda url, max_hops=5: {
        'chain': [{'url': url, 'status': 200}],
        'final_url': url,
        'final_status': 200,
        'content_type': None,
        'error': None,
        'redirect_hops': 0,
        'ssrf_blocked': False,
        'ssrf_reason': None,
    }
    res = analyze_url('http://example.pw/login', DummySession(), resolver=fake_resolver)
    assert res.status in {'SUSPICIOUS', 'MALICIOUS'}
    assert any('abuse rates' in r.lower() for r in res.reasons)


def test_long_redirect_chain_increases_risk(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(0))

    def fake_resolver(url, max_hops=5):
        return {
            'chain': [
                {'url': url, 'status': 301},
                {'url': 'http://mid.example.com', 'status': 302},
                {'url': 'http://final.example.net', 'status': 200},
            ],
            'final_url': 'http://final.example.net',
            'final_status': 200,
            'content_type': None,
            'error': None,
            'redirect_hops': 2,
            'ssrf_blocked': False,
            'ssrf_reason': None,
        }

    res = analyze_url('http://start.example.org', DummySession(), resolver=fake_resolver)
    assert res.status in {'SUSPICIOUS', 'MALICIOUS'}
    assert res.redirect_hops >= 2
