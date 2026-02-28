import types
from unittest import mock

from app.analysis import analyze_url
from app.brand import BrandLookalike


class DummySession:
    pass


def _rep_result(domain_nxdomain: bool, score_hint: int = 0):
    cache = mock.Mock()
    cache.reputation = 'suspicious' if score_hint else 'unknown'
    cache.score_hint = score_hint
    cache.signals = {'dns_nxdomain': domain_nxdomain, 'domain_nxdomain': domain_nxdomain}
    cache.sources = {'reasons': ['Domain is NXDOMAIN'] if domain_nxdomain else []}
    return cache, cache.signals, score_hint, cache.sources['reasons']


def test_official_domain_no_brand_bait(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(False, 0))
    monkeypatch.setattr('app.analysis.analyze_brand', lambda d: None)
    result = analyze_url('https://google.com', DummySession())
    assert all('brand-related' not in r for r in result.reasons)
    assert result.risk_score == 0


def test_nxdomain_with_strong_indicators_high_confidence(monkeypatch):
    monkeypatch.setattr('app.analysis.get_or_compute_domain_reputation', lambda db, d: _rep_result(True, 40))
    monkeypatch.setattr(
        'app.analysis.analyze_brand',
        lambda d: BrandLookalike(brand='apple', score=25, method='levenshtein', distance=1, official_domain_matched=False),
    )
    res = analyze_url('https://apple-secure-login-verification.com/login', DummySession())
    assert res.confidence == 'high'
    assert res.verdict in {'malicious', 'suspicious'}
