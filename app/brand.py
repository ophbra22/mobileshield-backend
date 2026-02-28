from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import tldextract

PROTECTED_BRANDS = {
    'apple': 'apple.com',
    'google': 'google.com',
    'microsoft': 'microsoft.com',
    'paypal': 'paypal.com',
    'whatsapp': 'whatsapp.com',
    'telegram': 'telegram.org',
}

HOMOGLYPH_MAP = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    '@': 'a',
    '$': 's',
}


def _normalize_token(token: str) -> str:
    token = token.lower()
    for src, tgt in HOMOGLYPH_MAP.items():
        token = token.replace(src, tgt)
    token = token.replace('rn', 'm').replace('vv', 'w')
    return token


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            insert_cost = prev_row[j] + 1
            delete_cost = curr[j - 1] + 1
            replace_cost = prev_row[j - 1] + (ca != cb)
            curr.append(min(insert_cost, delete_cost, replace_cost))
        prev_row = curr
    return prev_row[-1]


@dataclass
class BrandLookalike:
    brand: str
    score: int
    method: str
    distance: int
    official_domain_matched: bool


def analyze_brand(domain: str) -> Optional[BrandLookalike]:
    extracted = tldextract.extract(domain)
    sld = extracted.domain or domain
    sld_norm = _normalize_token(sld)

    for brand, official_domain in PROTECTED_BRANDS.items():
        if is_official_domain(domain, official_domain):
            return None

        brand_norm = _normalize_token(brand)
        distance = _levenshtein(sld_norm, brand_norm)
        if distance <= 1:
            score = 25
            method = 'levenshtein'
        else:
            # check homoglyph proximity: if normalized sld contains brand_norm
            if brand_norm in sld_norm or sld_norm in brand_norm:
                score = 25
                method = 'homoglyph'
                distance = min(distance, 1)
            else:
                continue

        if extracted.subdomain.startswith('xn--') or domain.startswith('xn--'):
            score = 35

        return BrandLookalike(
            brand=brand,
            score=score,
            method=method,
            distance=distance,
            official_domain_matched=False,
        )
    return None


def is_official_domain(domain: str, official: str | None = None) -> bool:
    """Return True if domain matches or is a subdomain of an official brand domain."""
    if not domain:
        return False
    domain = domain.lower()
    if official:
        official_domain = official.lower()
        return domain == official_domain or domain.endswith(f'.{official_domain}')

    for official_domain in PROTECTED_BRANDS.values():
        if domain == official_domain or domain.endswith(f'.{official_domain}'):
            return True
    return False
