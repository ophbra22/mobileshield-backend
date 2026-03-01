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

BRAND_KEYWORDS = [
    # generic
    'bank',
    'paypal',
    'visa',
    'mastercard',
    'amex',
    'appleid',
    'google',
    'microsoft',
    'office',
    'outlook',
    'icloud',
    # israeli banks / fintech
    'leumi',
    'hapoalim',
    'discount',
    'mizrahi',
    'beinleumi',
    'onezero',
    'pepper',
]

# allowlist of official domains per brand to avoid false positives
BRAND_ALLOWLIST_DOMAINS: dict[str, set[str]] = {
    'paypal': {'paypal.com'},
    'google': {'google.com', 'youtube.com'},
    'microsoft': {'microsoft.com', 'office.com', 'live.com', 'outlook.com'},
    'appleid': {'apple.com', 'icloud.com'},
    'leumi': {'leumi.co.il'},
    'hapoalim': {'bankhapoalim.co.il', 'poalim.biz'},
    'discount': {'discountbank.co.il'},
    'mizrahi': {'mizrahitfahot.co.il', 'mtb.co.il'},
    'beinleumi': {'bankisrael.co.il', 'bnpparibas.com'},
    'pepper': {'pepper.co.il'},
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


def detect_typosquat(registered_domain: str) -> tuple[str | None, int | None, str]:
    candidate = (registered_domain or '').split('.')[0].lower()
    targets = set(
        [
            'wpengine',
            'cloudfront',
            'cloudflare',
            'firebaseapp',
            'netlify',
            'vercel',
            'github',
            'pages',
            'google',
            'microsoft',
            'apple',
            'paypal',
        ]
        + BRAND_KEYWORDS
    )
    best: tuple[str | None, int | None] = (None, None)
    for target in targets:
        dist = _levenshtein(candidate, target)
        if dist <= 2 and len(candidate) >= 6:
            if best[1] is None or dist < best[1]:
                best = (target, dist)
    return best[0], best[1], candidate


def detect_brand_impersonation(hostname: str, registered_domain: str) -> dict:
    """Detect brand keywords in hostname/subdomain that are not present/allowlisted on the registered domain."""
    hostname_l = hostname.lower()
    reg_l = registered_domain.lower() if registered_domain else ''
    brands_found = [bk for bk in BRAND_KEYWORDS if bk in hostname_l]
    allowlisted = False
    for b in brands_found:
        allowed = BRAND_ALLOWLIST_DOMAINS.get(b, set())
        if reg_l in allowed or any(reg_l.endswith('.' + a) for a in allowed):
            allowlisted = True
            break
    is_brand_in_subdomain = bool(brands_found)
    is_registered_domain_suspicious = any(bk in reg_l for bk in brands_found) is False
    typosquat_target, distance, normalized_candidate = detect_typosquat(registered_domain)
    return {
        'brands_found': brands_found,
        'is_brand_in_subdomain': is_brand_in_subdomain,
        'is_registered_domain_suspicious': is_registered_domain_suspicious and not allowlisted,
        'typosquat_target': typosquat_target,
        'typosquat_distance': distance,
        'normalized_candidate': normalized_candidate,
    }


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
