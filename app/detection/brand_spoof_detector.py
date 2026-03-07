from __future__ import annotations

from typing import List, Optional

import tldextract

from app.brand import analyze_brand, detect_brand_impersonation, detect_typosquat, is_official_domain
from app.detection.config import DEFAULT_CONFIG
from app.detection.models import BrandAnalysis, URLParts


def analyze_brand_signals(parts: URLParts, config=DEFAULT_CONFIG) -> BrandAnalysis:
    hostname = parts.hostname
    registrable = parts.registrable_domain

    brand_keywords = [bk for bk in config.brand_keywords if bk in hostname or bk in parts.path.lower()]
    impersonation = detect_brand_impersonation(hostname, registrable)
    brand_in_subdomain = impersonation.get('is_brand_in_subdomain', False)

    lookalike = analyze_brand(registrable)
    typosquat_target, typosquat_distance, _ = detect_typosquat(registrable)
    brand = lookalike.brand if lookalike else (brand_keywords[0] if brand_keywords else None)

    return BrandAnalysis(
        impersonates_brand=bool(impersonation.get('is_registered_domain_suspicious')) or bool(lookalike) or bool(brand_keywords and not is_official_domain(registrable)),
        brand=brand,
        lookalike_score=lookalike.score if lookalike else None,
        method=lookalike.method if lookalike else None,
        typosquat_target=typosquat_target,
        typosquat_distance=typosquat_distance,
        official_domain=is_official_domain(registrable),
        brand_keyword_hits=brand_keywords,
        brand_in_subdomain=brand_in_subdomain,
    )
