from __future__ import annotations

from typing import List

from app.detection.models import ScoreComponent


def build_reasons(components: List[ScoreComponent]) -> List[str]:
    seen = set()
    reasons: List[str] = []
    for comp in components:
        if comp.reason in seen:
            continue
        seen.add(comp.reason)
        reasons.append(comp.reason)
    return reasons
