from __future__ import annotations

from html.parser import HTMLParser
from typing import List, Optional, Set
from urllib.parse import urljoin

import requests

from app.detection.models import ContentAnalysis

HTML_TIMEOUT = (3, 5)


class _LinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: List[str] = []
        self.form_inputs: Set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_name = None
        if tag in {'a', 'link'}:
            attr_name = 'href'
        elif tag in {'script', 'img', 'iframe'}:
            attr_name = 'src'
        elif tag == 'form':
            attr_name = 'action'
            self.form_inputs.add('form_present')
        if not attr_name:
            return
        for name, value in attrs:
            if name == attr_name and value:
                absolute = urljoin(self.base_url, value)
                self.links.append(absolute)
            if name in {'name', 'id', 'type'} and value:
                self.form_inputs.add(value.lower())


def analyze_content(final_url: str, content_type_hint: Optional[str]) -> ContentAnalysis:
    if not content_type_hint or 'text/html' not in content_type_hint:
        return ContentAnalysis(
            fetched=False,
            content_type=content_type_hint,
            has_form=False,
            credential_form=False,
            payment_form=False,
            brand_claim=None,
            outbound_domains=[],
            outbound_count=0,
            outbound_samples=[],
        )

    try:
        resp = requests.get(final_url, timeout=HTML_TIMEOUT, headers={'User-Agent': 'MobileShieldAI/1.0'}, allow_redirects=False)
    except Exception:  # pragma: no cover - network hiccups
        return ContentAnalysis(
            fetched=False,
            content_type=content_type_hint,
            has_form=False,
            credential_form=False,
            payment_form=False,
            brand_claim=None,
            outbound_domains=[],
            outbound_count=0,
            outbound_samples=[],
        )

    content_type = resp.headers.get('Content-Type', content_type_hint).split(';')[0].lower()
    html_text = resp.text[:200_000]
    parser = _LinkExtractor(final_url)
    parser.feed(html_text)
    lower_html = html_text.lower()

    brand_claim = None
    if '<title' in lower_html:
        start = lower_html.find('<title')
        end = lower_html.find('</title>', start)
        if end != -1:
            title_text = lower_html[start:end]
            brand_claim = title_text

    # Extract outbound domains
    from urllib.parse import urlparse
    import tldextract

    seen = set()
    domains: List[str] = []
    samples: List[str] = []

    for u in parser.links:
        parsed = urlparse(u)
        host = parsed.hostname or ''
        reg = tldextract.extract(host).registered_domain or host
        if reg and reg not in seen:
            seen.add(reg)
            domains.append(reg)
        if len(samples) < 20:
            samples.append(u)

    sensitive_inputs = {'password', 'pass', 'card', 'cc', 'cvv', 'cvc', 'iban', 'swift', 'account', 'routing', 'otp', 'pin', 'ssn'}
    credential_form = any(token in parser.form_inputs for token in sensitive_inputs)
    payment_form = any(token in parser.form_inputs for token in {'card', 'cc', 'cvv', 'cvc', 'iban', 'swift'})
    has_form = 'form_present' in parser.form_inputs

    return ContentAnalysis(
        fetched=True,
        content_type=content_type,
        has_form=has_form,
        credential_form=credential_form,
        payment_form=payment_form,
        brand_claim=brand_claim,
        outbound_domains=domains[:30],
        outbound_count=len(parser.links),
        outbound_samples=samples,
    )
