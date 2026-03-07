from __future__ import annotations

import ipaddress
from typing import Optional

from app.detection.models import ServerAnalysis


def analyze_server(ip: Optional[str], ip_version: Optional[str]) -> ServerAnalysis:
    is_private = False
    if ip:
        try:
            ip_obj = ipaddress.ip_address(ip)
            is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved
        except ValueError:
            is_private = False
    return ServerAnalysis(ip=ip, ip_version=ip_version, is_private=is_private, geo=None)
