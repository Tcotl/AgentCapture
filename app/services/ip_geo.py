"""Attacker IP classification: internal-vs-public and region resolution.

Internal/reserved addresses (RFC1918, loopback, link-local, CGNAT, ULA…) are
classified locally and instantly. Public addresses resolve their country via
the 微步在线 integration when it is enabled; without a provider the IP is
labelled 公网·未接入情报 rather than guessed. Results cache for 24h per IP —
attacker source IPs repeat heavily.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from typing import Any

_CACHE_TTL_SECONDS = 24 * 3600.0
_lock = threading.Lock()
_cache: dict[str, tuple[float, dict[str, Any]]] = {}

_INTERNAL_LABELS: list[tuple[str, str]] = [
    ("127.0.0.0/8", "内网 · 回环地址"),
    ("169.254.0.0/16", "内网 · 链路本地"),
    ("100.64.0.0/10", "内网 · 运营商级 NAT"),
    ("224.0.0.0/4", "保留 · 组播"),
    ("fe80::/10", "内网 · 链路本地"),
]


def _internal_label(ip: ipaddress._BaseAddress) -> str:
    for net, label in _INTERNAL_LABELS:
        try:
            if ip in ipaddress.ip_network(net):
                return label
        except ValueError:
            continue
    if ip.is_loopback:
        return "内网 · 回环地址"
    if ip.is_link_local:
        return "内网 · 链路本地"
    if ip.is_multicast:
        return "保留 · 组播"
    if ip.is_private:
        return "内网 · 私有地址"
    if getattr(ip, "is_global", False):
        return "公网"
    return "保留 / 特殊地址"


def _public_region(ip_text: str) -> dict[str, Any]:
    """Country resolution for public IPs via ThreatBook (best effort)."""
    from app.services import threatbook

    if not threatbook.is_enabled():
        return {"region": "公网 · 未知地区", "country": "", "source": "none"}
    result = threatbook.lookup_ip(ip_text)
    if not result.get("ok"):
        region = "公网 · 未知地区"
        if "无效" in (result.get("error") or "") or "配额" in (result.get("error") or ""):
            region = "公网 · 情报查询受限"
        return {"region": region, "country": "", "source": "threatbook-error"}
    country = (result.get("location") or "").split(" ")[0].strip()
    region = f"公网 · {country}" if country else "公网 · 未知地区"
    return {"region": region, "country": country, "source": "threatbook"}


def classify_ip(ip_text: str, *, refresh: bool = False) -> dict[str, Any]:
    ip_text = (ip_text or "").strip()
    if not ip_text or ip_text == "unknown":
        return {"ip": ip_text, "kind": "unknown", "internal": False, "region": "未知", "source": "none"}
    cached = _cache.get(ip_text)
    if cached and time.monotonic() - cached[0] < _CACHE_TTL_SECONDS and not refresh:
        return cached[1]
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        result = {"ip": ip_text, "kind": "unknown", "internal": False, "region": "非 IP 值", "source": "none"}
        _store(ip_text, result)
        return result

    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        result = {
            "ip": ip_text,
            "kind": "internal",
            "internal": True,
            "region": _internal_label(ip),
            "source": "local",
        }
    else:
        info = _public_region(ip_text)
        result = {
            "ip": ip_text,
            "kind": "public",
            "internal": False,
            "region": info["region"],
            "country": info.get("country", ""),
            "source": info.get("source", "none"),
        }
    _store(ip_text, result)
    return result


def _store(ip_text: str, result: dict[str, Any]) -> None:
    with _lock:
        if len(_cache) > 5000:
            _cache.clear()
        _cache[ip_text] = (time.monotonic(), result)


def ip_info_map(ips: list[str]) -> dict[str, dict[str, Any]]:
    """Batch helper for templates: {ip: classify result} (cached lookups)."""
    return {ip: classify_ip(ip) for ip in {i for i in ips if i}}
