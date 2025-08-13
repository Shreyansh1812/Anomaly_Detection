from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import ipaddress

try:
    import regex as re  # type: ignore
except Exception:  # pragma: no cover - fallback
    import re  # type: ignore

try:
    import geoip2.database  # type: ignore
except Exception:  # pragma: no cover - optional
    geoip2 = None  # type: ignore

# External services are optional and off by default.
try:
    from abuseipdb import AbuseIPDB  # type: ignore
except Exception:  # pragma: no cover
    AbuseIPDB = None  # type: ignore

try:
    import ipqualityscore  # type: ignore
except Exception:  # pragma: no cover
    ipqualityscore = None  # type: ignore


def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def extract_ips_from_texts(texts: List[str]) -> List[str]:
    # Robust IPv4/IPv6 regex; prefer IPv4 in these datasets
    ipv4 = r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})"
    # Common Linux auth fields: rhost=IP, from IP, Disconnected from IP, Connection closed by IP
    patterns = [
        rf"(?i)rhost\s*=\s*({ipv4})",
        rf"(?i)\bfrom\s+({ipv4})\b",
        rf"(?i)Disconnected from\s+({ipv4})",
        rf"(?i)Connection closed by\s+({ipv4})",
    ]
    compiled = [re.compile(p) for p in patterns]
    out: List[str] = []
    for t in texts:
        if not t:
            continue
        found: Optional[str] = None
        for cp in compiled:
            m = cp.search(t)
            if m:
                found = m.group(1)
                break
        if found and is_valid_ip(found):
            out.append(found)
    return out


def geoip_lookup(ip: str, db_path: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if not db_path or not geoip2:
        return None, None, None
    try:
        with geoip2.database.Reader(db_path) as reader:  # type: ignore
            city = reader.city(ip)
            country = city.country.name or None
            city_name = city.city.name or None
        # ASN db often a separate file; ignore if not provided
        asn_name = None
    except Exception:
        country = city_name = asn_name = None
    return country, city_name, asn_name


def abuse_lookup(ip: str, api_key: Optional[str]) -> Optional[int]:
    if not api_key or not AbuseIPDB:
        return None
    try:
        client = AbuseIPDB(api_key=api_key)  # type: ignore
        data = client.check(ip)
        # Normalize 0-100
        score = int(data.get("abuseConfidenceScore", 0))
        return max(0, min(100, score))
    except Exception:
        return None


def ipqs_lookup(ip: str, api_key: Optional[str]) -> Optional[int]:
    if not api_key or not ipqualityscore:
        return None
    try:
        # Minimal usage without network by design is not possible; keep optional
        resp = ipqualityscore.IPQualityScore(api_key).ip(ip)  # type: ignore
        score = int(resp.get("fraud_score", 0))
        return max(0, min(100, score))
    except Exception:
        return None


def enrich_ips(ip_counts: Dict[str, int], cfg: Dict) -> List[Dict]:
    enrich_cfg = cfg.get("enrichment", {}) if isinstance(cfg, dict) else {}
    enabled = bool(enrich_cfg.get("enabled", False))
    if not enabled:
        return []
    top_n = int(enrich_cfg.get("top_n", 10))
    geo_db = enrich_cfg.get("geoip2_city_db")
    abuse_key = enrich_cfg.get("abuseipdb_api_key") if enrich_cfg.get("abuseipdb_enabled", False) else None
    ipqs_key = enrich_cfg.get("ipqs_api_key") if enrich_cfg.get("ipqs_enabled", False) else None

    # Prepare ips sorted by events desc
    items = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    enriched: List[Dict] = []
    for ip, events in items:
        if not is_valid_ip(ip):
            continue
        country, city, asn = geoip_lookup(ip, geo_db)
        abuse = abuse_lookup(ip, abuse_key)
        iq = ipqs_lookup(ip, ipqs_key)
        risk = None
        if abuse is not None:
            risk = int(events * abuse)
        enriched.append({
            "ip": ip,
            "events": int(events),
            "country": country,
            "city": city,
            "asn": asn,
            "abuse_score": abuse,
            "ipqs_score": iq,
            "risk": risk,
        })
    # Sort by risk then events
    enriched.sort(key=lambda d: (d.get("risk") or 0, d.get("events") or 0), reverse=True)
    return enriched
