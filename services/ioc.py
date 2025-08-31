from typing import Dict, Any, List, Set
import re

_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL_RE = re.compile(r"https?://[^\s\"']+")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_DOMAIN_RE = re.compile(r"\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,24}\b")

def _maybe_add(s: Set[str], value: str) -> None:
    if value and isinstance(value, str):
        s.add(value.strip())

def extract_iocs(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    events = data.get("events", [])
    ips: Set[str] = set()
    domains: Set[str] = set()
    urls: Set[str] = set()
    hashes: Set[str] = set()

    for ev in events:
        for fld in ("src_ip", "dest_ip"):
            _maybe_add(ips, ev.get(fld))
        _maybe_add(domains, ev.get("domain"))
        _maybe_add(urls, ev.get("url"))

        val = ev.get("file_hash")
        if isinstance(val, str) and _SHA256_RE.search(val):
            hashes.add(val.strip())

        msg = ev.get("message") or ""
        if isinstance(msg, str):
            ips.update(_IP_RE.findall(msg))
            urls.update(_URL_RE.findall(msg))
            hashes.update(_SHA256_RE.findall(msg))
            msg_no_urls = _URL_RE.sub(" ", msg)
            domains.update(_DOMAIN_RE.findall(msg_no_urls))

        for u in list(urls):
            try:
                host = re.sub(r"^https?://", "", u).split("/")[0]
                if _DOMAIN_RE.fullmatch(host):
                    domains.add(host)
            except Exception:
                pass

    out: List[Dict[str, Any]] = []
    out += [{"type": "ip", "value": v} for v in sorted(ips)]
    out += [{"type": "domain", "value": v.lower()} for v in sorted(domains)]
    out += [{"type": "url", "value": v} for v in sorted(urls)]
    out += [{"type": "sha256", "value": v.lower()} for v in sorted(hashes)]
    return out
