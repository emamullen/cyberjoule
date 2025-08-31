from typing import Dict, Any
import os, requests

DEFAULT_TIMEOUT = (5, 10)

def enrich_ioc(ioc_item: Dict[str, Any]) -> Dict[str, Any]:
    ioc_type = ioc_item.get("type")
    value = ioc_item.get("value")
    result = {"ioc": ioc_item, "hit": False, "providers": {}}

    # VirusTotal
    vt_key = os.getenv("VT_API_KEY")
    if vt_key:
        try:
            vt_res = _virustotal_lookup(ioc_type, value, vt_key)
            result["providers"]["virustotal"] = vt_res
            result["hit"] = result["hit"] or bool(vt_res.get("hit"))
        except Exception as e:
            result["providers"]["virustotal"] = {"error": str(e)}

    # OTX
    otx_key = os.getenv("OTX_API_KEY")
    if otx_key and ioc_type in ("ip", "domain"):
        try:
            otx_res = _otx_lookup(ioc_type, value, otx_key)
            result["providers"]["otx"] = otx_res
            result["hit"] = result["hit"] or bool(otx_res.get("hit"))
        except Exception as e:
            result["providers"]["otx"] = {"error": str(e)}

    # AbuseIPDB
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuse_key and ioc_type == "ip":
        try:
            abuse_res = _abuseipdb_lookup(value, abuse_key)
            result["providers"]["abuseipdb"] = abuse_res
            result["hit"] = result["hit"] or bool(abuse_res.get("hit"))
        except Exception as e:
            result["providers"]["abuseipdb"] = {"error": str(e)}

    # MISP
    misp_base = os.getenv("MISP_BASE_URL")
    misp_key = os.getenv("MISP_API_KEY")
    if misp_base and misp_key:
        try:
            misp_res = _misp_search(misp_base, misp_key, value)
            result["providers"]["misp"] = misp_res
            result["hit"] = result["hit"] or bool(misp_res.get("hit"))
        except Exception as e:
            result["providers"]["misp"] = {"error": str(e)}

    return result

def _virustotal_lookup(ioc_type: str, value: str, api_key: str) -> Dict[str, Any]:
    headers = {"x-apikey": api_key}
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{value}"
    elif ioc_type == "sha256":
        url = f"https://www.virustotal.com/api/v3/files/{value}"
    else:
        return {"supported": False}
    r = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
    if r.status_code == 200:
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        hit = malicious + suspicious > 0
        return {"supported": True, "hit": hit, "malicious": malicious, "suspicious": suspicious, "harmless": harmless}
    else:
        return {"supported": True, "error": f"HTTP {r.status_code}", "hit": False}

def _otx_lookup(ioc_type: str, value: str, api_key: str) -> Dict[str, Any]:
    headers = {"X-OTX-API-KEY": api_key}
    if ioc_type == "ip":
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{value}/general"
    else:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{value}/general"
    r = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
    if r.status_code == 200:
        j = r.json()
        pulses = j.get("pulse_info", {}).get("count", 0)
        reputation = j.get("reputation")
        hit = bool(pulses) or (reputation is not None and reputation < 0)
        return {"hit": hit, "pulses": pulses, "reputation": reputation}
    else:
        return {"error": f"HTTP {r.status_code}", "hit": False}

def _abuseipdb_lookup(ip: str, api_key: str) -> Dict[str, Any]:
    headers = {"Key": api_key, "Accept": "application/json"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 60}
    r = requests.get(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT)
    if r.status_code == 200:
        data = r.json().get("data", {})
        score = int(data.get("abuseConfidenceScore") or 0)
        total_reports = int(data.get("totalReports") or 0)
        hit = score >= 50 or total_reports > 0
        return {"hit": hit, "abuse_confidence": score, "total_reports": total_reports}
    else:
        return {"error": f"HTTP {r.status_code}", "hit": False}

def _misp_search(base_url: str, api_key: str, value: str) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/attributes/restSearch"
    headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}
    body = {"returnFormat": "json", "value": value, "limit": 1}
    r = requests.post(url, headers=headers, json=body, timeout=DEFAULT_TIMEOUT)
    if r.status_code == 200:
        j = r.json()
        has_attr = False
        if isinstance(j, dict):
            resp = j.get("response")
            if isinstance(resp, dict):
                attrs = resp.get("Attribute") or []
                has_attr = len(attrs) > 0
            elif isinstance(resp, list):
                has_attr = len(resp) > 0
            else:
                attrs = j.get("Attribute") or []
                has_attr = len(attrs) > 0
        return {"hit": bool(has_attr)}
    else:
        return {"error": f"HTTP {r.status_code}", "hit": False}
