"""
sources.py — ThreatLens intelligence-source module.

STRICT RULE: this file must NEVER import anything from app.py.
app.py imports FROM this file only (one-way dependency).

To add a new intelligence source later:
  1. Write one function  get_<name>(value, ioc_type, _api_keys) -> dict
     that returns the standard result shape (see _standard_result).
     Pull whatever key(s) it needs out of the _api_keys dict, e.g.
     _api_keys.get("my_new_source"); ignore the param if no key is needed.
  2. Add one line to the SOURCES dict at the bottom.
  3. Nothing else changes, anywhere.

KEYS: this build is bring-your-own-key (BYOK). Every visitor enters their
own API key(s) in the app.py sidebar; keys live only in st.session_state
for that browser session and are passed in via the _api_keys dict below.
The leading underscore tells Streamlit's cache_data to ignore this
argument when computing the cache key (dicts aren't hashable, and we WANT
the cache shared across different users' keys anyway, since VirusTotal
data for a given IOC doesn't depend on whose key fetched it).
"""

import re
import ipaddress
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import streamlit as st

try:
    import whois as pywhois
except ImportError:
    pywhois = None


# ============================================================================
# INPUT HELPERS
# ============================================================================

def detect_ioc_type(value: str) -> str:
    """Return 'ip', 'domain', or 'url'. Raises ValueError if undetectable."""
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if "://" in value or value.startswith("www."):
        return "url"

    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
    if re.match(domain_pattern, value):
        return "domain"

    if "/" in value or "." in value:
        return "url"

    raise ValueError("Could not detect IOC type. Please select it manually.")


def is_valid_ioc(value: str, ioc_type: str) -> bool:
    """Validate value against the declared ioc_type."""
    value = value.strip()
    if not value:
        return False

    if ioc_type == "ip":
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    if ioc_type == "domain":
        domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
        return bool(re.match(domain_pattern, value))

    if ioc_type == "url":
        parsed = urlparse(value if "://" in value else "http://" + value)
        return bool(parsed.netloc)

    return False


def extract_domain(value: str) -> str:
    """Pull the bare domain out of a URL (strips scheme, port, www.)."""
    candidate = value if "://" in value else "http://" + value
    netloc = urlparse(candidate).netloc
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc


# ============================================================================
# STANDARD RESULT CONTRACT
# ============================================================================

def _standard_result(source, verdict="Unknown", risk_score=0, raw_data=None, error=None):
    return {
        "source": source,
        "verdict": verdict,          # Safe | Suspicious | Malicious | Unknown | Error
        "risk_score": risk_score,    # 0-100
        "raw_data": raw_data or {},
        "error": error,
    }


# ============================================================================
# SOURCE: VIRUSTOTAL
# ============================================================================

@st.cache_data(ttl=1800, show_spinner=False)
def get_virustotal(value: str, ioc_type: str, _api_keys: dict) -> dict:
    source = "VirusTotal"
    api_key = (_api_keys or {}).get("virustotal", "").strip()
    if not api_key:
        return _standard_result(source, "Error", 0, {},
                                 "No VirusTotal API key entered. Add your key in the sidebar.")

    headers = {"x-apikey": api_key}

    try:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{value}"
        elif ioc_type == "url":
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return _standard_result(source, "Error", 0, {}, f"Unsupported IOC type: {ioc_type}")

        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code == 404:
            return _standard_result(source, "Unknown", 0, {}, "No data found for this IOC in VirusTotal.")

        resp.raise_for_status()
        data = resp.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if total == 0:
            return _standard_result(source, "Unknown", 0, attributes,
                                     "VirusTotal has no analysis engines reporting on this IOC yet.")

        raw_score = (malicious * 100 + suspicious * 50) / total
        risk_score = min(100, round(raw_score))

        if malicious >= 5 or risk_score >= 50:
            verdict = "Malicious"
        elif malicious > 0 or suspicious > 0 or risk_score >= 10:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        raw_data = {
            "last_analysis_stats": stats,
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "tags": attributes.get("tags"),
        }

        return _standard_result(source, verdict, risk_score, raw_data, None)

    except requests.exceptions.RequestException as e:
        return _standard_result(source, "Error", 0, {}, f"VirusTotal request failed: {e}")
    except Exception as e:
        return _standard_result(source, "Error", 0, {}, f"Unexpected VirusTotal error: {e}")


# ============================================================================
# SOURCE: WHOIS
# ============================================================================

@st.cache_data(ttl=1800, show_spinner=False)
def get_whois(value: str, ioc_type: str, _api_keys: dict) -> dict:
    # WHOIS needs no API key — _api_keys is accepted only so every source
    # function shares one uniform signature for the generic app.py loop.
    source = "WHOIS"

    if ioc_type == "ip":
        return _standard_result(
            source, "Unknown", 0, {},
            "WHOIS domain registration data does not apply to raw IP addresses."
        )

    if pywhois is None:
        return _standard_result(source, "Error", 0, {}, "python-whois package is not installed.")

    try:
        domain = extract_domain(value) if ioc_type == "url" else value
        w = pywhois.whois(domain)

        def _first(field):
            return field[0] if isinstance(field, list) else field

        creation_date = _first(w.creation_date)
        expiration_date = _first(w.expiration_date)
        updated_date = _first(w.updated_date)

        raw_data = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(creation_date) if creation_date else None,
            "expiration_date": str(expiration_date) if expiration_date else None,
            "updated_date": str(updated_date) if updated_date else None,
            "name_servers": w.name_servers,
            "status": w.status,
            "country": getattr(w, "country", None),
        }

        if not creation_date:
            return _standard_result(source, "Unknown", 0, raw_data,
                                     "Could not determine domain creation date.")

        now = datetime.now(timezone.utc) if creation_date.tzinfo else datetime.now()
        age_days = (now - creation_date).days
        raw_data["domain_age_days"] = age_days

        if age_days < 30:
            verdict, risk_score = "Suspicious", 65
        elif age_days < 180:
            verdict, risk_score = "Suspicious", 35
        else:
            verdict, risk_score = "Safe", 5

        return _standard_result(source, verdict, risk_score, raw_data, None)

    except Exception as e:
        return _standard_result(source, "Error", 0, {}, f"WHOIS lookup failed: {e}")


# ============================================================================
# SOURCES REGISTRY — the one and only extensibility seam
# ============================================================================

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
