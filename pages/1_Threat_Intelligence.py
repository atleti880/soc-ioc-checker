import base64
import re
from urllib.parse import urlparse

import pycountry
import requests
import streamlit as st

st.title("🧠 Threat Intelligence Workbench")

VT_API = st.secrets["VT_API"]
ABUSE_API = st.secrets["ABUSE_API"]

VT_HEADERS = {"x-apikey": VT_API}
ABUSE_HEADERS = {"Key": ABUSE_API, "Accept": "application/json"}

ioc = st.text_input("Introduce un IOC (IP, URL, hash o dominio)")

# -------------------------
# VALIDACIÓN
# -------------------------
def is_ip(value):
    pattern = r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
    return re.fullmatch(pattern, value) is not None


def is_hash(value):
    return re.fullmatch(r"([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", value)


def is_url(value):
    try:
        parsed = urlparse(value)
        return bool(parsed.netloc)
    except:
        return False


def is_domain(value):
    pattern = r"^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
    return re.fullmatch(pattern, value)


# -------------------------
# UTILIDADES
# -------------------------
def safe_json(response):
    try:
        return response.json()
    except:
        return {}


def vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def total_engines(stats):
    return sum(v for v in stats.values() if isinstance(v, int))


def get_severity(vt_mal, vt_susp, abuse):
    if abuse >= 80 or vt_mal >= 8:
        return "Critical"
    if abuse >= 50 or vt_mal >= 3:
        return "High"
    if vt_mal >= 1 or vt_susp >= 2:
        return "Medium"
    return "Low"


def classify(ioc_type, vt_mal, vt_susp, abuse):
    if ioc_type == "IP":
        if abuse > 70:
            return "Malicious Infrastructure"
        return "Suspicious IP"

    if ioc_type == "URL":
        if vt_mal >= 5:
            return "Phishing / Malware"
        return "Suspicious URL"

    if ioc_type == "HASH":
        if vt_mal >= 5:
            return "Malware"
        return "Suspicious File"

    if ioc_type == "DOMAIN":
        return "Suspicious Domain"

    return "Unknown"


# -------------------------
# LOOKUPS
# -------------------------
def vt_ip(ip):
    return requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers=VT_HEADERS
    )


def vt_hash(hash_value):
    return requests.get(
        f"https://www.virustotal.com/api/v3/files/{hash_value}",
        headers=VT_HEADERS
    )


def vt_url(url):
    return requests.get(
        f"https://www.virustotal.com/api/v3/urls/{vt_url_id(url)}",
        headers=VT_HEADERS
    )


def vt_domain(domain):
    return requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers=VT_HEADERS
    )


def abuse(ip):
    return requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=ABUSE_HEADERS,
        params={"ipAddress": ip}
    )


# -------------------------
# MAIN
# -------------------------
if ioc:
    ioc = ioc.strip()

    with st.spinner("Consultando Threat Intelligence..."):

        # IP
        if is_ip(ioc):
            st.subheader("Tipo: IP")

            vt_res = vt_ip(ioc)
            ab_res = abuse(ioc)

            vt_data = safe_json(vt_res)
            ab_data = safe_json(ab_res)

            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_mal = stats.get("malicious", 0)
            vt_susp = stats.get("suspicious", 0)
            vt_total = total_engines(stats)

            abuse_score = ab_data.get("data", {}).get("abuseConfidenceScore", 0)

            severity = get_severity(vt_mal, vt_susp, abuse_score)
            category = classify("IP", vt_mal, vt_susp, abuse_score)

            st.metric("VT Malicious", vt_mal)
            st.metric("Abuse Score", abuse_score)
            st.metric("Severity", severity)

            st.write(f"**Threat Category:** {category}")

        # HASH
        elif is_hash(ioc):
            st.subheader("Tipo: Hash")

            vt_res = vt_hash(ioc)
            vt_data = safe_json(vt_res)

            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_mal = stats.get("malicious", 0)
            vt_susp = stats.get("suspicious", 0)

            severity = get_severity(vt_mal, vt_susp, 0)
            category = classify("HASH", vt_mal, vt_susp, 0)

            st.metric("VT Malicious", vt_mal)
            st.metric("Severity", severity)

            st.write(f"**Threat Category:** {category}")

        # URL
        elif is_url(ioc):
            st.subheader("Tipo: URL")

            vt_res = vt_url(ioc)
            vt_data = safe_json(vt_res)

            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_mal = stats.get("malicious", 0)
            vt_susp = stats.get("suspicious", 0)

            severity = get_severity(vt_mal, vt_susp, 0)
            category = classify("URL", vt_mal, vt_susp, 0)

            st.metric("VT Malicious", vt_mal)
            st.metric("Severity", severity)

            st.write(f"**Threat Category:** {category}")

        # DOMAIN
        elif is_domain(ioc):
            st.subheader("Tipo: Dominio")

            vt_res = vt_domain(ioc)
            vt_data = safe_json(vt_res)

            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_mal = stats.get("malicious", 0)
            vt_susp = stats.get("suspicious", 0)

            severity = get_severity(vt_mal, vt_susp, 0)
            category = classify("DOMAIN", vt_mal, vt_susp, 0)

            st.metric("VT Malicious", vt_mal)
            st.metric("Severity", severity)

            st.write(f"**Threat Category:** {category}")

        else:
            st.warning("IOC no válido")
