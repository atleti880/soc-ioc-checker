import streamlit as st
import requests
import re
import base64
from urllib.parse import urlparse
import pycountry

VT_API = st.secrets["VT_API"]
ABUSE_API = st.secrets["ABUSE_API"]

st.set_page_config(page_title="SOC IOC Checker", page_icon="🛡️", layout="wide")

st.title("SOC IOC Checker")
st.caption("Consulta IP / URL / Hash en VirusTotal y AbuseIPDB")

ioc = st.text_input("Introduce IP / URL / Hash")

VT_HEADERS = {"x-apikey": VT_API}
ABUSE_HEADERS = {"Key": ABUSE_API, "Accept": "application/json"}


# ------------------------
# FUNCIONES DE VALIDACIÓN
# ------------------------

def is_ip(value):
    pattern = r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
    return re.fullmatch(pattern, value) is not None


def is_hash(value):
    return re.fullmatch(r"([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", value) is not None


def is_url(value):
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except:
        return False


# ------------------------
# UTILIDADES
# ------------------------

def vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def country_name_from_code(code):
    try:
        return pycountry.countries.get(alpha_2=code).name
    except:
        return code


def safe_json(response):
    try:
        return response.json()
    except:
        return {}


# ------------------------
# CONSULTAS API
# ------------------------

def vt_ip_lookup(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    return requests.get(url, headers=VT_HEADERS, timeout=20)


def vt_hash_lookup(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    return requests.get(url, headers=VT_HEADERS, timeout=20)


def vt_url_lookup(url_value):
    url_id = vt_url_id(url_value)
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    return requests.get(url, headers=VT_HEADERS, timeout=20)


def abuse_lookup(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    return requests.get(url, headers=ABUSE_HEADERS, params=params, timeout=20)


# ------------------------
# VEREDICTO
# ------------------------

def get_verdict(vt_malicious=0, vt_suspicious=0, abuse_score=0):

    if abuse_score >= 80 or vt_malicious >= 5:
        return "Malicioso", "high"

    if abuse_score >= 30 or vt_malicious >= 1 or vt_suspicious >= 3:
        return "Sospechoso", "medium"

    return "Bajo riesgo", "low"


def show_verdict(verdict, severity):

    if severity == "high":
        st.error(f"Veredicto: {verdict}")

    elif severity == "medium":
        st.warning(f"Veredicto: {verdict}")

    else:
        st.success(f"Veredicto: {verdict}")


# ------------------------
# LÓGICA PRINCIPAL
# ------------------------

if ioc:

    ioc = ioc.strip()

    with st.spinner("Consultando fuentes de inteligencia..."):

        # ------------------------
        # IP
        # ------------------------

        if is_ip(ioc):

            st.info("Tipo detectado: IP")

            vt_response = vt_ip_lookup(ioc)
            abuse_response = abuse_lookup(ioc)

            vt = safe_json(vt_response)
            abuse = safe_json(abuse_response)

            attr = vt.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})

            vt_malicious = stats.get("malicious", 0)
            vt_suspicious = stats.get("suspicious", 0)
            vt_harmless = stats.get("harmless", 0)

            country = attr.get("country", "N/A")
            as_owner = attr.get("as_owner", "N/A")
            reputation = attr.get("reputation", "N/A")

            abuse_score = abuse.get("data", {}).get("abuseConfidenceScore", 0)
            reports = abuse.get("data", {}).get("totalReports", 0)

            verdict, severity = get_verdict(
                vt_malicious,
                vt_suspicious,
                abuse_score
            )

            show_verdict(verdict, severity)

            st.subheader("Resumen")

            st.write(
                f"La IP **{ioc}** presenta "
                f"**{vt_malicious} detecciones maliciosas** y "
                f"**{vt_suspicious} sospechosas** en VirusTotal, "
                f"con **abuse score {abuse_score}** en AbuseIPDB."
            )

            col1, col2, col3, col4, col5 = st.columns(5)

            col1.metric("VT Malicious", vt_malicious)
            col2.metric("VT Suspicious", vt_suspicious)
            col3.metric("VT Harmless", vt_harmless)
            col4.metric("Abuse Score", abuse_score)
            col5.metric("Reports", reports)

            st.subheader("Contexto")

            country_name = country_name_from_code(country)

            c1, c2, c3 = st.columns(3)

            flag = country.lower()
            c1.image(f"https://flagcdn.com/w40/{flag}.png", width=40)
            c1.write(f"**País:** {country_name} ({country})")

            c2.write(f"**AS Owner:** {as_owner}")
            c3.write(f"**VT Reputation:** {reputation}")

            st.subheader("Enlaces")

            st.markdown(
                f"[Abrir en VirusTotal](https://www.virustotal.com/gui/ip-address/{ioc})"
            )

            st.markdown(
                f"[Abrir en AbuseIPDB](https://www.abuseipdb.com/check/{ioc})"
            )

            ticket_text = f"""
IOC analizado: {ioc}
Tipo: IP
VirusTotal: malicious={vt_malicious}, suspicious={vt_suspicious}, harmless={vt_harmless}
AbuseIPDB: abuseConfidenceScore={abuse_score}, totalReports={reports}
País: {country_name} ({country})
AS Owner: {as_owner}
Conclusión: {verdict}
"""

            st.subheader("Texto para ticket")
            st.code(ticket_text, language="text")

        # ------------------------
        # HASH
        # ------------------------

        elif is_hash(ioc):

            st.info("Tipo detectado: Hash")

            vt_response = vt_hash_lookup(ioc)
            vt = safe_json(vt_response)

            attr = vt.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})

            vt_malicious = stats.get("malicious", 0)
            vt_suspicious = stats.get("suspicious", 0)
            vt_harmless = stats.get("harmless", 0)

            file_name = attr.get("meaningful_name", "N/A")
            file_type = attr.get("type_description", "N/A")
            size = attr.get("size", "N/A")

            verdict, severity = get_verdict(
                vt_malicious,
                vt_suspicious,
                0
            )

            show_verdict(verdict, severity)

            col1, col2, col3 = st.columns(3)

            col1.metric("VT Malicious", vt_malicious)
            col2.metric("VT Suspicious", vt_suspicious)
            col3.metric("VT Harmless", vt_harmless)

            st.subheader("Contexto")

            st.write(f"**Nombre de archivo:** {file_name}")
            st.write(f"**Tipo de archivo:** {file_type}")
            st.write(f"**Tamaño:** {size}")

            st.subheader("Enlaces")

            st.markdown(
                f"[Abrir en VirusTotal](https://www.virustotal.com/gui/file/{ioc})"
            )

        # ------------------------
        # URL
        # ------------------------

        elif is_url(ioc):

            st.info("Tipo detectado: URL")

            vt_response = vt_url_lookup(ioc)
            vt = safe_json(vt_response)

            attr = vt.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})

            vt_malicious = stats.get("malicious", 0)
            vt_suspicious = stats.get("suspicious", 0)
            vt_harmless = stats.get("harmless", 0)

            verdict, severity = get_verdict(
                vt_malicious,
                vt_suspicious,
                0
            )

            show_verdict(verdict, severity)

            col1, col2, col3 = st.columns(3)

            col1.metric("VT Malicious", vt_malicious)
            col2.metric("VT Suspicious", vt_suspicious)
            col3.metric("VT Harmless", vt_harmless)

            st.subheader("Enlaces")

            st.markdown(
                f"[Abrir en VirusTotal](https://www.virustotal.com/gui/url/{vt_url_id(ioc)})"
            )

        else:

            st.warning(
                "Tipo de IOC no reconocido. Introduce IP, URL o hash."
            )
