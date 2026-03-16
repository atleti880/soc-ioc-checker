import base64
import re
from urllib.parse import urlparse

import pycountry
import requests
import streamlit as st

VT_API = st.secrets["VT_API"]
ABUSE_API = st.secrets["ABUSE_API"]

VT_HEADERS = {"x-apikey": VT_API}
ABUSE_HEADERS = {"Key": ABUSE_API, "Accept": "application/json"}

st.set_page_config(page_title="SOC IOC Checker", page_icon="🛡️", layout="wide")

st.title("SOC IOC Checker")
st.caption("Consulta IP / URL / Hash en VirusTotal y AbuseIPDB")

ioc = st.text_input("Introduce IP / URL / Hash")


# -------------------------
# Validación
# -------------------------

def is_ip(value: str) -> bool:
    pattern = r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
    return re.fullmatch(pattern, value) is not None


def is_hash(value: str) -> bool:
    return re.fullmatch(r"([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", value) is not None


def is_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


# -------------------------
# Utilidades
# -------------------------

def safe_json(response: requests.Response) -> dict:
    try:
        return response.json()
    except Exception:
        return {}


def country_name_from_code(code: str) -> str:
    if not code or code == "N/A":
        return "N/A"
    try:
        country = pycountry.countries.get(alpha_2=code.upper())
        return country.name if country else code
    except Exception:
        return code


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def total_engines_from_stats(stats: dict) -> int:
    if not isinstance(stats, dict):
        return 0
    total = 0
    for value in stats.values():
        if isinstance(value, int):
            total += value
    return total


def get_verdict(vt_malicious: int = 0, vt_suspicious: int = 0, abuse_score: int = 0):
    if abuse_score >= 80 or vt_malicious >= 5:
        return "Malicioso", "high"
    if abuse_score >= 30 or vt_malicious >= 1 or vt_suspicious >= 3:
        return "Sospechoso", "medium"
    return "Bajo riesgo", "low"


def show_verdict(verdict: str, severity: str):
    if severity == "high":
        st.error(f"Veredicto: {verdict}")
    elif severity == "medium":
        st.warning(f"Veredicto: {verdict}")
    else:
        st.success(f"Veredicto: {verdict}")


def show_api_error(source: str, response: requests.Response):
    data = safe_json(response)
    message = (
        data.get("error", {}).get("message")
        or data.get("errors")
        or response.text[:300]
        or "Error desconocido"
    )
    st.error(f"{source} devolvió error {response.status_code}: {message}")


def render_vt_score_card(malicious: int, total: int):
    percent = 0 if total == 0 else round((malicious / total) * 100)
    card_html = f"""
    <div style="
        background:#1f2a44;
        border-radius:14px;
        padding:22px 18px;
        text-align:center;
        width:220px;
        margin-bottom:12px;
    ">
        <div style="
            width:120px;
            height:120px;
            border-radius:50%;
            margin:0 auto 12px auto;
            background:
                conic-gradient(#ff5a52 {percent}%, #31456e 0%);
            display:flex;
            align-items:center;
            justify-content:center;
        ">
            <div style="
                width:88px;
                height:88px;
                border-radius:50%;
                background:#1f2a44;
                display:flex;
                flex-direction:column;
                align-items:center;
                justify-content:center;
            ">
                <div style="font-size:22px; color:#ff5a52; line-height:1; font-weight:700;">
                    {malicious}
                </div>
                <div style="font-size:14px; color:#c9d4ea; line-height:1.2; margin-top:4px;">
                    / {total}
                </div>
            </div>
        </div>
        <div style="font-size:14px; color:#c9d4ea; font-weight:600;">
            VT Community Score
        </div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


# -------------------------
# API lookups
# -------------------------

def vt_ip_lookup(ip: str) -> requests.Response:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    return requests.get(url, headers=VT_HEADERS, timeout=20)


def vt_hash_lookup(hash_value: str) -> requests.Response:
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    return requests.get(url, headers=VT_HEADERS, timeout=20)


def vt_url_lookup(url_value: str) -> requests.Response:
    url_id = vt_url_id(url_value)
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    return requests.get(url, headers=VT_HEADERS, timeout=20)


def abuse_lookup(ip: str) -> requests.Response:
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    return requests.get(url, headers=ABUSE_HEADERS, params=params, timeout=20)


# -------------------------
# Main
# -------------------------

if ioc:
    ioc = ioc.strip()

    with st.spinner("Consultando fuentes de inteligencia..."):

        # =========================
        # IP
        # =========================
        if is_ip(ioc):
            st.info("Tipo detectado: IP")

            try:
                vt_response = vt_ip_lookup(ioc)
                abuse_response = abuse_lookup(ioc)
            except requests.RequestException as e:
                st.error(f"Error de red al consultar APIs: {e}")
                st.stop()

            vt_malicious = 0
            vt_suspicious = 0
            vt_harmless = 0
            vt_total = 0
            country_code = "N/A"
            as_owner = "N/A"
            reputation = "N/A"
            abuse_score = 0
            reports = 0

            if vt_response.status_code == 200:
                vt = safe_json(vt_response)
                attr = vt.get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                vt_malicious = stats.get("malicious", 0)
                vt_suspicious = stats.get("suspicious", 0)
                vt_harmless = stats.get("harmless", 0)
                vt_total = total_engines_from_stats(stats)
                country_code = attr.get("country", "N/A")
                as_owner = attr.get("as_owner", "N/A")
                reputation = attr.get("reputation", "N/A")
            else:
                show_api_error("VirusTotal", vt_response)

            if abuse_response.status_code == 200:
                abuse = safe_json(abuse_response)
                data = abuse.get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
            else:
                show_api_error("AbuseIPDB", abuse_response)

            verdict, severity = get_verdict(vt_malicious, vt_suspicious, abuse_score)
            show_verdict(verdict, severity)

            st.subheader("Resumen")
            st.write(
                f"La IP **{ioc}** presenta **{vt_malicious}/{vt_total if vt_total else 0}** "
                f"en VirusTotal, **{vt_suspicious}** detecciones sospechosas y "
                f"**abuse score {abuse_score}** con **{reports} reportes** en AbuseIPDB."
            )

            score_col, metrics_col = st.columns([1, 3])

            with score_col:
                render_vt_score_card(vt_malicious, vt_total)

            with metrics_col:
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("VT Malicious", vt_malicious)
                m2.metric("VT Suspicious", vt_suspicious)
                m3.metric("Abuse Score", abuse_score)
                m4.metric("Reports", reports)

            st.subheader("Contexto")
            country_name = country_name_from_code(country_code)
            c1, c2, c3 = st.columns(3)
            c1.write(f"**País:** {country_name} ({country_code})")
            c2.write(f"**AS Owner:** {as_owner}")
            c3.write(f"**VT Reputation:** {reputation}")

            st.subheader("Enlaces")
            st.markdown(f"[Abrir en VirusTotal](https://www.virustotal.com/gui/ip-address/{ioc})")
            st.markdown(f"[Abrir en AbuseIPDB](https://www.abuseipdb.com/check/{ioc})")

            ticket_text = f"""IOC analizado: {ioc}
Tipo: IP
VirusTotal: score={vt_malicious}/{vt_total}, suspicious={vt_suspicious}, reputation={reputation}
AbuseIPDB: abuseConfidenceScore={abuse_score}, totalReports={reports}
País: {country_name} ({country_code})
AS Owner: {as_owner}
Conclusión: {verdict}
"""
            st.subheader("Texto para ticket")
            st.code(ticket_text, language="text")

        # =========================
        # HASH
        # =========================
        elif is_hash(ioc):
            st.info("Tipo detectado: Hash")

            try:
                vt_response = vt_hash_lookup(ioc)
            except requests.RequestException as e:
                st.error(f"Error de red al consultar VirusTotal: {e}")
                st.stop()

            if vt_response.status_code == 200:
                vt = safe_json(vt_response)
                attr = vt.get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})

                vt_malicious = stats.get("malicious", 0)
                vt_suspicious = stats.get("suspicious", 0)
                vt_total = total_engines_from_stats(stats)

                file_name = attr.get("meaningful_name", "N/A")
                file_type = attr.get("type_description", "N/A")
                size = attr.get("size", "N/A")
                sha256 = attr.get("sha256", "N/A")

                verdict, severity = get_verdict(vt_malicious, vt_suspicious, 0)
                show_verdict(verdict, severity)

                st.subheader("Resumen")
                st.write(
                    f"El hash **{ioc}** presenta **{vt_malicious}/{vt_total if vt_total else 0}** "
                    f"en VirusTotal y **{vt_suspicious}** detecciones sospechosas."
                )

                score_col, metrics_col = st.columns([1, 3])

                with score_col:
                    render_vt_score_card(vt_malicious, vt_total)

                with metrics_col:
                    m1, m2 = st.columns(2)
                    m1.metric("VT Malicious", vt_malicious)
                    m2.metric("VT Suspicious", vt_suspicious)

                st.subheader("Contexto")
                c1, c2, c3 = st.columns(3)
                c1.write(f"**Nombre de archivo:** {file_name}")
                c2.write(f"**Tipo de archivo:** {file_type}")
                c3.write(f"**Tamaño:** {size}")

                st.subheader("Enlaces")
                st.markdown(f"[Abrir en VirusTotal](https://www.virustotal.com/gui/file/{ioc})")

                ticket_text = f"""IOC analizado: {ioc}
Tipo: Hash
SHA256: {sha256}
Nombre de archivo: {file_name}
Tipo de archivo: {file_type}
Tamaño: {size}
VirusTotal: score={vt_malicious}/{vt_total}, suspicious={vt_suspicious}
Conclusión: {verdict}
"""
                st.subheader("Texto para ticket")
                st.code(ticket_text, language="text")
            else:
                show_api_error("VirusTotal", vt_response)

        # =========================
        # URL
        # =========================
        elif is_url(ioc):
            st.info("Tipo detectado: URL")

            try:
                vt_response = vt_url_lookup(ioc)
            except requests.RequestException as e:
                st.error(f"Error de red al consultar VirusTotal: {e}")
                st.stop()

            if vt_response.status_code == 200:
                vt = safe_json(vt_response)
                attr = vt.get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})

                vt_malicious = stats.get("malicious", 0)
                vt_suspicious = stats.get("suspicious", 0)
                vt_total = total_engines_from_stats(stats)
                final_url = attr.get("url", ioc)
                categories = attr.get("categories", {})

                verdict, severity = get_verdict(vt_malicious, vt_suspicious, 0)
                show_verdict(verdict, severity)

                st.subheader("Resumen")
                st.write(
                    f"La URL **{final_url}** presenta **{vt_malicious}/{vt_total if vt_total else 0}** "
                    f"en VirusTotal y **{vt_suspicious}** detecciones sospechosas."
                )

                score_col, metrics_col = st.columns([1, 3])

                with score_col:
                    render_vt_score_card(vt_malicious, vt_total)

                with metrics_col:
                    m1, m2 = st.columns(2)
                    m1.metric("VT Malicious", vt_malicious)
                    m2.metric("VT Suspicious", vt_suspicious)

                st.subheader("Contexto")
                st.write(f"**URL:** {final_url}")
                if categories:
                    st.write(f"**Categorías:** {categories}")

                st.subheader("Enlaces")
                st.markdown(f"[Abrir en VirusTotal](https://www.virustotal.com/gui/url/{vt_url_id(ioc)})")

                ticket_text = f"""IOC analizado: {ioc}
Tipo: URL
VirusTotal: score={vt_malicious}/{vt_total}, suspicious={vt_suspicious}
Categorías: {categories if categories else 'N/A'}
Conclusión: {verdict}
"""
                st.subheader("Texto para ticket")
                st.code(ticket_text, language="text")
            else:
                show_api_error("VirusTotal", vt_response)

        else:
            st.warning("Tipo de IOC no reconocido. Introduce una IP, URL o hash válido.")
