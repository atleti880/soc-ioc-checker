import base64
import re
from urllib.parse import urlparse

import pycountry
import requests
import streamlit as st

# -------------------------
# Configuración
# -------------------------
st.set_page_config(
    page_title="Threat Intelligence Workbench",
    page_icon="🧠",
    layout="wide",
)

st.title("🧠 Threat Intelligence Workbench")
st.caption("Análisis de IP / URL / Hash / Dominio con VirusTotal, AbuseIPDB y GreyNoise")

VT_API = st.secrets.get("VT_API")
ABUSE_API = st.secrets.get("ABUSE_API")
GREYNOISE_API = st.secrets.get("GREYNOISE_API")

missing = []
if not VT_API:
    missing.append("VT_API")
if not ABUSE_API:
    missing.append("ABUSE_API")
if not GREYNOISE_API:
    missing.append("GREYNOISE_API")

if missing:
    st.error(
        "Faltan secrets en Streamlit Cloud: " + ", ".join(missing)
    )
    st.info(
        "Añádelas en Manage app → Settings → Secrets con este formato:\n\n"
        'VT_API = "tu_api"\n'
        'ABUSE_API = "tu_api"\n'
        'GREYNOISE_API = "tu_api"'
    )
    st.stop()

VT_HEADERS = {"x-apikey": VT_API}
ABUSE_HEADERS = {"Key": ABUSE_API, "Accept": "application/json"}
GREYNOISE_HEADERS = {
    "key": GREYNOISE_API,
    "accept": "application/json",
    "user-agent": "streamlit-threat-intel-workbench",
}

ioc = st.text_input("Introduce un IOC (IP, URL, hash o dominio)")

# -------------------------
# Validación
# -------------------------
def is_ip(value: str) -> bool:
    pattern = r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
    return re.fullmatch(pattern, value) is not None


def is_hash(value: str) -> bool:
    return re.fullmatch(r"([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", value) is not None


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    return value


def is_url(value: str) -> bool:
    try:
        parsed = urlparse(normalize_url(value))
        return bool(parsed.netloc) and "." in parsed.netloc
    except Exception:
        return False


def is_domain(value: str) -> bool:
    value = value.strip().lower()
    if value.startswith(("http://", "https://")):
        return False
    pattern = r"^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
    return re.fullmatch(pattern, value) is not None


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
    return sum(value for value in stats.values() if isinstance(value, int))


def show_api_error(source: str, response: requests.Response):
    data = safe_json(response)
    message = (
        data.get("error", {}).get("message")
        or data.get("message")
        or data.get("errors")
        or response.text[:300]
        or "Error desconocido"
    )
    st.error(f"{source} devolvió error {response.status_code}: {message}")


def get_severity(vt_malicious=0, vt_suspicious=0, abuse_score=0, gn_malicious=False):
    if gn_malicious or abuse_score >= 80 or vt_malicious >= 8:
        return "Critical"
    if abuse_score >= 50 or vt_malicious >= 3 or vt_suspicious >= 5:
        return "High"
    if abuse_score >= 20 or vt_malicious >= 1 or vt_suspicious >= 2:
        return "Medium"
    return "Low"


def get_confidence(vt_malicious=0, vt_suspicious=0, abuse_score=0, gn_malicious=False, gn_noise=False):
    if gn_malicious or abuse_score >= 80 or vt_malicious >= 8:
        return "High"
    if gn_noise or abuse_score >= 30 or vt_malicious >= 2 or vt_suspicious >= 3:
        return "Medium"
    return "Low"


def classify_threat_ip(vt_malicious=0, vt_suspicious=0, abuse_score=0, gn_data=None):
    gn_data = gn_data or {}
    gn_classification = str(gn_data.get("classification", "")).lower()
    gn_noise = bool(gn_data.get("noise", False))
    gn_riot = bool(gn_data.get("riot", False))

    if gn_riot:
        return "Benign Internet Service"
    if gn_classification == "malicious":
        return "Malicious Infrastructure"
    if abuse_score >= 70:
        return "Malicious Infrastructure / Abuse"
    if gn_noise:
        return "Internet Scanner / Background Noise"
    if vt_malicious >= 3:
        return "Suspicious Infrastructure"
    if vt_suspicious >= 2:
        return "Reconnaissance / Scanner"
    return "Low Confidence / Unknown"


def classify_threat(ioc_type: str, vt_malicious=0, vt_suspicious=0, abuse_score=0, gn_data=None):
    if ioc_type == "IP":
        return classify_threat_ip(vt_malicious, vt_suspicious, abuse_score, gn_data)

    if ioc_type == "URL":
        if vt_malicious >= 5:
            return "Phishing / Malware Delivery"
        if vt_malicious >= 1 or vt_suspicious >= 2:
            return "Suspicious URL"
        return "Low Confidence / Unknown"

    if ioc_type == "HASH":
        if vt_malicious >= 5:
            return "Malware"
        if vt_malicious >= 1 or vt_suspicious >= 2:
            return "Suspicious File"
        return "Low Confidence / Unknown"

    if ioc_type == "DOMAIN":
        if vt_malicious >= 5:
            return "Malicious Domain"
        if vt_malicious >= 1 or vt_suspicious >= 2:
            return "Suspicious Domain"
        return "Low Confidence / Unknown"

    return "Unknown"


def get_verdict(severity: str):
    if severity == "Critical":
        return "Malicioso"
    if severity == "High":
        return "Alta sospecha"
    if severity == "Medium":
        return "Sospechoso"
    return "Bajo riesgo"


def show_verdict_box(verdict: str, severity: str):
    if severity in ["Critical", "High"]:
        st.error(f"Veredicto: {verdict} | Severity: {severity}")
    elif severity == "Medium":
        st.warning(f"Veredicto: {verdict} | Severity: {severity}")
    else:
        st.success(f"Veredicto: {verdict} | Severity: {severity}")


def build_intelligence_summary_ip(
    ip_value,
    threat_category,
    confidence,
    severity,
    vt_malicious=0,
    vt_total=0,
    vt_suspicious=0,
    abuse_score=0,
    reports=0,
    gn_data=None,
):
    gn_data = gn_data or {}
    parts = []

    gn_classification = gn_data.get("classification", "unknown")
    gn_noise = gn_data.get("noise", False)
    gn_riot = gn_data.get("riot", False)
    gn_name = gn_data.get("name", "N/A")
    gn_tags = gn_data.get("tags", [])

    parts.append(f"La IP **{ip_value}** ha sido analizada como infraestructura potencialmente sospechosa.")
    parts.append(
        f"La clasificación preliminar es **{threat_category}**, con **confidence {confidence}** y **severity {severity}**."
    )

    if vt_total > 0:
        parts.append(
            f"En VirusTotal presenta **{vt_malicious}/{vt_total}** detecciones maliciosas y **{vt_suspicious}** sospechosas."
        )

    parts.append(
        f"En AbuseIPDB registra un **abuse confidence score de {abuse_score}%** y **{reports} reportes**."
    )

    parts.append(
        f"GreyNoise la clasifica como **{gn_classification}**, con **noise={gn_noise}** y **riot={gn_riot}**."
    )

    if gn_name and gn_name != "N/A":
        parts.append(f"GreyNoise identifica el actor o etiqueta principal como **{gn_name}**.")

    if gn_tags:
        parts.append(f"Tags observadas en GreyNoise: **{', '.join(gn_tags)}**.")

    if severity in ["Critical", "High"]:
        parts.append(
            "La evidencia conjunta sugiere una alta probabilidad de actividad maliciosa o abusiva. Se recomienda bloqueo preventivo y revisión de telemetría relacionada en firewall, proxy y EDR."
        )
    elif severity == "Medium":
        parts.append(
            "La evidencia disponible indica actividad sospechosa o de reconocimiento. Se recomienda validación adicional antes de tomar una acción disruptiva."
        )
    else:
        parts.append(
            "No se observa evidencia suficiente para una clasificación concluyente. Se recomienda mantener la IP en observación y correlacionarla con eventos internos."
        )

    return " ".join(parts)


def build_intelligence_summary_generic(
    ioc_type,
    ioc_value,
    threat_category,
    confidence,
    severity,
    vt_malicious=0,
    vt_total=0,
    vt_suspicious=0,
):
    parts = []
    parts.append(f"El indicador **{ioc_value}** ha sido analizado como **{ioc_type}**.")
    parts.append(
        f"La clasificación preliminar es **{threat_category}**, con un nivel de confianza **{confidence}** y severidad **{severity}**."
    )

    if vt_total > 0:
        parts.append(
            f"En VirusTotal presenta **{vt_malicious}/{vt_total}** detecciones maliciosas y **{vt_suspicious}** sospechosas."
        )

    if severity in ["Critical", "High"]:
        parts.append(
            "La evidencia disponible sugiere una alta probabilidad de actividad maliciosa. Se recomienda bloqueo preventivo y revisión de telemetría relacionada."
        )
    elif severity == "Medium":
        parts.append(
            "La evidencia disponible indica actividad sospechosa. Se recomienda validación adicional en proxy, EDR, firewall o correo."
        )
    else:
        parts.append(
            "No se observa evidencia suficiente para una clasificación concluyente. Se recomienda mantenerlo en observación."
        )

    return " ".join(parts)


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
            VT Detection Score
        </div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_abuse_score_bar(score: int, reports: int):
    st.subheader("AbuseIPDB Score")
    st.write(f"Esta IP ha sido reportada **{reports}** veces. Confidence of Abuse: **{score}%**")
    st.progress(min(max(score, 0), 100))


# -------------------------
# API Lookups
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


def vt_domain_lookup(domain_value: str) -> requests.Response:
    url = f"https://www.virustotal.com/api/v3/domains/{domain_value}"
    return requests.get(url, headers=VT_HEADERS, timeout=20)


def abuse_lookup(ip: str) -> requests.Response:
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    return requests.get(url, headers=ABUSE_HEADERS, params=params, timeout=20)


def greynoise_lookup(ip: str) -> requests.Response:
    url = f"https://api.greynoise.io/v3/community/{ip}"
    return requests.get(url, headers=GREYNOISE_HEADERS, timeout=20)


# -------------------------
# Main
# -------------------------
if ioc:
    ioc = ioc.strip()

    with st.spinner("Consultando fuentes de Threat Intelligence..."):

        # -------------------------
        # IP
        # -------------------------
        if is_ip(ioc):
            st.info("Tipo detectado: IP")

            vt_malicious = 0
            vt_suspicious = 0
            vt_total = 0
            country_code = "N/A"
            as_owner = "N/A"
            reputation = "N/A"
            abuse_score = 0
            reports = 0
            gn_data = {}

            try:
                vt_response = vt_ip_lookup(ioc)
                abuse_response = abuse_lookup(ioc)
                gn_response = greynoise_lookup(ioc)
            except requests.RequestException as e:
                st.error(f"Error de red al consultar APIs: {e}")
                st.stop()

            if vt_response.status_code == 200:
                vt = safe_json(vt_response)
                attr = vt.get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                vt_malicious = stats.get("malicious", 0)
                vt_suspicious = stats.get("suspicious", 0)
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

            if gn_response.status_code == 200:
                gn_data = safe_json(gn_response)
            elif gn_response.status_code == 404:
                gn_data = {
                    "classification": "unknown",
                    "noise": False,
                    "riot": False,
                    "name": "N/A",
                    "link": f"https://viz.greynoise.io/ip/{ioc}",
                    "tags": [],
                }
            else:
                show_api_error("GreyNoise", gn_response)

            gn_classification = str(gn_data.get("classification", "unknown")).lower()
            gn_noise = bool(gn_data.get("noise", False))
            gn_riot = bool(gn_data.get("riot", False))
            gn_name = gn_data.get("name", "N/A")
            gn_link = gn_data.get("link", f"https://viz.greynoise.io/ip/{ioc}")
            gn_tags = gn_data.get("tags", [])
            gn_last_seen = gn_data.get("last_seen", "N/A")
            gn_malicious = gn_classification == "malicious"

            severity = get_severity(vt_malicious, vt_suspicious, abuse_score, gn_malicious)
            confidence = get_confidence(vt_malicious, vt_suspicious, abuse_score, gn_malicious, gn_noise)
            threat_category = classify_threat("IP", vt_malicious, vt_suspicious, abuse_score, gn_data)
            verdict = get_verdict(severity)

            show_verdict_box(verdict, severity)

            tab1, tab2, tab3, tab4 = st.tabs(
                ["Resumen", "Intelligence Summary", "Fuentes", "Texto para ticket"]
            )

            with tab1:
                st.subheader("Resumen")
                st.write(
                    f"La IP **{ioc}** presenta **{vt_malicious}/{vt_total if vt_total else 0}** en VirusTotal, "
                    f"**{vt_suspicious}** detecciones sospechosas, un **abuse score de {abuse_score}** "
                    f"con **{reports} reportes** en AbuseIPDB y clasificación **{gn_classification}** en GreyNoise."
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

                render_abuse_score_bar(abuse_score, reports)

                st.subheader("Contexto")
                country_name = country_name_from_code(country_code)
                c1, c2, c3 = st.columns(3)
                c1.write(f"**País:** {country_name} ({country_code})")
                c2.write(f"**AS Owner:** {as_owner}")
                c3.write(f"**VT Reputation:** {reputation}")

                st.subheader("Clasificación TI")
                t1, t2, t3 = st.columns(3)
                t1.metric("Threat Category", threat_category)
                t2.metric("Confidence", confidence)
                t3.metric("Severity", severity)

                st.subheader("GreyNoise Quick View")
                g1, g2, g3, g4 = st.columns(4)
                g1.metric("Classification", gn_classification.capitalize())
                g2.metric("Noise", "Yes" if gn_noise else "No")
                g3.metric("RIOT", "Yes" if gn_riot else "No")
                g4.metric("Name", gn_name if gn_name else "N/A")

                if gn_tags:
                    st.write(f"**Tags GreyNoise:** {', '.join(gn_tags)}")

                st.subheader("Enlaces")
                st.markdown(f"[Abrir en VirusTotal](https://www.virustotal.com/gui/ip-address/{ioc})")
                st.markdown(f"[Abrir en AbuseIPDB](https://www.abuseipdb.com/check/{ioc})")
                st.markdown(f"[Abrir en GreyNoise]({gn_link})")

            with tab2:
                summary = build_intelligence_summary_ip(
                    ioc,
                    threat_category,
                    confidence,
                    severity,
                    vt_malicious,
                    vt_total,
                    vt_suspicious,
                    abuse_score,
                    reports,
                    gn_data,
                )
                st.subheader("Intelligence Summary")
                st.write(summary)

            with tab3:
                st.subheader("Detalle por fuente")

                source1, source2, source3 = st.columns(3)

                with source1:
                    st.markdown("### VirusTotal")
                    st.write(f"**Malicious:** {vt_malicious}")
                    st.write(f"**Suspicious:** {vt_suspicious}")
                    st.write(f"**Total engines:** {vt_total}")
                    st.write(f"**Reputation:** {reputation}")
                    st.write(f"**Country:** {country_name_from_code(country_code)}")
                    st.write(f"**AS Owner:** {as_owner}")

                with source2:
                    st.markdown("### AbuseIPDB")
                    st.write(f"**Abuse Score:** {abuse_score}")
                    st.write(f"**Reports:** {reports}")

                with source3:
                    st.markdown("### GreyNoise")
                    st.write(f"**Classification:** {gn_classification}")
                    st.write(f"**Noise:** {gn_noise}")
                    st.write(f"**RIOT:** {gn_riot}")
                    st.write(f"**Name:** {gn_name}")
                    st.write(f"**Last Seen:** {gn_last_seen}")
                    if gn_tags:
                        st.write(f"**Tags:** {', '.join(gn_tags)}")
                    else:
                        st.write("**Tags:** N/A")

                with st.expander("Ver respuesta JSON de GreyNoise"):
                    st.json(gn_data)

            with tab4:
                country_name = country_name_from_code(country_code)
                ticket_text = f"""IOC analizado: {ioc}
Tipo: IP
Threat Category: {threat_category}
Confidence: {confidence}
Severity: {severity}

VirusTotal:
- score={vt_malicious}/{vt_total}
- suspicious={vt_suspicious}
- reputation={reputation}

AbuseIPDB:
- abuseConfidenceScore={abuse_score}
- totalReports={reports}

GreyNoise:
- classification={gn_classification}
- noise={gn_noise}
- riot={gn_riot}
- name={gn_name}
- last_seen={gn_last_seen}
- tags={", ".join(gn_tags) if gn_tags else "N/A"}

País: {country_name} ({country_code})
AS Owner: {as_owner}

Conclusión: {verdict}
"""
                st.code(ticket_text, language="text")

        # -------------------------
        # HASH
        # -------------------------
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

                severity = get_severity(vt_malicious, vt_suspicious, 0, False)
                confidence = get_confidence(vt_malicious, vt_suspicious, 0, False, False)
                threat_category = classify_threat("HASH", vt_malicious, vt_suspicious, 0)
                verdict = get_verdict(severity)

                show_verdict_box(verdict, severity)

                tab1, tab2, tab3 = st.tabs(["Resumen", "Intelligence Summary", "Texto para ticket"])

                with tab1:
                    st.subheader("Resumen")
                    st.write(
                        f"El hash **{ioc}** presenta **{vt_malicious}/{vt_total if vt_total else 0}** "
                        f"en VirusTotal y **{vt_suspicious}** detecciones sospechosas."
                    )

                    score_col, metrics_col = st.columns([1, 3])

                    with score_col:
                        render_vt_score_card(vt_malicious, vt_total)

                    with metrics_col:
                        m1, m2, m3 = st.columns(3)
                        m1.metric("VT Malicious", vt_malicious)
                        m2.metric("VT Suspicious", vt_suspicious)
                        m3.metric("Severity", severity)

                    st.subheader("Contexto")
                    c1, c2, c3 = st.columns(3)
                    c1.write(f"**Nombre de archivo:** {file_name}")
                    c2.write(f"**Tipo de archivo:** {file_type}")
                    c3.write(f"**Tamaño:** {size}")

                    st.subheader("Clasificación TI")
                    t1, t2, t3 = st.columns(3)
                    t1.metric("Threat Category", threat_category)
                    t2.metric("Confidence", confidence)
                    t3.metric("Severity", severity)

                    st.subheader("Enlaces")
                    st.markdown(f"[Abrir en VirusTotal](https://www.virustotal.com/gui/file/{ioc})")

                with tab2:
                    summary = build_intelligence_summary_generic(
                        "HASH",
                        ioc,
                        threat_category,
                        confidence,
                        severity,
                        vt_malicious,
                        vt_total,
                        vt_suspicious,
                    )
                    st.subheader("Intelligence Summary")
                    st.write(summary)

                with tab3:
                    ticket_text = f"""IOC analizado: {ioc}
Tipo: Hash
SHA256: {sha256}
Nombre de archivo: {file_name}
Tipo de archivo: {file_type}
Tamaño: {size}
Threat Category: {threat_category}
Confidence: {confidence}
Severity: {severity}
VirusTotal: score={vt_malicious}/{vt_total}, suspicious={vt_suspicious}
Conclusión: {verdict}
"""
                    st.code(ticket_text, language="text")
            else:
                show_api_error("VirusTotal", vt_response)

        # -------------------------
        # URL
        # -------------------------
        elif is_url(ioc):
            ioc = normalize_url(ioc)
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

                severity = get_severity(vt_malicious, vt_suspicious, 0, False)
                confidence = get_confidence(vt_malicious, vt_suspicious, 0, False, False)
                threat_category = classify_threat("URL", vt_malicious, vt_suspicious, 0)
                verdict = get_verdict(severity)

                show_verdict_box(verdict, severity)

                tab1, tab2, tab3 = st.tabs(["Resumen", "Intelligence Summary", "Texto para ticket"])

                with tab1:
                    st.subheader("Resumen")
                    st.write(
                        f"La URL **{final_url}** presenta **{vt_malicious}/{vt_total if vt_total else 0}** "
                        f"en VirusTotal y **{vt_suspicious}** detecciones sospechosas."
                    )

                    score_col, metrics_col = st.columns([1, 3])

                    with score_col:
                        render_vt_score_card(vt_malicious, vt_total)

                    with metrics_col:
                        m1, m2, m3 = st.columns(3)
                        m1.metric("VT Malicious", vt_malicious)
                        m2.metric("VT Suspicious", vt_suspicious)
                        m3.metric("Severity", severity)

                    st.subheader("Contexto")
                    st.write(f"**URL:** {final_url}")
                    if categories:
                        st.write(f"**Categorías:** {categories}")

                    st.subheader("Clasificación TI")
                    t1, t2, t3 = st.columns(3)
                    t1.metric("Threat Category", threat_category)
                    t2.metric("Confidence", confidence)
                    t3.metric("Severity", severity)

                    st.subheader("Enlaces")
                    st.markdown(f"[Abrir en VirusTotal](https://www.virustotal.com/gui/url/{vt_url_id(ioc)})")

                with tab2:
                    summary = build_intelligence_summary_generic(
                        "URL",
                        final_url,
                        threat_category,
                        confidence,
                        severity,
                        vt_malicious,
                        vt_total,
                        vt_suspicious,
                    )
                    st.subheader("Intelligence Summary")
                    st.write(summary)

                with tab3:
                    ticket_text = f"""IOC analizado: {ioc}
Tipo: URL
Threat Category: {threat_category}
Confidence: {confidence}
Severity: {severity}
VirusTotal: score={vt_malicious}/{vt_total}, suspicious={vt_suspicious}
Categorías: {categories if categories else 'N/A'}
Conclusión: {verdict}
"""
                    st.code(ticket_text, language="text")
            else:
                show_api_error("VirusTotal", vt_response)

        # -------------------------
        # DOMAIN
        # -------------------------
        elif is_domain(ioc):
            st.info("Tipo detectado: Dominio")

            try:
                vt_response = vt_domain_lookup(ioc)
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
                reputation = attr.get("reputation", "N/A")
                categories = attr.get("categories", {})
                registrar = attr.get("registrar", "N/A")

                severity = get_severity(vt_malicious, vt_suspicious, 0, False)
                confidence = get_confidence(vt_malicious, vt_suspicious, 0, False, False)
                threat_category = classify_threat("DOMAIN", vt_malicious, vt_suspicious, 0)
                verdict = get_verdict(severity)

                show_verdict_box(verdict, severity)

                tab1, tab2, tab3 = st.tabs(["Resumen", "Intelligence Summary", "Texto para ticket"])

                with tab1:
                    st.subheader("Resumen")
                    st.write(
                        f"El dominio **{ioc}** presenta **{vt_malicious}/{vt_total if vt_total else 0}** "
                        f"en VirusTotal y **{vt_suspicious}** detecciones sospechosas."
                    )

                    score_col, metrics_col = st.columns([1, 3])

                    with score_col:
                        render_vt_score_card(vt_malicious, vt_total)

                    with metrics_col:
                        m1, m2, m3 = st.columns(3)
                        m1.metric("VT Malicious", vt_malicious)
                        m2.metric("VT Suspicious", vt_suspicious)
                        m3.metric("Severity", severity)

                    st.subheader("Contexto")
                    c1, c2 = st.columns(2)
                    c1.write(f"**Registrar:** {registrar}")
                    c2.write(f"**VT Reputation:** {reputation}")
                    if categories:
                        st.write(f"**Categorías:** {categories}")

                    st.subheader("Clasificación TI")
                    t1, t2, t3 = st.columns(3)
                    t1.metric("Threat Category", threat_category)
                    t2.metric("Confidence", confidence)
                    t3.metric("Severity", severity)

                    st.subheader("Enlaces")
                    st.markdown(f"[Abrir en VirusTotal](https://www.virustotal.com/gui/domain/{ioc})")

                with tab2:
                    summary = build_intelligence_summary_generic(
                        "DOMAIN",
                        ioc,
                        threat_category,
                        confidence,
                        severity,
                        vt_malicious,
                        vt_total,
                        vt_suspicious,
                    )
                    st.subheader("Intelligence Summary")
                    st.write(summary)

                with tab3:
                    ticket_text = f"""IOC analizado: {ioc}
Tipo: Dominio
Threat Category: {threat_category}
Confidence: {confidence}
Severity: {severity}
VirusTotal: score={vt_malicious}/{vt_total}, suspicious={vt_suspicious}
VT Reputation: {reputation}
Registrar: {registrar}
Categorías: {categories if categories else 'N/A'}
Conclusión: {verdict}
"""
                    st.code(ticket_text, language="text")
            else:
                show_api_error("VirusTotal", vt_response)

        else:
            st.warning("Tipo de IOC no reconocido. Introduce una IP, URL, hash o dominio válido.")
