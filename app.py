import base64
import html
import ipaddress
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import pandas as pd
import pycountry
import requests
import streamlit as st
import streamlit.components.v1 as components

# ==============================================================================
# CONFIGURACIÓN Y API KEYS
# ==============================================================================
VT_API = st.secrets["VT_API"]
ABUSE_API = st.secrets["ABUSE_API"]

VT_HEADERS = {"x-apikey": VT_API}
ABUSE_HEADERS = {"Key": ABUSE_API, "Accept": "application/json"}

st.set_page_config(page_title="SOC IOC Checker", page_icon="🛡️", layout="wide")

st.title("SOC IOC Checker")
st.caption("Consulta IP / URL / Hash en VirusTotal y AbuseIPDB con Refang")


# ==============================================================================
# UTILIDADES BÁSICAS (Incluye Punto 2: Refang)
# ==============================================================================
def refang_ioc(value: str) -> str:
    """
    Limpia IOCs ofuscados para que sean procesables:
    Ej: 1.1.1[.]1 -> 1.1.1.1 | hxxp:// -> http:// | google(.)com -> google.com
    """
    # Elimina corchetes y paréntesis comunes en la ofuscación de puntos
    value = re.sub(r'[\[\(\]\)]', '', value)
    # Normaliza protocolos (hxxp -> http)
    value = re.sub(r'^hxxp', 'http', value, flags=re.IGNORECASE)
    return value.strip()


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False


def is_hash(value: str) -> bool:
    return re.fullmatch(r"([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", value.strip()) is not None


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    return value


def is_url(value: str) -> bool:
    try:
        parsed = urlparse(normalize_url(value))
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return False
        if is_ip(host):
            return True
        domain_regex = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$"
        return re.fullmatch(domain_regex, host) is not None
    except Exception:
        return False


def detect_ioc_type(value: str) -> str:
    value = value.strip()
    if is_ip(value):
        return "IP"
    if is_hash(value):
        return "Hash"
    if is_url(value):
        return "URL"
    return "Desconocido"


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
    return sum(v for v in stats.values() if isinstance(v, int))


def format_file_size(size):
    if not isinstance(size, (int, float)):
        return str(size)
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024


def format_unix_timestamp(ts):
    if ts in (None, "", "N/A"):
        return "N/A"
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def format_categories(categories) -> str:
    if not categories:
        return "N/A"
    if isinstance(categories, dict):
        return ", ".join(f"{k}: {v}" for k, v in categories.items())
    if isinstance(categories, list):
        return ", ".join(str(x) for x in categories)
    return str(categories)


def normalize_reputation(value):
    if value in (None, "", "N/A"):
        return "N/A"
    return value


def escape_key(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", value)


def get_status_icon(verdict: str) -> str:
    if verdict == "Malicioso":
        return "🔴"
    if verdict == "Sospechoso":
        return "🟠"
    if verdict == "Bajo riesgo":
        return "🟢"
    return "⚪"


def build_vt_summary_link(ioc: str, ioc_type: str) -> str:
    if ioc_type == "IP":
        return f"https://www.virustotal.com/gui/ip-address/{ioc}"
    if ioc_type == "Hash":
        return f"https://www.virustotal.com/gui/file/{ioc}"
    if ioc_type == "URL":
        normalized = normalize_url(ioc)
        return f"https://www.virustotal.com/gui/url/{vt_url_id(normalized)}"
    return ""


def build_abuse_summary_link(ioc: str, ioc_type: str) -> str:
    if ioc_type == "IP":
        return f"https://www.abuseipdb.com/check/{ioc}"
    return ""


# ==============================================================================
# VEREDICTO / OBSERVACIONES
# ==============================================================================
def get_verdict(vt_malicious: int = 0, vt_suspicious: int = 0, abuse_score: int = 0):
    if abuse_score >= 80 or vt_malicious >= 5:
        return "Malicioso", "high"
    if abuse_score >= 30 or vt_malicious >= 1 or vt_suspicious >= 3:
        return "Sospechoso", "medium"
    return "Bajo riesgo", "low"


def get_verdict_icon(severity: str) -> str:
    if severity == "high":
        return "🔴"
    if severity == "medium":
        return "🟠"
    return "🟢"


def get_verdict_hint(severity: str) -> str:
    if severity == "high":
        return "Requiere revisión inmediata."
    if severity == "medium":
        return "Conviene validar el contexto y revisar eventos asociados."
    return "Sin indicadores claros en las fuentes consultadas."


def show_verdict_banner(verdict: str, severity: str):
    icon = get_verdict_icon(severity)
    hint = get_verdict_hint(severity)
    if severity == "high":
        st.error(f"{icon} Veredicto: {verdict}")
    elif severity == "medium":
        st.warning(f"{icon} Veredicto: {verdict}")
    else:
        st.success(f"{icon} Veredicto: {verdict}")
    st.caption(hint)


def get_observations_ip(vt_malicious, vt_suspicious, abuse_score, reports, as_owner, hostname):
    obs = []
    if vt_malicious > 0:
        obs.append(f"La IP presenta {vt_malicious} detecciones maliciosas en VirusTotal.")
    elif vt_suspicious > 0:
        obs.append(f"La IP no tiene detecciones maliciosas, pero sí {vt_suspicious} detecciones sospechosas en VirusTotal.")
    else:
        obs.append("La IP no presenta detecciones claras en VirusTotal en esta consulta.")

    if abuse_score >= 30:
        obs.append(f"AbuseIPDB muestra un confidence score de {abuse_score}% con {reports} reportes.")
    elif reports > 0:
        obs.append(f"La IP tiene {reports} reportes en AbuseIPDB, aunque con score moderado o bajo.")
    else:
        obs.append("No se observan reportes relevantes en AbuseIPDB.")

    if as_owner != "N/A":
        obs.append(f"El AS Owner reportado es {as_owner}.")
    if hostname != "N/A":
        obs.append(f"El reverse DNS resuelve a {hostname}.")

    return " ".join(obs)


def get_observations_hash(vt_malicious, vt_suspicious, signature):
    obs = []
    if vt_malicious > 0:
        obs.append(f"El hash presenta {vt_malicious} detecciones maliciosas en VirusTotal.")
    elif vt_suspicious > 0:
        obs.append(f"El hash presenta {vt_suspicious} detecciones sospechosas, sin detecciones maliciosas directas.")
    else:
        obs.append("El hash no presenta detecciones claras en VirusTotal en esta consulta.")

    if signature["is_signed"] and signature["is_valid"]:
        obs.append("El archivo está firmado digitalmente y la firma parece válida.")
    elif signature["is_signed"]:
        obs.append("El archivo está firmado digitalmente, pero la validez de la firma no es concluyente.")
    else:
        obs.append("El archivo no aparece firmado digitalmente.")

    return " ".join(obs)


def get_observations_url(vt_malicious, vt_suspicious, categories):
    obs = []
    if vt_malicious > 0:
        obs.append(f"La URL presenta {vt_malicious} detecciones maliciosas en VirusTotal.")
    elif vt_suspicious > 0:
        obs.append(f"La URL presenta {vt_suspicious} detecciones sospechosas en VirusTotal.")
    else:
        obs.append("La URL no presenta detecciones claras en VirusTotal en esta consulta.")

    if categories:
        obs.append(f"VirusTotal devuelve categorías asociadas: {format_categories(categories)}.")
    else:
        obs.append("No se han devuelto categorías adicionales para la URL.")

    return " ".join(obs)


# ==============================================================================
# RENDER VISUAL
# ==============================================================================
def render_vt_score_card(malicious: int, total: int):
    percent = 0 if total == 0 else round((malicious / total) * 100)
    card_html = f"""
    <div style="background:#1f2a44; border-radius:14px; padding:22px 18px; text-align:center; width:220px; margin-bottom:12px;">
        <div style="width:120px; height:120px; border-radius:50%; margin:0 auto 12px auto; background:conic-gradient(#ff5a52 {percent}%, #31456e 0%); display:flex; align-items:center; justify-content:center;">
            <div style="width:88px; height:88px; border-radius:50%; background:#1f2a44; display:flex; flex-direction:column; align-items:center; justify-content:center;">
                <div style="font-size:22px; color:#ff5a52; line-height:1; font-weight:700;">{malicious}</div>
                <div style="font-size:14px; color:#c9d4ea; line-height:1.2; margin-top:4px;">/ {total}</div>
            </div>
        </div>
        <div style="font-size:14px; color:#c9d4ea; font-weight:600;">VT Community Score</div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_abuse_score_bar(score: int, reports: int):
    st.subheader("AbuseIPDB Score")
    st.write(f"Esta IP ha sido reportada **{reports}** veces. Confidence of Abuse: **{score}%**")
    st.progress(min(max(score, 0), 100))


def render_severity_badge(label: str, value, severity: str):
    colors = {"high": ("#ffdddd", "#8b0000"), "medium": ("#fff4d6", "#8a5a00"), "low": ("#ddffea", "#0a6b33")}
    bg, fg = colors[severity]
    st.markdown(f'<div style="background:{bg}; color:{fg}; border-radius:10px; padding:10px 12px; margin-bottom:8px; font-weight:600;">{label}: {value}</div>', unsafe_allow_html=True)


def get_metric_severity_for_vt(vt_malicious: int) -> str:
    if vt_malicious >= 5: return "high"
    if vt_malicious >= 1: return "medium"
    return "low"


def get_metric_severity_for_abuse(score: int) -> str:
    if score >= 80: return "high"
    if score >= 30: return "medium"
    return "low"


# ==============================================================================
# PORTAPAPELES
# ==============================================================================
def render_copy_box(title: str, text: str, unique_key: str, height: int = 320):
    st.subheader(title)
    escaped_text = html.escape(text)
    component_html = f"""
    <div style="margin-top: 0.5rem; margin-bottom: 1rem;">
        <textarea id="copy_box_{unique_key}" readonly style="width: 100%; height: {height}px; padding: 12px; border-radius: 8px; border: 1px solid #4a4a4a; background: #0e1117; color: #fafafa; font-family: monospace; font-size: 14px; line-height: 1.5; resize: vertical; box-sizing: border-box;">{escaped_text}</textarea>
        <button onclick="copyText_{unique_key}()" style="margin-top: 10px; background: #ff4b4b; color: white; border: none; padding: 10px 16px; border-radius: 8px; cursor: pointer; font-weight: 600;">Copiar al portapapeles</button>
        <span id="copy_msg_{unique_key}" style="margin-left: 12px; color: #7dd87d; font-weight: 600;"></span>
    </div>
    <script>
    function copyText_{unique_key}() {{
        const textarea = document.getElementById("copy_box_{unique_key}");
        textarea.select();
        textarea.setSelectionRange(0, 999999);
        navigator.clipboard.writeText(textarea.value).then(function() {{
            const msg = document.getElementById("copy_msg_{unique_key}");
            msg.innerText = "Copiado ✅";
            setTimeout(() => {{ msg.innerText = ""; }}, 2000);
        }});
    }}
    </script>
    """
    components.html(component_html, height=height + 80)


# ==============================================================================
# FIRMA DIGITAL / HISTORIAL (LÓGICA EXTENSA RESTAURADA)
# ==============================================================================
def normalize_verification_text(value) -> str:
    if value is None: return "N/A"
    if isinstance(value, bool): return "Valid signature" if value else "Invalid signature"
    return str(value).strip()


def extract_signature_info(vt_attributes: dict) -> dict:
    result = {"is_signed": False, "is_valid": False, "signers": [], "verified": "N/A", "publisher": "N/A", "date_signed": "N/A", "product": "N/A", "description": "N/A", "file_version": "N/A", "original_name": "N/A"}
    signature_info = vt_attributes.get("signature_info", {})
    signatures = vt_attributes.get("signatures", [])
    pe_info = vt_attributes.get("pe_info", {})
    version_info = vt_attributes.get("file_version_info", {})

    verification_candidates = [
        vt_attributes.get("signature_verification"),
        vt_attributes.get("signature verification"),
        signature_info.get("signature_verification") if isinstance(signature_info, dict) else None,
        signature_info.get("verification") if isinstance(signature_info, dict) else None,
        signature_info.get("verified") if isinstance(signature_info, dict) else None,
        signature_info.get("status") if isinstance(signature_info, dict) else None,
        pe_info.get("signature_verification") if isinstance(pe_info, dict) else None,
        pe_info.get("verified") if isinstance(pe_info, dict) else None,
        pe_info.get("status") if isinstance(pe_info, dict) else None,
    ]

    if isinstance(signatures, list):
        for sig in signatures:
            if isinstance(sig, dict):
                verification_candidates.extend([sig.get("signature_verification"), sig.get("verification"), sig.get("verified"), sig.get("status")])

    verified_text = "N/A"
    for candidate in verification_candidates:
        if candidate not in (None, "", [], {}):
            verified_text = normalize_verification_text(candidate)
            break

    verified_lower = verified_text.lower()
    result["verified"] = verified_text

    if any(x in verified_lower for x in ["not signed", "unsigned", "file is not signed"]):
        result["is_signed"], result["is_valid"] = False, False
    elif any(x in verified_lower for x in ["signed file, valid signature", "valid signature"]):
        result["is_signed"], result["is_valid"] = True, True
    elif "signed" in verified_lower:
        result["is_signed"] = True
        result["is_valid"] = "invalid" not in verified_lower
    elif "invalid" in verified_lower:
        result["is_signed"], result["is_valid"] = True, False
    else:
        has_signature_artifacts = any([
            isinstance(signature_info, dict) and len(signature_info) > 0,
            isinstance(signatures, list) and len(signatures) > 0,
            isinstance(pe_info, dict) and any(k in pe_info for k in ["signers", "signer_info", "signature_info", "date_signed"]),
        ])
        if has_signature_artifacts:
            result["is_signed"], result["is_valid"] = True, False

    # Extracción de Publisher, Signers, etc...
    if isinstance(signature_info, dict) and signature_info:
        signers = signature_info.get("signers") or signature_info.get("signer") or []
        if isinstance(signers, str): signers = [signers]
        if signers: result["signers"] = signers
        result["publisher"] = signature_info.get("publisher") or signature_info.get("company") or signature_info.get("copyright") or "N/A"
        result["date_signed"] = signature_info.get("date_signed") or signature_info.get("signing_time") or "N/A"

    if isinstance(signatures, list) and signatures:
        for sig in signatures:
            if isinstance(sig, dict):
                signer = sig.get("signer") or sig.get("subject") or sig.get("name")
                if signer and not result["signers"]: result["signers"] = [str(signer)]
                if result["publisher"] == "N/A": result["publisher"] = str(sig.get("publisher") or sig.get("company") or "N/A")

    if not isinstance(version_info, dict): version_info = {}
    result["product"] = version_info.get("Product") or "N/A"
    result["description"] = version_info.get("FileDescription") or "N/A"
    result["file_version"] = version_info.get("FileVersion") or "N/A"
    result["original_name"] = version_info.get("OriginalFilename") or "N/A"

    return result


def extract_history_info(vt_attributes: dict) -> dict:
    return {
        "fecha_creacion": format_unix_timestamp(vt_attributes.get("creation_date")),
        "primera_subida_vt": format_unix_timestamp(vt_attributes.get("first_submission_date")),
        "ultima_subida_vt": format_unix_timestamp(vt_attributes.get("last_submission_date")),
        "ultimo_analisis": format_unix_timestamp(vt_attributes.get("last_analysis_date")),
    }


# ==============================================================================
# RED / HOSTNAME / API CLIENTS
# ==============================================================================
@st.cache_data(ttl=3600, show_spinner=False)
def reverse_dns_lookup(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except: return "N/A"


def parse_api_error(source: str, status_code: int, data: dict, fallback_text: str = "") -> str:
    api_message = data.get("error", {}).get("message") or data.get("errors") or fallback_text[:300] or "Error desconocido"
    return f"{source}: error {status_code} - {api_message}"


@st.cache_data(ttl=300, show_spinner=False)
def vt_ip_lookup(ip: str):
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=VT_HEADERS, timeout=20)
        return {"ok": r.status_code == 200, "status_code": r.status_code, "json": safe_json(r), "text": r.text[:500]}
    except Exception as e: return {"ok": False, "status_code": -1, "json": {}, "text": str(e)}

@st.cache_data(ttl=300, show_spinner=False)
def vt_hash_lookup(hash_value: str):
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{hash_value}", headers=VT_HEADERS, timeout=20)
        return {"ok": r.status_code == 200, "status_code": r.status_code, "json": safe_json(r), "text": r.text[:500]}
    except Exception as e: return {"ok": False, "status_code": -1, "json": {}, "text": str(e)}

@st.cache_data(ttl=300, show_spinner=False)
def vt_url_lookup(url_value: str):
    url_id = vt_url_id(url_value)
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=VT_HEADERS, timeout=20)
        return {"ok": r.status_code == 200, "status_code": r.status_code, "json": safe_json(r), "text": r.text[:500]}
    except Exception as e: return {"ok": False, "status_code": -1, "json": {}, "text": str(e)}

@st.cache_data(ttl=300, show_spinner=False)
def abuse_lookup(ip: str):
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=ABUSE_HEADERS, params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=20)
        return {"ok": r.status_code == 200, "status_code": r.status_code, "json": safe_json(r), "text": r.text[:500]}
    except Exception as e: return {"ok": False, "status_code": -1, "json": {}, "text": str(e)}


# ==============================================================================
# TEXTO PARA TICKET
# ==============================================================================
def build_ticket_text_ip(ioc, vt_m, vt_t, vt_s, rep, ab_s, ab_r, country, c_code, as_o, asn, net, host, vt_l, ab_l, verdict, observations):
    analysis_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"IOC: {ioc}\nTipo: IP\nFecha de análisis: {analysis_time}\nResultado: {verdict}\n\nResumen:\n- VT: {vt_m}/{vt_t}\n- AbuseIPDB: {ab_s}%\n\nContexto:\n- País: {country}\n- AS Owner: {as_o}\n- Reverse DNS: {host}\n\nObservaciones:\n- {observations}\n\nEnlaces:\n- VT: {vt_l}\n- Abuse: {ab_l}"

def build_ticket_text_hash(ioc, sha256, fname, ftype, size, history, signature, vt_m, vt_t, vt_s, vt_l, verdict, observations):
    analysis_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"IOC: {ioc}\nTipo: Hash\nFecha de análisis: {analysis_time}\nResultado: {verdict}\n\nDetalles:\n- SHA256: {sha256}\n- Nombre: {fname}\n- Tipo: {ftype}\n\nFirma:\n- Firmado: {'Sí' if signature['is_signed'] else 'No'}\n- Válida: {'Sí' if signature['is_valid'] else 'No'}\n- Publisher: {signature['publisher']}\n\nObservaciones:\n- {observations}\n\nEnlace VT: {vt_l}"

def build_ticket_text_url(ioc, final_url, vt_m, vt_t, vt_s, categories, vt_l, verdict, observations):
    analysis_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"IOC: {ioc}\nTipo: URL\nFecha de análisis: {analysis_time}\nResultado: {verdict}\n\nContexto:\n- URL final: {final_url}\n- Categorías: {format_categories(categories)}\n\nObservaciones:\n- {observations}\n\nEnlace VT: {vt_l}"


# ==============================================================================
# INTERFAZ Y PROCESADO
# ==============================================================================
col_input, col_actions = st.columns([6, 1])
with col_input:
    raw_iocs = st.text_area("Introduce IOC(s), uno por línea (el sistema hará Refang automático)", key="ioc_input", height=140, placeholder="8.8.8.8\n1.1.1[.]1\nhxxp://google[.]com")

with col_actions:
    st.write("")
    st.write("")
    if st.button("Limpiar", use_container_width=True): st.session_state["ioc_input"] = ""

if st.button("Analizar IOC(s)", type="primary", use_container_width=True):
    raw_list = [x.strip() for x in raw_iocs.splitlines() if x.strip()]
    iocs = list(dict.fromkeys(raw_list))

    if not iocs:
        st.warning("Introduce al menos un IOC válido.")
        st.stop()

    summary_rows, detailed_results = [], []

    with st.spinner("Consultando fuentes de inteligencia..."):
        for original_ioc in iocs:
            # --- APLICAR REFANG ---
            ioc = refang_ioc(original_ioc)
            ioc_type = detect_ioc_type(ioc)

            if ioc_type == "IP":
                vt_r, ab_r = vt_ip_lookup(ioc), abuse_lookup(ioc)
                vt_m, vt_s, vt_t, country_code, as_o, asn, net, rep = 0, 0, 0, "N/A", "N/A", "N/A", "N/A", "N/A"
                if vt_r["ok"]:
                    attr = vt_r["json"].get("data", {}).get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    vt_m, vt_s, vt_t = stats.get("malicious", 0), stats.get("suspicious", 0), total_engines_from_stats(stats)
                    country_code, as_o, asn, net, rep = attr.get("country", "N/A"), attr.get("as_owner", "N/A"), attr.get("asn", "N/A"), attr.get("network", "N/A"), normalize_reputation(attr.get("reputation", "N/A"))
                
                ab_s, ab_reports = 0, 0
                if ab_r["ok"]:
                    data = ab_r["json"].get("data", {})
                    ab_s, ab_reports = data.get("abuseConfidenceScore", 0), data.get("totalReports", 0)

                verdict, severity = get_verdict(vt_m, vt_s, ab_s)
                host = reverse_dns_lookup(ioc)
                obs = get_observations_ip(vt_m, vt_s, ab_s, ab_reports, as_o, host)
                
                summary_rows.append({"Estado": get_status_icon(verdict), "IOC": ioc, "Tipo": "IP", "Veredicto": verdict, "VT Malicious": vt_m, "VT Suspicious": vt_s, "Abuse Score": ab_s, "Reports": ab_reports, "VirusTotal": build_vt_summary_link(ioc, "IP"), "AbuseIPDB": build_abuse_summary_link(ioc, "IP")})
                detailed_results.append({"ioc": ioc, "type": "IP", "verdict": verdict, "severity": severity, "errors": [], "data": {"vt_m": vt_m, "vt_s": vt_s, "vt_t": vt_t, "country_code": country_code, "country_name": country_name_from_code(country_code), "as_o": as_o, "asn": asn, "net": net, "rep": rep, "ab_s": ab_s, "ab_r": ab_reports, "host": host, "obs": obs, "vt_l": f"https://www.virustotal.com/gui/ip-address/{ioc}", "ab_l": f"https://www.abuseipdb.com/check/{ioc}"}})

            elif ioc_type == "Hash":
                vt_r = vt_hash_lookup(ioc)
                if vt_r["ok"]:
                    attr = vt_r["json"].get("data", {}).get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    vt_m, vt_s, vt_t = stats.get("malicious", 0), stats.get("suspicious", 0), total_engines_from_stats(stats)
                    sig, hist = extract_signature_info(attr), extract_history_info(attr)
                    verdict, severity = get_verdict(vt_m, vt_s)
                    obs = get_observations_hash(vt_m, vt_s, sig)
                    
                    summary_rows.append({"Estado": get_status_icon(verdict), "IOC": ioc, "Tipo": "Hash", "Veredicto": verdict, "VT Malicious": vt_m, "VT Suspicious": vt_s, "Abuse Score": "N/A", "Reports": "N/A", "VirusTotal": build_vt_summary_link(ioc, "Hash"), "AbuseIPDB": ""})
                    detailed_results.append({"ioc": ioc, "type": "Hash", "verdict": verdict, "severity": severity, "errors": [], "data": {"vt_m": vt_m, "vt_s": vt_s, "vt_t": vt_t, "fname": attr.get("meaningful_name", "N/A"), "ftype": attr.get("type_description", "N/A"), "size": attr.get("size", "N/A"), "sha256": attr.get("sha256", "N/A"), "sig": sig, "hist": hist, "obs": obs, "vt_l": f"https://www.virustotal.com/gui/file/{ioc}"}})

            elif ioc_type == "URL":
                norm_url = normalize_url(ioc)
                vt_r = vt_url_lookup(norm_url)
                if vt_r["ok"]:
                    attr = vt_r["json"].get("data", {}).get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    vt_m, vt_s, vt_t = stats.get("malicious", 0), stats.get("suspicious", 0), total_engines_from_stats(stats)
                    verdict, severity = get_verdict(vt_m, vt_s)
                    obs = get_observations_url(vt_m, vt_s, attr.get("categories", {}))
                    
                    summary_rows.append({"Estado": get_status_icon(verdict), "IOC": ioc, "Tipo": "URL", "Veredicto": verdict, "VT Malicious": vt_m, "VT Suspicious": vt_s, "Abuse Score": "N/A", "Reports": "N/A", "VirusTotal": build_vt_summary_link(ioc, "URL"), "AbuseIPDB": ""})
                    detailed_results.append({"ioc": ioc, "type": "URL", "verdict": verdict, "severity": severity, "errors": [], "data": {"norm_ioc": norm_url, "vt_m": vt_m, "vt_s": vt_s, "vt_t": vt_t, "final_url": attr.get("url", norm_url), "cats": attr.get("categories", {}), "obs": obs, "vt_l": build_vt_summary_link(norm_url, "URL")}})

    # --- Renderizado Global ---
    st.header("Resumen global")
    st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)

    # --- Detalles por IOC ---
    for res in detailed_results:
        st.markdown("---")
        st.subheader(f"IOC analizado: {res['ioc']}")
        d = res['data']
        if d:
            show_verdict_banner(res['verdict'], res['severity'])
            if res['type'] == "IP":
                score_col, metrics_col = st.columns([1, 3])
                with score_col: render_vt_score_card(d['vt_m'], d['vt_t'])
                with metrics_col:
                    m1, m2 = st.columns(2)
                    with m1:
                        render_severity_badge("VT Malicious", d['vt_m'], get_metric_severity_for_vt(d['vt_m']))
                        render_severity_badge("VT Suspicious", d['vt_s'], "medium" if d['vt_s'] > 0 else "low")
                    with m2:
                        render_severity_badge("Abuse Score", d['ab_s'], get_metric_severity_for_abuse(d['ab_s']))
                        render_severity_badge("Reports", d['ab_r'], "medium" if d['ab_r'] > 0 else "low")
                render_abuse_score_bar(d['ab_s'], d['ab_r'])
                st.write(f"**Contexto:** País: {d['country_name']} | Owner: {d['as_o']} | Host: {d['host']}")
                ticket = build_ticket_text_ip(res['ioc'], d['vt_m'], d['vt_t'], d['vt_s'], d['rep'], d['ab_s'], d['ab_r'], d['country_name'], d['country_code'], d['as_o'], d['asn'], d['net'], d['host'], d['vt_l'], d['ab_l'], res['verdict'], d['obs'])
                render_copy_box("Ticket SOC", ticket, f"tk_{escape_key(res['ioc'])}")

            elif res['type'] == "Hash":
                score_col, metrics_col = st.columns([1, 3])
                with score_col: render_vt_score_card(d['vt_m'], d['vt_t'])
                with metrics_col:
                    render_severity_badge("VT Malicious", d['vt_m'], get_metric_severity_for_vt(d['vt_m']))
                    render_severity_badge("VT Suspicious", d['vt_s'], "medium" if d['vt_s'] > 0 else "low")
                st.write(f"**Nombre:** {d['fname']} | **Tipo:** {d['ftype']}")
                st.write(f"**Firma Digital:** Firmado: {'Sí' if d['sig']['is_signed'] else 'No'} | Válida: {'Sí' if d['sig']['is_valid'] else 'No'} | Publisher: {d['sig']['publisher']}")
                ticket = build_ticket_text_hash(res['ioc'], d['sha256'], d['fname'], d['ftype'], d['size'], d['hist'], d['sig'], d['vt_m'], d['vt_t'], d['vt_s'], d['vt_l'], res['verdict'], d['obs'])
                render_copy_box("Ticket SOC", ticket, f"tk_h_{escape_key(res['ioc'][:16])}")

            elif res['type'] == "URL":
                score_col, metrics_col = st.columns([1, 3])
                with score_col: render_vt_score_card(d['vt_m'], d['vt_t'])
                with metrics_col:
                    render_severity_badge("VT Malicious", d['vt_m'], get_metric_severity_for_vt(d['vt_m']))
                    render_severity_badge("VT Suspicious", d['vt_s'], "medium" if d['vt_s'] > 0 else "low")
                st.write(f"**URL:** {d['final_url']}")
                st.write(f"**Categorías:** {format_categories(d['cats'])}")
                ticket = build_ticket_text_url(res['ioc'], d['final_url'], d['vt_m'], d['vt_t'], d['vt_s'], d['cats'], d['vt_l'], res['verdict'], d['obs'])
                render_copy_box("Ticket SOC", ticket, f"tk_u_{escape_key(d['final_url'][:16])}")
