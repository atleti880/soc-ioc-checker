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

VT_API = st.secrets["VT_API"]
ABUSE_API = st.secrets["ABUSE_API"]

VT_HEADERS = {"x-apikey": VT_API}
ABUSE_HEADERS = {"Key": ABUSE_API, "Accept": "application/json"}

st.set_page_config(page_title="SOC IOC Checker", page_icon="🛡️", layout="wide")

st.title("SOC IOC Checker")
st.caption("Consulta IP / URL / Hash en VirusTotal y AbuseIPDB")


# =========================
# UTILIDADES BÁSICAS
# =========================
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


# =========================
# VEREDICTO / OBSERVACIONES
# =========================
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
        obs.append(
            f"La IP no tiene detecciones maliciosas, pero sí {vt_suspicious} detecciones sospechosas en VirusTotal."
        )
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
        obs.append(
            f"El hash presenta {vt_suspicious} detecciones sospechosas, sin detecciones maliciosas directas."
        )
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


# =========================
# RENDER VISUAL
# =========================
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


def render_abuse_score_bar(score: int, reports: int):
    st.subheader("AbuseIPDB Score")
    st.write(
        f"Esta IP ha sido reportada **{reports}** veces. "
        f"Confidence of Abuse: **{score}%**"
    )
    st.progress(min(max(score, 0), 100))


def render_severity_badge(label: str, value, severity: str):
    colors = {
        "high": ("#ffdddd", "#8b0000"),
        "medium": ("#fff4d6", "#8a5a00"),
        "low": ("#ddffea", "#0a6b33"),
    }
    bg, fg = colors[severity]
    st.markdown(
        f"""
        <div style="
            background:{bg};
            color:{fg};
            border-radius:10px;
            padding:10px 12px;
            margin-bottom:8px;
            font-weight:600;
        ">
            {label}: {value}
        </div>
        """,
        unsafe_allow_html=True
    )


def get_metric_severity_for_vt(vt_malicious: int) -> str:
    if vt_malicious >= 5:
        return "high"
    if vt_malicious >= 1:
        return "medium"
    return "low"


def get_metric_severity_for_abuse(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


# =========================
# PORTAPAPELES
# =========================
def render_copy_box(title: str, text: str, unique_key: str, height: int = 320):
    st.subheader(title)

    escaped_text = html.escape(text)
    component_html = f"""
    <div style="margin-top: 0.5rem; margin-bottom: 1rem;">
        <textarea
            id="copy_box_{unique_key}"
            readonly
            style="
                width: 100%;
                height: {height}px;
                padding: 12px;
                border-radius: 8px;
                border: 1px solid #4a4a4a;
                background: #0e1117;
                color: #fafafa;
                font-family: monospace;
                font-size: 14px;
                line-height: 1.5;
                resize: vertical;
                box-sizing: border-box;
            "
        >{escaped_text}</textarea>

        <button
            onclick="copyText_{unique_key}()"
            style="
                margin-top: 10px;
                background: #ff4b4b;
                color: white;
                border: none;
                padding: 10px 16px;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
            "
        >
            Copiar al portapapeles
        </button>

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
            setTimeout(() => {{
                msg.innerText = "";
            }}, 2000);
        }});
    }}
    </script>
    """
    components.html(component_html, height=height + 80)


# =========================
# FIRMA DIGITAL / HISTORIAL
# =========================
def normalize_verification_text(value) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, bool):
        return "Valid signature" if value else "Invalid signature"
    return str(value).strip()


def extract_signature_info(vt_attributes: dict) -> dict:
    result = {
        "is_signed": False,
        "is_valid": False,
        "signers": [],
        "verified": "N/A",
        "publisher": "N/A",
        "date_signed": "N/A",
        "product": "N/A",
        "description": "N/A",
        "file_version": "N/A",
        "original_name": "N/A",
    }

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
                verification_candidates.extend([
                    sig.get("signature_verification"),
                    sig.get("verification"),
                    sig.get("verified"),
                    sig.get("status"),
                ])

    verified_text = "N/A"
    for candidate in verification_candidates:
        if candidate not in (None, "", [], {}):
            verified_text = normalize_verification_text(candidate)
            break

    verified_lower = verified_text.lower()
    result["verified"] = verified_text

    if any(x in verified_lower for x in ["not signed", "unsigned", "file is not signed"]):
        result["is_signed"] = False
        result["is_valid"] = False
    elif any(x in verified_lower for x in ["signed file, valid signature", "valid signature"]):
        result["is_signed"] = True
        result["is_valid"] = True
    elif "signed" in verified_lower:
        result["is_signed"] = True
        result["is_valid"] = "invalid" not in verified_lower
    elif "invalid" in verified_lower:
        result["is_signed"] = True
        result["is_valid"] = False
    else:
        has_signature_artifacts = any([
            isinstance(signature_info, dict) and len(signature_info) > 0,
            isinstance(signatures, list) and len(signatures) > 0,
            isinstance(pe_info, dict) and any(
                k in pe_info for k in ["signers", "signer_info", "signature_info", "date_signed"]
            ),
        ])
        if has_signature_artifacts:
            result["is_signed"] = True
            result["is_valid"] = False

    if isinstance(signature_info, dict) and signature_info:
        signers = signature_info.get("signers") or signature_info.get("signer") or []
        if isinstance(signers, str):
            signers = [signers]
        elif not isinstance(signers, list):
            signers = []

        publisher = (
            signature_info.get("publisher")
            or signature_info.get("company")
            or signature_info.get("copyright")
            or "N/A"
        )
        date_signed = signature_info.get("date_signed") or signature_info.get("signing_time") or "N/A"

        if signers:
            result["signers"] = signers
        if publisher != "N/A":
            result["publisher"] = publisher
        result["date_signed"] = date_signed

    if isinstance(signatures, list) and signatures:
        names = []
        for sig in signatures:
            if isinstance(sig, dict):
                signer = sig.get("signer") or sig.get("subject") or sig.get("name")
                if signer:
                    names.append(str(signer))
                if result["publisher"] == "N/A":
                    publisher = sig.get("publisher") or sig.get("company")
                    if publisher:
                        result["publisher"] = str(publisher)
                if result["date_signed"] == "N/A":
                    ds = sig.get("date_signed") or sig.get("signing_time")
                    if ds:
                        result["date_signed"] = str(ds)
        if names and not result["signers"]:
            result["signers"] = names

    if isinstance(pe_info, dict) and pe_info:
        signer_info = (
            pe_info.get("signers")
            or pe_info.get("signer_info")
            or pe_info.get("signature_info")
        )

        if isinstance(signer_info, list):
            names = []
            for item in signer_info:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("signer") or item.get("subject")
                    if name:
                        names.append(str(name))
                elif isinstance(item, str):
                    names.append(item)
            if names and not result["signers"]:
                result["signers"] = names

        elif isinstance(signer_info, dict):
            signer = signer_info.get("name") or signer_info.get("signer") or signer_info.get("subject")
            if signer and not result["signers"]:
                result["signers"] = [str(signer)]
            if result["publisher"] == "N/A":
                result["publisher"] = (
                    signer_info.get("publisher")
                    or signer_info.get("company")
                    or "N/A"
                )

        elif isinstance(signer_info, str) and not result["signers"]:
            result["signers"] = [signer_info]

        if result["date_signed"] == "N/A":
            ds = pe_info.get("date_signed")
            if ds:
                result["date_signed"] = str(ds)

    if not isinstance(version_info, dict):
        version_info = {}

    result["product"] = version_info.get("Product") or version_info.get("product") or "N/A"
    result["description"] = (
        version_info.get("Description")
        or version_info.get("FileDescription")
        or version_info.get("description")
        or "N/A"
    )
    result["file_version"] = version_info.get("FileVersion") or version_info.get("file_version") or "N/A"
    result["original_name"] = (
        version_info.get("OriginalName")
        or version_info.get("OriginalFilename")
        or version_info.get("original_name")
        or "N/A"
    )

    return result


def extract_history_info(vt_attributes: dict) -> dict:
    return {
        "fecha_creacion": format_unix_timestamp(vt_attributes.get("creation_date")),
        "primera_subida_vt": format_unix_timestamp(vt_attributes.get("first_submission_date")),
        "ultima_subida_vt": format_unix_timestamp(vt_attributes.get("last_submission_date")),
        "ultimo_analisis": format_unix_timestamp(vt_attributes.get("last_analysis_date")),
    }


# =========================
# RED / HOSTNAME
# =========================
@st.cache_data(ttl=3600, show_spinner=False)
def reverse_dns_lookup(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "N/A"


# =========================
# API / ERRORES
# =========================
def parse_api_error(source: str, status_code: int, data: dict, fallback_text: str = "") -> str:
    api_message = (
        data.get("error", {}).get("message")
        or data.get("errors")
        or fallback_text[:300]
        or "Error desconocido"
    )

    if status_code == 401:
        return f"{source}: API key inválida o sin permisos."
    if status_code == 403:
        return f"{source}: acceso denegado."
    if status_code == 404:
        return f"{source}: IOC no encontrado."
    if status_code == 429:
        return f"{source}: límite de peticiones excedido."
    if 500 <= status_code <= 599:
        return f"{source}: error del servicio ({status_code})."
    if status_code == -1:
        return f"{source}: error de red o timeout."
    return f"{source}: error {status_code} - {api_message}"


@st.cache_data(ttl=300, show_spinner=False)
def vt_ip_lookup(ip: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = requests.get(url, headers=VT_HEADERS, timeout=20)
        return {
            "ok": response.status_code == 200,
            "status_code": response.status_code,
            "json": safe_json(response),
            "text": response.text[:500],
        }
    except requests.RequestException as e:
        return {"ok": False, "status_code": -1, "json": {}, "text": str(e)}


@st.cache_data(ttl=300, show_spinner=False)
def vt_hash_lookup(hash_value: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    try:
        response = requests.get(url, headers=VT_HEADERS, timeout=20)
        return {
            "ok": response.status_code == 200,
            "status_code": response.status_code,
            "json": safe_json(response),
            "text": response.text[:500],
        }
    except requests.RequestException as e:
        return {"ok": False, "status_code": -1, "json": {}, "text": str(e)}


@st.cache_data(ttl=300, show_spinner=False)
def vt_url_lookup(url_value: str) -> dict:
    url_id = vt_url_id(url_value)
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        response = requests.get(url, headers=VT_HEADERS, timeout=20)
        return {
            "ok": response.status_code == 200,
            "status_code": response.status_code,
            "json": safe_json(response),
            "text": response.text[:500],
        }
    except requests.RequestException as e:
        return {"ok": False, "status_code": -1, "json": {}, "text": str(e)}


@st.cache_data(ttl=300, show_spinner=False)
def abuse_lookup(ip: str) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=ABUSE_HEADERS, params=params, timeout=20)
        return {
            "ok": response.status_code == 200,
            "status_code": response.status_code,
            "json": safe_json(response),
            "text": response.text[:500],
        }
    except requests.RequestException as e:
        return {"ok": False, "status_code": -1, "json": {}, "text": str(e)}


# =========================
# TEXTO PARA TICKET
# =========================
def build_ticket_text_ip(
    ioc,
    vt_malicious,
    vt_total,
    vt_suspicious,
    reputation,
    abuse_score,
    reports,
    country_name,
    country_code,
    as_owner,
    asn,
    network,
    hostname,
    vt_link,
    abuse_link,
    verdict,
    observations,
):
    analysis_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""IOC: {ioc}
Tipo: IP
Fecha de análisis: {analysis_time}
Resultado: {verdict}

Resumen:
- VT: {vt_malicious}/{vt_total}
- VT suspicious: {vt_suspicious}
- VT reputation: {reputation}
- AbuseIPDB: {abuse_score}%
- Reports: {reports}

Contexto:
- País: {country_name} ({country_code})
- AS Owner: {as_owner}
- ASN: {asn}
- Network: {network}
- Reverse DNS: {hostname}

Observaciones:
- {observations}

Enlaces:
- {ioc} - VirusTotal: {vt_link}
- {ioc} - AbuseIPDB: {abuse_link}
"""


def build_ticket_text_hash(
    ioc,
    sha256,
    file_name,
    file_type,
    size,
    history,
    signature,
    vt_malicious,
    vt_total,
    vt_suspicious,
    vt_link,
    verdict,
    observations,
):
    analysis_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""IOC: {ioc}
Tipo: Hash
Fecha de análisis: {analysis_time}
Resultado: {verdict}

Resumen:
- VT: {vt_malicious}/{vt_total}
- VT suspicious: {vt_suspicious}

Detalles:
- SHA256: {sha256}
- Nombre de archivo: {file_name}
- Tipo de archivo: {file_type}
- Tamaño: {format_file_size(size)}

Historial:
- Fecha de creación: {history['fecha_creacion']}
- Primera subida a VT: {history['primera_subida_vt']}
- Última subida a VT: {history['ultima_subida_vt']}
- Último análisis: {history['ultimo_analisis']}

Firma digital:
- Firmado: {'Sí' if signature['is_signed'] else 'No'}
- Firma válida: {'Sí' if signature['is_valid'] else 'No'}
- Verificación: {signature['verified']}
- Publisher: {signature['publisher']}
- Signers: {', '.join(signature['signers']) if signature['signers'] else 'N/A'}
- Producto: {signature['product']}
- Descripción: {signature['description']}
- Versión: {signature['file_version']}
- Fecha firma: {signature['date_signed']}

Observaciones:
- {observations}

Enlaces:
- {ioc} - VirusTotal: {vt_link}
"""


def build_ticket_text_url(
    ioc,
    final_url,
    vt_malicious,
    vt_total,
    vt_suspicious,
    categories,
    vt_link,
    verdict,
    observations,
):
    analysis_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""IOC: {ioc}
Tipo: URL
Fecha de análisis: {analysis_time}
Resultado: {verdict}

Resumen:
- VT: {vt_malicious}/{vt_total}
- VT suspicious: {vt_suspicious}

Contexto:
- URL final: {final_url}
- Categorías: {format_categories(categories)}

Observaciones:
- {observations}

Enlaces:
- {final_url} - VirusTotal: {vt_link}
"""


# =========================
# INPUT / BOTONES
# =========================
def clear_ioc_input():
    st.session_state["ioc_input"] = ""


col_input, col_actions = st.columns([6, 1])
with col_input:
    raw_iocs = st.text_area(
        "Introduce uno o varios IOC(s), uno por línea",
        key="ioc_input",
        height=140,
        placeholder="Ejemplo:\n8.8.8.8\nexample.com\n44d88612fea8a8f36de82e1278abb02f"
    )

with col_actions:
    st.write("")
    st.write("")
    st.button("Limpiar", use_container_width=True, on_click=clear_ioc_input)

process = st.button("Analizar IOC(s)", type="primary", use_container_width=True)


# =========================
# PROCESADO PRINCIPAL
# =========================
if process:
    raw_list = [x.strip() for x in raw_iocs.splitlines() if x.strip()]

    seen = set()
    iocs = []
    for item in raw_list:
        if item not in seen:
            seen.add(item)
            iocs.append(item)

    if not iocs:
        st.warning("Introduce al menos un IOC válido.")
        st.stop()

    summary_rows = []
    detailed_results = []

    with st.spinner("Consultando fuentes de inteligencia..."):
        for ioc in iocs:
            ioc_type = detect_ioc_type(ioc)

            if ioc_type == "IP":
                vt_response = vt_ip_lookup(ioc)
                abuse_response = abuse_lookup(ioc)

                vt_malicious = 0
                vt_suspicious = 0
                vt_total = 0
                country_code = "N/A"
                as_owner = "N/A"
                asn = "N/A"
                network = "N/A"
                reputation = "N/A"
                abuse_score = 0
                reports = 0
                errors = []

                if vt_response["ok"]:
                    vt = vt_response["json"]
                    attr = vt.get("data", {}).get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    vt_malicious = stats.get("malicious", 0)
                    vt_suspicious = stats.get("suspicious", 0)
                    vt_total = total_engines_from_stats(stats)
                    country_code = attr.get("country", "N/A")
                    as_owner = attr.get("as_owner", "N/A")
                    asn = attr.get("asn", "N/A")
                    network = attr.get("network", "N/A")
                    reputation = normalize_reputation(attr.get("reputation", "N/A"))
                else:
                    errors.append(parse_api_error(
                        "VirusTotal",
                        vt_response["status_code"],
                        vt_response["json"],
                        vt_response["text"]
                    ))

                if abuse_response["ok"]:
                    abuse = abuse_response["json"]
                    data = abuse.get("data", {})
                    abuse_score = data.get("abuseConfidenceScore", 0)
                    reports = data.get("totalReports", 0)
                else:
                    errors.append(parse_api_error(
                        "AbuseIPDB",
                        abuse_response["status_code"],
                        abuse_response["json"],
                        abuse_response["text"]
                    ))

                verdict, severity = get_verdict(vt_malicious, vt_suspicious, abuse_score)
                hostname = reverse_dns_lookup(ioc)
                country_name = country_name_from_code(country_code)
                observations = get_observations_ip(
                    vt_malicious, vt_suspicious, abuse_score, reports, as_owner, hostname
                )
                vt_ip_link = f"https://www.virustotal.com/gui/ip-address/{ioc}"
                abuse_ip_link = f"https://www.abuseipdb.com/check/{ioc}"

                summary_rows.append({
                    "IOC": ioc,
                    "Tipo": "IP",
                    "Veredicto": verdict,
                    "VT Malicious": vt_malicious,
                    "VT Suspicious": vt_suspicious,
                    "Abuse Score": abuse_score,
                    "Reports": reports,
                })

                detailed_results.append({
                    "ioc": ioc,
                    "type": "IP",
                    "verdict": verdict,
                    "severity": severity,
                    "errors": errors,
                    "data": {
                        "vt_malicious": vt_malicious,
                        "vt_suspicious": vt_suspicious,
                        "vt_total": vt_total,
                        "country_code": country_code,
                        "country_name": country_name,
                        "as_owner": as_owner,
                        "asn": asn,
                        "network": network,
                        "reputation": reputation,
                        "abuse_score": abuse_score,
                        "reports": reports,
                        "hostname": hostname,
                        "observations": observations,
                        "vt_ip_link": vt_ip_link,
                        "abuse_ip_link": abuse_ip_link,
                    }
                })

            elif ioc_type == "Hash":
                vt_response = vt_hash_lookup(ioc)

                if not vt_response["ok"]:
                    err = parse_api_error(
                        "VirusTotal",
                        vt_response["status_code"],
                        vt_response["json"],
                        vt_response["text"]
                    )
                    summary_rows.append({
                        "IOC": ioc,
                        "Tipo": "Hash",
                        "Veredicto": "Error",
                        "VT Malicious": 0,
                        "VT Suspicious": 0,
                        "Abuse Score": "N/A",
                        "Reports": "N/A",
                    })
                    detailed_results.append({
                        "ioc": ioc,
                        "type": "Hash",
                        "verdict": "Error",
                        "severity": "high",
                        "errors": [err],
                        "data": None,
                    })
                    continue

                vt = vt_response["json"]
                attr = vt.get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})

                vt_malicious = stats.get("malicious", 0)
                vt_suspicious = stats.get("suspicious", 0)
                vt_total = total_engines_from_stats(stats)

                file_name = attr.get("meaningful_name", "N/A")
                file_type = attr.get("type_description", "N/A")
                size = attr.get("size", "N/A")
                sha256 = attr.get("sha256", "N/A")

                signature = extract_signature_info(attr)
                history = extract_history_info(attr)
                verdict, severity = get_verdict(vt_malicious, vt_suspicious, 0)
                observations = get_observations_hash(vt_malicious, vt_suspicious, signature)
                vt_hash_link = f"https://www.virustotal.com/gui/file/{ioc}"

                summary_rows.append({
                    "IOC": ioc,
                    "Tipo": "Hash",
                    "Veredicto": verdict,
                    "VT Malicious": vt_malicious,
                    "VT Suspicious": vt_suspicious,
                    "Abuse Score": "N/A",
                    "Reports": "N/A",
                })

                detailed_results.append({
                    "ioc": ioc,
                    "type": "Hash",
                    "verdict": verdict,
                    "severity": severity,
                    "errors": [],
                    "data": {
                        "vt_malicious": vt_malicious,
                        "vt_suspicious": vt_suspicious,
                        "vt_total": vt_total,
                        "file_name": file_name,
                        "file_type": file_type,
                        "size": size,
                        "sha256": sha256,
                        "signature": signature,
                        "history": history,
                        "observations": observations,
                        "vt_hash_link": vt_hash_link,
                    }
                })

            elif ioc_type == "URL":
                normalized_ioc = normalize_url(ioc)
                vt_response = vt_url_lookup(normalized_ioc)

                if not vt_response["ok"]:
                    err = parse_api_error(
                        "VirusTotal",
                        vt_response["status_code"],
                        vt_response["json"],
                        vt_response["text"]
                    )
                    summary_rows.append({
                        "IOC": ioc,
                        "Tipo": "URL",
                        "Veredicto": "Error",
                        "VT Malicious": 0,
                        "VT Suspicious": 0,
                        "Abuse Score": "N/A",
                        "Reports": "N/A",
                    })
                    detailed_results.append({
                        "ioc": ioc,
                        "type": "URL",
                        "verdict": "Error",
                        "severity": "high",
                        "errors": [err],
                        "data": None,
                    })
                    continue

                vt = vt_response["json"]
                attr = vt.get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})

                vt_malicious = stats.get("malicious", 0)
                vt_suspicious = stats.get("suspicious", 0)
                vt_total = total_engines_from_stats(stats)
                final_url = attr.get("url", normalized_ioc)
                categories = attr.get("categories", {})
                verdict, severity = get_verdict(vt_malicious, vt_suspicious, 0)
                observations = get_observations_url(vt_malicious, vt_suspicious, categories)
                vt_url_link = f"https://www.virustotal.com/gui/url/{vt_url_id(normalized_ioc)}"

                summary_rows.append({
                    "IOC": ioc,
                    "Tipo": "URL",
                    "Veredicto": verdict,
                    "VT Malicious": vt_malicious,
                    "VT Suspicious": vt_suspicious,
                    "Abuse Score": "N/A",
                    "Reports": "N/A",
                })

                detailed_results.append({
                    "ioc": ioc,
                    "type": "URL",
                    "verdict": verdict,
                    "severity": severity,
                    "errors": [],
                    "data": {
                        "normalized_ioc": normalized_ioc,
                        "vt_malicious": vt_malicious,
                        "vt_suspicious": vt_suspicious,
                        "vt_total": vt_total,
                        "final_url": final_url,
                        "categories": categories,
                        "observations": observations,
                        "vt_url_link": vt_url_link,
                    }
                })

            else:
                summary_rows.append({
                    "IOC": ioc,
                    "Tipo": "Desconocido",
                    "Veredicto": "No válido",
                    "VT Malicious": "N/A",
                    "VT Suspicious": "N/A",
                    "Abuse Score": "N/A",
                    "Reports": "N/A",
                })
                detailed_results.append({
                    "ioc": ioc,
                    "type": "Desconocido",
                    "verdict": "No válido",
                    "severity": "medium",
                    "errors": [f"Tipo de IOC no reconocido: {ioc}"],
                    "data": None,
                })

    st.markdown("---")
    st.header("Resumen global")
    df = pd.DataFrame(summary_rows)
    st.dataframe(df, use_container_width=True)

    st.markdown("---")
    st.header("Detalles por IOC")

    for result in detailed_results:
        ioc = result["ioc"]
        ioc_type = result["type"]
        verdict = result["verdict"]
        severity = result["severity"]
        errors = result["errors"]
        data = result["data"]

        with st.container():
            st.markdown("---")
            st.subheader(f"IOC analizado: {ioc}")
            st.info(f"Tipo detectado: {ioc_type}")

            for err in errors:
                st.error(err)

            if data is None:
                continue

            show_verdict_banner(verdict, severity)

            if ioc_type == "IP":
                vt_malicious = data["vt_malicious"]
                vt_suspicious = data["vt_suspicious"]
                vt_total = data["vt_total"]
                country_code = data["country_code"]
                country_name = data["country_name"]
                as_owner = data["as_owner"]
                asn = data["asn"]
                network = data["network"]
                reputation = data["reputation"]
                abuse_score = data["abuse_score"]
                reports = data["reports"]
                hostname = data["hostname"]
                observations = data["observations"]
                vt_ip_link = data["vt_ip_link"]
                abuse_ip_link = data["abuse_ip_link"]

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
                    m1, m2 = st.columns(2)
                    with m1:
                        render_severity_badge("VT Malicious", vt_malicious, get_metric_severity_for_vt(vt_malicious))
                        render_severity_badge(
                            "VT Suspicious", vt_suspicious, "medium" if vt_suspicious > 0 else "low"
                        )
                    with m2:
                        render_severity_badge("Abuse Score", abuse_score, get_metric_severity_for_abuse(abuse_score))
                        render_severity_badge("Reports", reports, "medium" if reports > 0 else "low")

                render_abuse_score_bar(abuse_score, reports)

                st.subheader("Contexto")
                c1, c2, c3 = st.columns(3)
                c1.write(f"**País:** {country_name} ({country_code})")
                c2.write(f"**AS Owner:** {as_owner}")
                c3.write(f"**VT Reputation:** {reputation}")

                c4, c5, c6 = st.columns(3)
                c4.write(f"**ASN:** {asn}")
                c5.write(f"**Network:** {network}")
                c6.write(f"**Reverse DNS:** {hostname}")

                st.subheader("Observaciones")
                st.write(observations)

                st.subheader("Enlaces")
                st.markdown(f"[{ioc} - VirusTotal]({vt_ip_link})")
                st.markdown(f"[{ioc} - AbuseIPDB]({abuse_ip_link})")

                ticket_text = build_ticket_text_ip(
                    ioc=ioc,
                    vt_malicious=vt_malicious,
                    vt_total=vt_total,
                    vt_suspicious=vt_suspicious,
                    reputation=reputation,
                    abuse_score=abuse_score,
                    reports=reports,
                    country_name=country_name,
                    country_code=country_code,
                    as_owner=as_owner,
                    asn=asn,
                    network=network,
                    hostname=hostname,
                    vt_link=vt_ip_link,
                    abuse_link=abuse_ip_link,
                    verdict=verdict,
                    observations=observations,
                )
                render_copy_box("Texto para ticket", ticket_text, f"ticket_ip_{escape_key(ioc)}", height=320)

            elif ioc_type == "Hash":
                vt_malicious = data["vt_malicious"]
                vt_suspicious = data["vt_suspicious"]
                vt_total = data["vt_total"]
                file_name = data["file_name"]
                file_type = data["file_type"]
                size = data["size"]
                sha256 = data["sha256"]
                signature = data["signature"]
                history = data["history"]
                observations = data["observations"]
                vt_hash_link = data["vt_hash_link"]

                st.subheader("Resumen")
                st.write(
                    f"El hash **{ioc}** presenta **{vt_malicious}/{vt_total if vt_total else 0}** "
                    f"en VirusTotal y **{vt_suspicious}** detecciones sospechosas."
                )

                score_col, metrics_col = st.columns([1, 3])
                with score_col:
                    render_vt_score_card(vt_malicious, vt_total)

                with metrics_col:
                    render_severity_badge("VT Malicious", vt_malicious, get_metric_severity_for_vt(vt_malicious))
                    render_severity_badge(
                        "VT Suspicious", vt_suspicious, "medium" if vt_suspicious > 0 else "low"
                    )

                st.subheader("Contexto")
                c1, c2, c3 = st.columns(3)
                c1.write(f"**Nombre de archivo:** {file_name}")
                c2.write(f"**Tipo de archivo:** {file_type}")
                c3.write(f"**Tamaño:** {format_file_size(size)}")

                st.subheader("Historial")
                h1, h2, h3, h4 = st.columns(4)
                h1.write(f"**Fecha de creación:** {history['fecha_creacion']}")
                h2.write(f"**Primera subida a VT:** {history['primera_subida_vt']}")
                h3.write(f"**Última subida a VT:** {history['ultima_subida_vt']}")
                h4.write(f"**Último análisis:** {history['ultimo_analisis']}")

                st.subheader("Firma digital")
                if signature["is_signed"]:
                    if signature["is_valid"]:
                        st.success("El archivo está firmado digitalmente y la firma parece válida.")
                    else:
                        st.warning(
                            "El archivo está firmado digitalmente, pero la verificación no parece válida o no está clara."
                        )

                    s1, s2, s3 = st.columns(3)
                    s1.write("**Firmado:** Sí")
                    s2.write(f"**Verificación:** {signature['verified']}")
                    s3.write(f"**Publisher:** {signature['publisher']}")

                    if signature["signers"]:
                        st.write(f"**Signer(s):** {', '.join(signature['signers'])}")

                    meta1, meta2, meta3, meta4 = st.columns(4)
                    meta1.write(f"**Producto:** {signature['product']}")
                    meta2.write(f"**Descripción:** {signature['description']}")
                    meta3.write(f"**Versión:** {signature['file_version']}")
                    meta4.write(f"**Fecha firma:** {signature['date_signed']}")
                else:
                    st.error("El archivo NO está firmado digitalmente.")
                    st.write(f"**Verificación:** {signature['verified']}")

                st.subheader("Observaciones")
                st.write(observations)

                st.subheader("Enlaces")
                st.markdown(f"[{ioc} - VirusTotal]({vt_hash_link})")

                ticket_text = build_ticket_text_hash(
                    ioc=ioc,
                    sha256=sha256,
                    file_name=file_name,
                    file_type=file_type,
                    size=size,
                    history=history,
                    signature=signature,
                    vt_malicious=vt_malicious,
                    vt_total=vt_total,
                    vt_suspicious=vt_suspicious,
                    vt_link=vt_hash_link,
                    verdict=verdict,
                    observations=observations,
                )
                render_copy_box("Texto para ticket", ticket_text, f"ticket_hash_{escape_key(ioc[:16])}", height=340)

            elif ioc_type == "URL":
                normalized_ioc = data["normalized_ioc"]
                vt_malicious = data["vt_malicious"]
                vt_suspicious = data["vt_suspicious"]
                vt_total = data["vt_total"]
                final_url = data["final_url"]
                categories = data["categories"]
                observations = data["observations"]
                vt_url_link = data["vt_url_link"]

                st.subheader("Resumen")
                st.write(
                    f"La URL **{final_url}** presenta **{vt_malicious}/{vt_total if vt_total else 0}** "
                    f"en VirusTotal y **{vt_suspicious}** detecciones sospechosas."
                )

                score_col, metrics_col = st.columns([1, 3])
                with score_col:
                    render_vt_score_card(vt_malicious, vt_total)

                with metrics_col:
                    render_severity_badge("VT Malicious", vt_malicious, get_metric_severity_for_vt(vt_malicious))
                    render_severity_badge(
                        "VT Suspicious", vt_suspicious, "medium" if vt_suspicious > 0 else "low"
                    )

                st.subheader("Contexto")
                st.write(f"**URL:** {final_url}")
                st.write(f"**Categorías:** {format_categories(categories)}")

                st.subheader("Observaciones")
                st.write(observations)

                st.subheader("Enlaces")
                st.markdown(f"[{final_url} - VirusTotal]({vt_url_link})")

                ticket_text = build_ticket_text_url(
                    ioc=normalized_ioc,
                    final_url=final_url,
                    vt_malicious=vt_malicious,
                    vt_total=vt_total,
                    vt_suspicious=vt_suspicious,
                    categories=categories,
                    vt_link=vt_url_link,
                    verdict=verdict,
                    observations=observations,
                )
                render_copy_box("Texto para ticket", ticket_text, f"ticket_url_{escape_key(final_url[:16])}", height=300)
