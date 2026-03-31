import base64
import html
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

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

ioc = st.text_input("Introduce IP / URL / Hash")


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
        return bool(parsed.netloc)
    except Exception:
        return False


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


def render_abuse_score_bar(score: int, reports: int):
    st.subheader("AbuseIPDB Score")
    st.write(
        f"Esta IP ha sido reportada **{reports}** veces. "
        f"Confidence of Abuse: **{score}%**"
    )
    st.progress(min(max(score, 0), 100))


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

    result["product"] = (
        version_info.get("Product")
        or version_info.get("product")
        or "N/A"
    )
    result["description"] = (
        version_info.get("Description")
        or version_info.get("FileDescription")
        or version_info.get("description")
        or "N/A"
    )
    result["file_version"] = (
        version_info.get("FileVersion")
        or version_info.get("file_version")
        or "N/A"
    )
    result["original_name"] = (
        version_info.get("OriginalName")
        or version_info.get("OriginalFilename")
        or version_info.get("original_name")
        or "N/A"
    )

    return result


def extract_history_info(vt_attributes: dict) -> dict:
    return {
        "creation_time": format_unix_timestamp(vt_attributes.get("creation_date")),
        "first_submission": format_unix_timestamp(vt_attributes.get("first_submission_date")),
        "last_submission": format_unix_timestamp(vt_attributes.get("last_submission_date")),
        "last_analysis": format_unix_timestamp(vt_attributes.get("last_analysis_date")),
    }


def format_categories(categories) -> str:
    if not categories:
        return "N/A"
    if isinstance(categories, dict):
        return ", ".join(f"{k}: {v}" for k, v in categories.items())
    if isinstance(categories, list):
        return ", ".join(str(x) for x in categories)
    return str(categories)


def render_ticket_box(ticket_text: str, unique_key: str):
    st.subheader("Texto para ticket")

    escaped_text = html.escape(ticket_text)
    component_html = f"""
    <div style="margin-top: 0.5rem; margin-bottom: 1rem;">
        <textarea
            id="ticket_box_{unique_key}"
            readonly
            style="
                width: 100%;
                height: 320px;
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
            onclick="copyTicketText_{unique_key}()"
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
    function copyTicketText_{unique_key}() {{
        const textarea = document.getElementById("ticket_box_{unique_key}");
        textarea.select();
        textarea.setSelectionRange(0, 999999);

        navigator.clipboard.writeText(textarea.value).then(function() {{
            const msg = document.getElementById("copy_msg_{unique_key}");
            msg.innerText = "Copiado";
            setTimeout(() => {{
                msg.innerText = "";
            }}, 2000);
        }});
    }}
    </script>
    """
    components.html(component_html, height=390)


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
    vt_link,
    abuse_link,
    verdict
):
    analysis_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""[IOC CHECK - IP]

Fecha de análisis: {analysis_time}
IOC analizado: {ioc}
Tipo: IP

[RESUMEN]
Resultado: {verdict}
VirusTotal: {vt_malicious}/{vt_total} motores la clasifican como maliciosa
Detecciones sospechosas en VT: {vt_suspicious}
VT Reputation: {reputation}
AbuseIPDB Confidence of Abuse: {abuse_score}%
Reportes en AbuseIPDB: {reports}

[CONTEXTO]
País: {country_name} ({country_code})
AS Owner: {as_owner}

[ENLACES]
{ioc} - VirusTotal: {vt_link}
{ioc} - AbuseIPDB: {abuse_link}
"""


def build_ticket_text_hash(
    ioc,
    sha256,
    file_name,
    file_type,
    size,
    history,
    vt_malicious,
    vt_total,
    vt_suspicious,
    signature,
    vt_link,
    verdict
):
    analysis_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""[IOC CHECK - HASH]

Fecha de análisis: {analysis_time}
IOC analizado: {ioc}
Tipo: Hash

[RESUMEN]
Resultado: {verdict}
VirusTotal: {vt_malicious}/{vt_total} motores lo clasifican como malicioso
Detecciones sospechosas en VT: {vt_suspicious}

[DETALLES DEL ARCHIVO]
SHA256: {sha256}
Nombre de archivo: {file_name}
Tipo de archivo: {file_type}
Tamaño: {format_file_size(size)}

[HISTORIAL]
Creation Time: {history['creation_time']}
First Submission: {history['first_submission']}
Last Submission: {history['last_submission']}
Last Analysis: {history['last_analysis']}

[FIRMA DIGITAL]
Firmado: {'Sí' if signature['is_signed'] else 'No'}
Firma válida: {'Sí' if signature['is_valid'] else 'No'}
Verificación: {signature['verified']}
Publisher: {signature['publisher']}
Signers: {', '.join(signature['signers']) if signature['signers'] else 'N/A'}
Producto: {signature['product']}
Descripción: {signature['description']}
Versión: {signature['file_version']}
Fecha firma: {signature['date_signed']}

[ENLACES]
{ioc} - VirusTotal: {vt_link}
"""


def build_ticket_text_url(
    ioc,
    final_url,
    vt_malicious,
    vt_total,
    vt_suspicious,
    categories,
    vt_link,
    verdict
):
    analysis_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""[IOC CHECK - URL]

Fecha de análisis: {analysis_time}
IOC analizado: {ioc}
Tipo: URL

[RESUMEN]
Resultado: {verdict}
VirusTotal: {vt_malicious}/{vt_total} motores la clasifican como maliciosa
Detecciones sospechosas en VT: {vt_suspicious}

[CONTEXTO]
URL final: {final_url}
Categorías: {format_categories(categories)}

[ENLACES]
{final_url} - VirusTotal: {vt_link}
"""


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


if ioc:
    ioc = ioc.strip()

    with st.spinner("Consultando fuentes de inteligencia..."):

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

            render_abuse_score_bar(abuse_score, reports)

            st.subheader("Contexto")
            country_name = country_name_from_code(country_code)
            c1, c2, c3 = st.columns(3)
            c1.write(f"**País:** {country_name} ({country_code})")
            c2.write(f"**AS Owner:** {as_owner}")
            c3.write(f"**VT Reputation:** {reputation}")

            st.subheader("Enlaces")
            vt_ip_link = f"https://www.virustotal.com/gui/ip-address/{ioc}"
            abuse_ip_link = f"https://www.abuseipdb.com/check/{ioc}"

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
                vt_link=vt_ip_link,
                abuse_link=abuse_ip_link,
                verdict=verdict,
            )
            render_ticket_box(ticket_text, f"ip_{ioc.replace('.', '_')}")

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

                signature = extract_signature_info(attr)
                history = extract_history_info(attr)

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
                c3.write(f"**Tamaño:** {format_file_size(size)}")

                st.subheader("History")
                h1, h2, h3, h4 = st.columns(4)
                h1.write(f"**Creation Time:** {history['creation_time']}")
                h2.write(f"**First Submission:** {history['first_submission']}")
                h3.write(f"**Last Submission:** {history['last_submission']}")
                h4.write(f"**Last Analysis:** {history['last_analysis']}")

                st.subheader("Firma digital")

                if signature["is_signed"]:
                    if signature["is_valid"]:
                        st.success("El archivo está firmado digitalmente y la firma parece válida.")
                    else:
                        st.warning("El archivo está firmado digitalmente, pero la verificación no parece válida o no está clara.")

                    s1, s2, s3 = st.columns(3)
                    s1.write("**Firmado:** Sí")
                    s2.write(f"**Verificación:** {signature['verified']}")
                    s3.write(f"**Publisher:** {signature['publisher']}")

                    if signature["signers"]:
                        st.write(f"**Signer(s):** {', '.join(signature['signers'])}")

                    meta1, meta2, meta3, meta4 = st.columns(4)
                    meta1.write(f"**Producto:** {signature['product']}")
                    meta2.write(f"**Descripción:** {signature['description']}")
                    meta3.write(f"**File Version:** {signature['file_version']}")
                    meta4.write(f"**Date Signed:** {signature['date_signed']}")
                else:
                    st.error("El archivo NO está firmado digitalmente.")
                    st.write(f"**Verificación:** {signature['verified']}")

                st.subheader("Enlaces")
                vt_hash_link = f"https://www.virustotal.com/gui/file/{ioc}"
                st.markdown(f"[{ioc} - VirusTotal]({vt_hash_link})")

                ticket_text = build_ticket_text_hash(
                    ioc=ioc,
                    sha256=sha256,
                    file_name=file_name,
                    file_type=file_type,
                    size=size,
                    history=history,
                    vt_malicious=vt_malicious,
                    vt_total=vt_total,
                    vt_suspicious=vt_suspicious,
                    signature=signature,
                    vt_link=vt_hash_link,
                    verdict=verdict,
                )
                render_ticket_box(ticket_text, f"hash_{ioc[:12]}")

            else:
                show_api_error("VirusTotal", vt_response)

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
                    st.write(f"**Categorías:** {format_categories(categories)}")

                st.subheader("Enlaces")
                vt_url_link = f"https://www.virustotal.com/gui/url/{vt_url_id(ioc)}"
                st.markdown(f"[{final_url} - VirusTotal]({vt_url_link})")

                ticket_text = build_ticket_text_url(
                    ioc=ioc,
                    final_url=final_url,
                    vt_malicious=vt_malicious,
                    vt_total=vt_total,
                    vt_suspicious=vt_suspicious,
                    categories=categories,
                    vt_link=vt_url_link,
                    verdict=verdict,
                )
                render_ticket_box(ticket_text, "url_ticket")

            else:
                show_api_error("VirusTotal", vt_response)

        else:
            st.warning("Tipo de IOC no reconocido. Introduce una IP, URL o hash válido.")
