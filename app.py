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

# =========================
# CONFIGURACIÓN Y APIS
# =========================
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
        if not host: return False
        if is_ip(host): return True
        domain_regex = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$"
        return re.fullmatch(domain_regex, host) is not None
    except Exception: return False

def detect_ioc_type(value: str) -> str:
    value = value.strip()
    if is_ip(value): return "IP"
    if is_hash(value): return "Hash"
    if is_url(value): return "URL"
    return "Desconocido"

def safe_json(response: requests.Response) -> dict:
    try: return response.json()
    except Exception: return {}

def country_name_from_code(code: str) -> str:
    if not code or code == "N/A": return "N/A"
    try:
        country = pycountry.countries.get(alpha_2=code.upper())
        return country.name if country else code
    except Exception: return code

def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def total_engines_from_stats(stats: dict) -> int:
    if not isinstance(stats, dict): return 0
    return sum(v for v in stats.values() if isinstance(v, int))

def format_file_size(size):
    if not isinstance(size, (int, float)): return str(size)
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B": return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024

def format_unix_timestamp(ts):
    if ts in (None, "", "N/A"): return "N/A"
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception: return str(ts)

def format_categories(categories) -> str:
    if not categories: return "N/A"
    if isinstance(categories, dict): return ", ".join(f"{k}: {v}" for k, v in categories.items())
    return str(categories)

def escape_key(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", value)

def get_status_icon(verdict: str) -> str:
    if verdict == "Malicioso": return "🔴"
    if verdict == "Sospechoso": return "🟠"
    if verdict == "Bajo riesgo": return "🟢"
    return "⚪"

def get_verdict(vt_m=0, vt_s=0, ab_s=0):
    if ab_s >= 80 or vt_m >= 5: return "Malicioso"
    if ab_s >= 30 or vt_m >= 1 or vt_s >= 3: return "Sospechoso"
    return "Bajo riesgo"


# =========================
# RENDERIZADO DE COPIA
# =========================
def render_copy_box(title: str, text: str, unique_key: str, height: int = 250):
    st.subheader(title)
    escaped_text = html.escape(text)
    component_html = f"""
    <div style="margin-bottom: 10px;">
        <textarea id="copy_box_{unique_key}" readonly style="width: 100%; height: {height}px; padding: 10px; border-radius: 5px; border: 1px solid #4a4a4a; background: #0e1117; color: #fafafa; font-family: monospace; font-size: 13px;">{escaped_text}</textarea>
        <button onclick="copyText_{unique_key}()" style="margin-top: 5px; background: #ff4b4b; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; font-weight: bold;">Copiar para iTop</button>
        <span id="msg_{unique_key}" style="margin-left: 10px; color: #7dd87d; font-weight: bold;"></span>
    </div>
    <script>
    function copyText_{unique_key}() {{
        const textarea = document.getElementById("copy_box_{unique_key}");
        textarea.select();
        navigator.clipboard.writeText(textarea.value).then(() => {{
            const msg = document.getElementById("msg_{unique_key}");
            msg.innerText = "¡Copiado! ✅";
            setTimeout(() => {{ msg.innerText = ""; }}, 2000);
        }});
    }}
    </script>
    """
    components.html(component_html, height=height + 70)


# =========================
# FORMATOS DE TICKET
# =========================
def build_ticket_text_ip(ioc, vt_m, vt_t, vt_s, ab_s, reps, country, as_o, host, vt_l, ab_l, verd, obs):
    return f"IOC: {ioc}\nTipo: IP\nEstado: {verd}\nPaís: {country}\nVT: {vt_m}/{vt_t}\nAbuse Score: {ab_s}%\nReports: {reps}\nAS Owner: {as_o}\nHostname: {host}\n\nObservaciones: {obs}\n\nEnlaces:\nVT: {vt_l}\nAbuse: {ab_l}"

def build_ticket_text_hash(ioc, name, vt_m, vt_t, sig, vt_l, verd, obs):
    firmado = "SÍ (Válida)" if sig["is_valid"] else ("SÍ (No válida)" if sig["is_signed"] else "NO")
    return f"IOC: {ioc}\nTipo: Hash\nArchivo: {name}\nEstado: {verd}\nFirmado: {firmado}\nVT: {vt_m}/{vt_t}\n\nObservaciones: {obs}\n\nEnlace VT: {vt_l}"

def build_ticket_text_url(ioc, final, vt_m, vt_t, cats, vt_l, verd, obs):
    return f"IOC: {ioc}\nTipo: URL\nURL Final: {final}\nEstado: {verd}\nCategorías: {format_categories(cats)}\nVT: {vt_m}/{vt_t}\n\nObservaciones: {obs}\n\nEnlace VT: {vt_l}"


# =========================
# PROCESO PRINCIPAL
# =========================
raw_iocs = st.text_area("Introduce IOCs (uno por línea)", height=150)
if st.button("Analizar IOC(s)", type="primary", use_container_width=True):
    iocs = list(dict.fromkeys([x.strip() for x in raw_iocs.splitlines() if x.strip()]))
    if not iocs: st.stop()

    summary_rows = []
    ticket_boxes = []

    with st.spinner("Consultando fuentes..."):
        for ioc in iocs:
            t = detect_ioc_type(ioc)
            vt_m, vt_s, vt_t = 0, 0, 0
            
            # API VirusTotal
            v_res = requests.get(f"https://www.virustotal.com/api/v3/{'ip_addresses' if t=='IP' else 'files' if t=='Hash' else 'urls'}/{vt_url_id(ioc) if t=='URL' else ioc}", headers=VT_HEADERS)
            v_data = safe_json(v_res).get("data", {}).get("attributes", {})
            if v_res.status_code == 200:
                stats = v_data.get("last_analysis_stats", {})
                vt_m, vt_s, vt_t = stats.get("malicious", 0), stats.get("suspicious", 0), total_engines_from_stats(stats)

            # Lógica por tipo
            if t == "IP":
                a_res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=ABUSE_HEADERS, params={"ipAddress": ioc})
                a_data = safe_json(a_res).get("data", {})
                ab_s, reps = a_data.get("abuseConfidenceScore", 0), a_data.get("totalReports", 0)
                country = country_name_from_code(v_data.get("country"))
                as_o = v_data.get("as_owner", "N/A")
                host = "N/A"
                try: host = socket.gethostbyaddr(ioc)[0]
                except: pass
                
                verd = get_verdict(vt_m, vt_s, ab_s)
                summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "IP", "País": country, "Firmado": "N/A", "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": f"{ab_s}%"})
                ticket_boxes.append(("IP", ioc, build_ticket_text_ip(ioc, vt_m, vt_t, vt_s, ab_s, reps, country, as_o, host, f"https://www.virustotal.com/gui/ip-address/{ioc}", f"https://www.abuseipdb.com/check/{ioc}", verd, "IP analizada en fuentes SOC.")))

            elif t == "Hash":
                # Extraer firma
                sig_info = v_data.get("signature_info", {})
                is_signed = bool(sig_info)
                is_valid = sig_info.get("verified") == "Valid"
                sig = {"is_signed": is_signed, "is_valid": is_valid}
                
                verd = get_verdict(vt_m, vt_s)
                firmado_txt = "✅ Válida" if is_valid else ("⚠️ No válida" if is_signed else "❌ No")
                summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "Hash", "País": "N/A", "Firmado": firmado_txt, "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": "N/A"})
                ticket_boxes.append(("Hash", ioc, build_ticket_text_hash(ioc, v_data.get("meaningful_name", "Archivo"), vt_m, vt_t, sig, f"https://www.virustotal.com/gui/file/{ioc}", verd, "Hash analizado en VirusTotal.")))

            elif t == "URL":
                verd = get_verdict(vt_m, vt_s)
                summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "URL", "País": "N/A", "Firmado": "N/A", "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": "N/A"})
                ticket_boxes.append(("URL", ioc, build_ticket_text_url(ioc, v_data.get("url", ioc), vt_m, vt_t, v_data.get("categories", {}), f"https://www.virustotal.com/gui/url/{vt_url_id(ioc)}", verd, "URL analizada en VirusTotal.")))

    # =========================
    # VISUALIZACIÓN FINAL
    # =========================
    st.header("Resumen global")
    df = pd.DataFrame(summary_rows)
    st.dataframe(df, use_container_width=True, hide_index=True, column_config={
        "Estado": st.column_config.TextColumn("Estado", width="small"),
        "País": st.column_config.TextColumn("País", width="medium"),
        "Firmado": st.column_config.TextColumn("Firmado", width="medium"),
    })

    st.markdown("---")
    st.header("Texto para tickets")
    for t_type, t_ioc, t_text in ticket_boxes:
        render_copy_box(f"Ticket {t_type}: {t_ioc}", t_text, escape_key(t_ioc))
