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

# CONFIGURACIÓN DE APIS
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

def normalize_reputation(value):
    return value if value not in (None, "", "N/A") else "N/A"

def escape_key(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", value)

def get_status_icon(verdict: str) -> str:
    if verdict == "Malicioso": return "🔴"
    if verdict == "Sospechoso": return "🟠"
    if verdict == "Bajo riesgo": return "🟢"
    return "⚪"

# =========================
# NUEVA FUNCIÓN TABLA ITOP
# =========================
def df_to_markdown_table(df):
    """Genera la tabla en formato Markdown compatible con iTop."""
    if df.empty: return ""
    # Seleccionamos y renombramos columnas para que la tabla sea compacta
    cols = ["Estado", "IOC", "Tipo", "Veredicto", "VT Malicious", "Abuse Score"]
    # Filtramos solo las columnas que existan en el DF actual
    existing_cols = [c for c in cols if c in df.columns]
    sub_df = df[existing_cols].copy()
    
    header = "| " + " | ".join(sub_df.columns) + " |"
    separator = "| " + " | ".join(["---"] * len(sub_df.columns)) + " |"
    rows = []
    for _, row in sub_df.iterrows():
        # Limpiamos los valores para asegurar que no rompan el markdown
        clean_row = [str(val).replace("|", "\\|") for val in row.values]
        rows.append("| " + " | ".join(clean_row) + " |")
    
    return "\n".join([header, separator] + rows)

# =========================
# VEREDICTO / OBSERVACIONES
# =========================
def get_verdict(vt_malicious: int = 0, vt_suspicious: int = 0, abuse_score: int = 0):
    if abuse_score >= 80 or vt_malicious >= 5: return "Malicioso", "high"
    if abuse_score >= 30 or vt_malicious >= 1 or vt_suspicious >= 3: return "Sospechoso", "medium"
    return "Bajo riesgo", "low"

def get_verdict_icon(severity: str) -> str:
    if severity == "high": return "🔴"
    if severity == "medium": return "🟠"
    return "🟢"

def get_verdict_hint(severity: str) -> str:
    if severity == "high": return "Requiere revisión inmediata."
    if severity == "medium": return "Conviene validar el contexto."
    return "Sin indicadores claros."

def show_verdict_banner(verdict: str, severity: str):
    icon = get_verdict_icon(severity)
    if severity == "high": st.error(f"{icon} Veredicto: {verdict}")
    elif severity == "medium": st.warning(f"{icon} Veredicto: {verdict}")
    else: st.success(f"{icon} Veredicto: {verdict}")

def get_observations_ip(vt_m, vt_s, ab_s, reports, as_o, host):
    obs = []
    if vt_m > 0: obs.append(f"IP con {vt_m} detecciones en VT.")
    if ab_s >= 30: obs.append(f"AbuseIPDB Score: {ab_s}% ({reports} reportes).")
    if as_o != "N/A": obs.append(f"Proveedor: {as_o}.")
    return " ".join(obs)

# =========================
# RENDER VISUAL
# =========================
def render_vt_score_card(malicious: int, total: int):
    percent = 0 if total == 0 else round((malicious / total) * 100)
    card_html = f"""
    <div style="background:#1f2a44; border-radius:14px; padding:20px; text-align:center; width:200px;">
        <div style="width:100px; height:100px; border-radius:50%; margin:0 auto 10px; background: conic-gradient(#ff5a52 {percent}%, #31456e 0%); display:flex; align-items:center; justify-content:center;">
            <div style="width:75px; height:75px; border-radius:50%; background:#1f2a44; display:flex; flex-direction:column; align-items:center; justify-content:center;">
                <div style="font-size:20px; color:#ff5a52; font-weight:700;">{malicious}</div>
                <div style="font-size:12px; color:#c9d4ea;">/ {total}</div>
            </div>
        </div>
        <div style="font-size:13px; color:#c9d4ea; font-weight:600;">VT Score</div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)

def render_copy_box(title: str, text: str, unique_key: str, height: int = 250):
    st.subheader(title)
    escaped_text = html.escape(text)
    component_html = f"""
    <textarea id="cb_{unique_key}" readonly style="width:100%; height:{height}px; background:#0e1117; color:#fafafa; font-family:monospace; padding:10px; border-radius:5px;">{escaped_text}</textarea>
    <button onclick="copy_{unique_key}()" style="margin-top:5px; background:#ff4b4b; color:white; border:none; padding:8px 15px; border-radius:5px; cursor:pointer;">Copiar</button>
    <script>
    function copy_{unique_key}() {{
        var txt = document.getElementById("cb_{unique_key}");
        txt.select();
        navigator.clipboard.writeText(txt.value);
    }}
    </script>
    """
    components.html(component_html, height=height + 60)

# =========================
# APIS
# =========================
@st.cache_data(ttl=300)
def vt_lookup(ioc, ioc_type):
    if ioc_type == "IP": url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "Hash": url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else: url = f"https://www.virustotal.com/api/v3/urls/{vt_url_id(ioc)}"
    try:
        r = requests.get(url, headers=VT_HEADERS, timeout=15)
        return {"ok": r.status_code == 200, "json": safe_json(r), "status": r.status_code}
    except: return {"ok": False, "status": -1}

@st.cache_data(ttl=300)
def abuse_lookup(ip):
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=ABUSE_HEADERS, params={"ipAddress": ip}, timeout=15)
        return {"ok": r.status_code == 200, "json": safe_json(r), "status": r.status_code}
    except: return {"ok": False, "status": -1}

# =========================
# LÓGICA PRINCIPAL
# =========================
raw_iocs = st.text_area("IOCs (uno por línea)", height=100)
if st.button("Analizar", type="primary"):
    iocs = list(dict.fromkeys([x.strip() for x in raw_iocs.splitlines() if x.strip()]))
    if not iocs: st.stop()

    summary_rows = []
    
    for ioc in iocs:
        t = detect_ioc_type(ioc)
        vt_m, vt_s, vt_t, ab_s, reps = 0, 0, 0, 0, 0
        
        # Consultas
        v = vt_lookup(ioc, t)
        if v["ok"]:
            stats = v["json"]["data"]["attributes"]["last_analysis_stats"]
            vt_m, vt_s, vt_t = stats["malicious"], stats["suspicious"], total_engines_from_stats(stats)
        
        if t == "IP":
            a = abuse_lookup(ioc)
            if a["ok"]:
                ab_s = a["json"]["data"]["abuseConfidenceScore"]
                reps = a["json"]["data"]["totalReports"]

        verd, sev = get_verdict(vt_m, vt_s, ab_s)
        
        # Guardar para resumen
        summary_rows.append({
            "Estado": get_status_icon(verd),
            "IOC": ioc,
            "Tipo": t,
            "Veredicto": verd,
            "VT Malicious": vt_m,
            "Abuse Score": f"{ab_s}%" if t == "IP" else "N/A"
        })

    # Mostrar Tabla de iTop
    st.header("Resumen para iTop")
    df = pd.DataFrame(summary_rows)
    st.dataframe(df, hide_index=True, use_container_width=True)
    
    # ESTO ES LO QUE TE FALTABA:
    markdown_table = df_to_markdown_table(df)
    render_copy_box("Tabla Markdown para iTop", markdown_table, "itop_table", height=150)
    
    # Detalles individuales... (puedes añadir los tickets aquí abajo)
