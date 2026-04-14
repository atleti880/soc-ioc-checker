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
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.2f} {unit}"
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
# EXTRACCIÓN DE DATOS COMPLEJOS
# =========================
def extract_signature_info(vt_attributes: dict) -> dict:
    sig_info = vt_attributes.get("signature_info", {})
    v_info = vt_attributes.get("file_version_info", {})
    return {
        "is_signed": bool(sig_info),
        "is_valid": sig_info.get("verified") == "Valid",
        "publisher": sig_info.get("publisher", "N/A"),
        "product": v_info.get("Product", "N/A"),
        "description": v_info.get("FileDescription", "N/A")
    }

def extract_history_info(vt_attributes: dict) -> dict:
    return {
        "creation": format_unix_timestamp(vt_attributes.get("creation_date")),
        "first_sub": format_unix_timestamp(vt_attributes.get("first_submission_date")),
        "last_sub": format_unix_timestamp(vt_attributes.get("last_submission_date")),
    }

# =========================
# FORMATOS DE TICKET (VERSION ORIGINAL RESTAURADA)
# =========================
def build_ticket_text_ip(ioc, vt_malicious, vt_total, vt_suspicious, reputation, abuse_score, reports, country_name, country_code, as_owner, asn, network, hostname, vt_link, abuse_link, verdict, observations):
    return f"""--- DETALLES DEL INDICADOR (IOC) ---
IOC:         {ioc}
TIPO:        IP Address
ESTADO:      {verdict.upper()}
FECHA:       {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

[1] REPUTACIÓN Y SCORE
--------------------------------------------------
VirusTotal:    {vt_malicious}/{vt_total} detecciones maliciosas
               {vt_suspicious} detecciones sospechosas
               Reputación VT: {reputation}

AbuseIPDB:     Confidence Score: {abuse_score}%
               Total Reportes: {reports}

[2] INFORMACIÓN DE CONTEXTO
--------------------------------------------------
País:        {country_name} ({country_code})
Proveedor:   {as_owner}
ASN:         {asn}
Red/Rango:   {network}
Hostname:    {hostname}

[3] OBSERVACIONES SOC
--------------------------------------------------
{observations}

[4] EVIDENCIAS Y ENLACES
--------------------------------------------------
- VirusTotal: {vt_link}
- AbuseIPDB:  {abuse_link}
--------------------------------------------------"""

def build_ticket_text_hash(ioc, sha256, file_name, file_type, size, history, signature, vt_malicious, vt_total, vt_suspicious, vt_link, verdict, observations):
    firmado = "SÍ" if signature["is_signed"] else "NO"
    validez = "VÁLIDA" if signature["is_valid"] else "N/A"
    return f"""--- ANÁLISIS DE ARCHIVO (HASH) ---
IOC (Hash):  {ioc}
ESTADO:      {verdict.upper()}
FECHA:       {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

[1] IDENTIFICACIÓN DEL ARCHIVO
--------------------------------------------------
Nombre:      {file_name}
Tipo:        {file_type}
Tamaño:      {format_file_size(size)}
SHA256:      {sha256}

[2] REPUTACIÓN (VirusTotal)
--------------------------------------------------
Detecciones: {vt_malicious}/{vt_total} motores maliciosos
             {vt_suspicious} motores sospechosos

[3] FIRMA DIGITAL Y ORIGEN
--------------------------------------------------
Firmado:     {firmado}
Estado:      {validez}
Publisher:   {signature["publisher"]}
Producto:    {signature["product"]}

[4] HISTORIAL (VT)
--------------------------------------------------
Creación:    {history["creation"]}
1ª Subida:   {history["first_sub"]}
Últ. Subida: {history["last_sub"]}

[5] OBSERVACIONES SOC
--------------------------------------------------
{observations}

[6] EVIDENCIAS
--------------------------------------------------
- VirusTotal: {vt_link}
--------------------------------------------------"""

def build_ticket_text_url(ioc, final_url, vt_malicious, vt_total, vt_suspicious, categories, vt_link, verdict, observations):
    return f"""--- ANÁLISIS DE URL / DOMINIO ---
IOC:         {ioc}
ESTADO:      {verdict.upper()}
FECHA:       {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

[1] DETALLES DE LA URL
--------------------------------------------------
URL Final:   {final_url}
Categoría:   {format_categories(categories)}

[2] REPUTACIÓN (VirusTotal)
--------------------------------------------------
Detecciones: {vt_malicious}/{vt_total} motores maliciosos
             {vt_suspicious} motores sospechosos

[3] OBSERVACIONES SOC
--------------------------------------------------
{observations}

[4] EVIDENCIAS
--------------------------------------------------
- VirusTotal: {vt_link}
--------------------------------------------------"""

def render_copy_box(title: str, text: str, unique_key: str, height: int = 300):
    st.subheader(title)
    escaped_text = html.escape(text)
    component_html = f"""
    <div style="margin-bottom: 10px;">
        <textarea id="cb_{unique_key}" readonly style="width: 100%; height: {height}px; padding: 10px; background: #0e1117; color: #fafafa; font-family: monospace; font-size: 13px; border-radius: 5px; border: 1px solid #4a4a4a;">{escaped_text}</textarea>
        <button onclick="copy_{unique_key}()" style="margin-top: 8px; background: #ff4b4b; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold;">Copiar Ticket</button>
    </div>
    <script>
    function copy_{unique_key}() {{
        var txt = document.getElementById("cb_{unique_key}");
        txt.select();
        navigator.clipboard.writeText(txt.value);
    }}
    </script>
    """
    components.html(component_html, height=height + 80)

# =========================
# LÓGICA DE PROCESAMIENTO
# =========================
raw_iocs = st.text_area("Introduce IOCs", height=100)
if st.button("Analizar IOC(s)", type="primary"):
    iocs = list(dict.fromkeys([x.strip() for x in raw_iocs.splitlines() if x.strip()]))
    if not iocs: st.stop()

    summary_rows = []
    ticket_data_list = []

    with st.spinner("Procesando..."):
        for ioc in iocs:
            t = detect_ioc_type(ioc)
            vt_res = requests.get(f"https://www.virustotal.com/api/v3/{'ip_addresses' if t=='IP' else 'files' if t=='Hash' else 'urls'}/{vt_url_id(ioc) if t=='URL' else ioc}", headers=VT_HEADERS)
            v_attr = safe_json(vt_res).get("data", {}).get("attributes", {})
            
            vt_m, vt_s, vt_t = 0, 0, 0
            if vt_res.status_code == 200:
                stats = v_attr.get("last_analysis_stats", {})
                vt_m, vt_s, vt_t = stats.get("malicious", 0), stats.get("suspicious", 0), total_engines_from_stats(stats)

            if t == "IP":
                a_res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=ABUSE_HEADERS, params={"ipAddress": ioc})
                a_data = safe_json(a_res).get("data", {})
                ab_s = a_data.get("abuseConfidenceScore", 0)
                verd = get_verdict(vt_m, vt_s, ab_s)
                c_name = country_name_from_code(v_attr.get("country"))
                summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "IP", "País": c_name, "Firmado": "N/A", "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": f"{ab_s}%"})
                
                # Guardar datos para el ticket original
                host = "N/A"
                try: host = socket.gethostbyaddr(ioc)[0]
                except: pass
                ticket_data_list.append(("IP", ioc, {
                    "vt_m": vt_m, "vt_t": vt_t, "vt_s": vt_s, "rep": v_attr.get("reputation", 0),
                    "ab_s": ab_s, "reps": a_data.get("totalReports", 0), "c_n": c_name, 
                    "c_c": v_attr.get("country", "N/A"), "as": v_attr.get("as_owner", "N/A"),
                    "asn": v_attr.get("asn", "N/A"), "net": v_attr.get("network", "N/A"),
                    "host": host, "vt_l": f"https://www.virustotal.com/gui/ip-address/{ioc}",
                    "ab_l": f"https://www.abuseipdb.com/check/{ioc}", "verd": verd, "obs": "IP analizada."
                }))

            elif t == "Hash":
                sig = extract_signature_info(v_attr)
                hist = extract_history_info(v_attr)
                verd = get_verdict(vt_m, vt_s)
                firmado_txt = "✅ Válida" if sig["is_valid"] else ("⚠️ No válida" if sig["is_signed"] else "❌ No")
                summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "Hash", "País": "N/A", "Firmado": firmado_txt, "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": "N/A"})
                
                ticket_data_list.append(("Hash", ioc, {
                    "sha": v_attr.get("sha256", ioc), "name": v_attr.get("meaningful_name", "N/A"),
                    "type": v_attr.get("type_description", "N/A"), "size": v_attr.get("size", 0),
                    "hist": hist, "sig": sig, "vt_m": vt_m, "vt_t": vt_t, "vt_s": vt_s,
                    "vt_l": f"https://www.virustotal.com/gui/file/{ioc}", "verd": verd, "obs": "Archivo analizado."
                }))

            elif t == "URL":
                verd = get_verdict(vt_m, vt_s)
                summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "URL", "País": "N/A", "Firmado": "N/A", "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": "N/A"})
                
                ticket_data_list.append(("URL", ioc, {
                    "final": v_attr.get("url", ioc), "vt_m": vt_m, "vt_t": vt_t, "vt_s": vt_s,
                    "cats": v_attr.get("categories", {}), "vt_l": f"https://www.virustotal.com/gui/url/{vt_url_id(ioc)}",
                    "verd": verd, "obs": "URL analizada."
                }))

    # VISUALIZACIÓN
    st.header("Resumen global")
    df = pd.DataFrame(summary_rows)
    st.dataframe(df, use_container_width=True, hide_index=True, column_config={
        "Estado": st.column_config.TextColumn("Estado", width="small"),
        "País": st.column_config.TextColumn("País", width="medium"),
        "Firmado": st.column_config.TextColumn("Firmado", width="medium"),
    })

    st.markdown("---")
    st.header("Texto para tickets")
    for type, ioc, d in ticket_data_list:
        if type == "IP":
            txt = build_ticket_text_ip(ioc, d["vt_m"], d["vt_t"], d["vt_s"], d["rep"], d["ab_s"], d["reps"], d["c_n"], d["c_c"], d["as"], d["asn"], d["net"], d["host"], d["vt_l"], d["ab_l"], d["verd"], d["obs"])
        elif type == "Hash":
            txt = build_ticket_text_hash(ioc, d["sha"], d["name"], d["type"], d["size"], d["hist"], d["sig"], d["vt_m"], d["vt_t"], d["vt_s"], d["vt_l"], d["verd"], d["obs"])
        else:
            txt = build_ticket_text_url(ioc, d["final"], d["vt_m"], d["vt_t"], d["vt_s"], d["cats"], d["vt_l"], d["verd"], d["obs"])
        render_copy_box(f"Ticket {type}: {ioc}", txt, escape_key(ioc))
