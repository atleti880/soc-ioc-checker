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
# LÓGICA DE LIMPIEZA
# =========================
if "ioc_input" not in st.session_state:
    st.session_state["ioc_input"] = ""

def clear_text():
    st.session_state["ioc_input"] = ""

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
# FORMATOS DE TICKET (Investigación Interna)
# =========================
def build_ticket_text_ip(ioc, vt_m, vt_t, vt_s, rep, ab_s, reps, c_n, c_c, as_o, asn, net, host, vt_l, ab_l, verd, obs):
    return f"""--- INVESTIGACIÓN INTERNA ---
IOC:         {ioc}
TIPO:        IP Address
ESTADO:      {verd.upper()}
FECHA:       {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

[1] REPUTACIÓN Y SCORE
--------------------------------------------------
VirusTotal:    {vt_m}/{vt_t} detecciones maliciosas
               {vt_s} detecciones sospechosas
               Reputación VT: {rep}

AbuseIPDB:     Confidence Score: {ab_s}%
               Total Reportes: {reps}

[2] INFORMACIÓN DE CONTEXTO
--------------------------------------------------
País:        {c_n} ({c_c})
Proveedor:   {as_o}
ASN:         {asn}
Red/Rango:   {net}
Hostname:    {host}

[3] OBSERVACIONES SOC
--------------------------------------------------
{obs}

[4] EVIDENCIAS Y ENLACES
--------------------------------------------------
- VirusTotal: {vt_l}
- AbuseIPDB:  {ab_l}
--------------------------------------------------"""

def build_ticket_text_hash(ioc, sha, name, type, size, sig, vt_m, vt_t, vt_s, vt_l, verd, obs):
    firmado = "SÍ" if sig["is_signed"] else "NO"
    validez = "VÁLIDA" if sig["is_valid"] else "N/A"
    return f"""--- INVESTIGACIÓN INTERNA (HASH) ---
IOC (Hash):  {ioc}
ESTADO:      {verd.upper()}

[1] IDENTIFICACIÓN DEL ARCHIVO
--------------------------------------------------
Nombre:      {name}
Tipo:        {type}
SHA256:      {sha}

[2] REPUTACIÓN (VirusTotal)
--------------------------------------------------
Detecciones: {vt_m}/{vt_t} motores maliciosos

[3] FIRMA DIGITAL
--------------------------------------------------
Firmado:     {firmado}
Estado:      {validez}

[4] EVIDENCIAS
--------------------------------------------------
- VirusTotal: {vt_l}
--------------------------------------------------"""

def build_ticket_text_url(ioc, final, vt_m, vt_t, vt_s, cats, vt_l, verd, obs):
    return f"""--- INVESTIGACIÓN INTERNA (URL) ---
URL:         {ioc}
ESTADO:      {verd.upper()}

[1] DETALLES
--------------------------------------------------
URL Final:   {final}
Categoría:   {", ".join(f"{k}: {v}" for k, v in cats.items()) if cats else "N/A"}

[2] REPUTACIÓN
--------------------------------------------------
Detecciones: {vt_m}/{vt_t} motores maliciosos

[3] EVIDENCIAS
--------------------------------------------------
- VirusTotal: {vt_l}
--------------------------------------------------"""

# =========================
# FORMATO DE ANÁLISIS DE IOC (Compacto)
# =========================
def build_short_analysis(ioc, type, verd, vt_l, ab_l=None):
    text = f"--- ANÁLISIS DE IOC ---\n"
    text += f"IOC:      {ioc}\n"
    text += f"TIPO:     {type}\n"
    text += f"ESTADO:    {verd.upper()}\n"
    text += f"--------------------------------------------------\n"
    text += f"EVIDENCIAS:\n"
    text += f"- VirusTotal: {vt_l}\n"
    if ab_l:
        text += f"- AbuseIPDB:  {ab_l}\n"
    text += f"--------------------------------------------------"
    return text

def render_copy_box(title: str, text: str, unique_key: str, height: int = 250):
    st.subheader(title)
    escaped_text = html.escape(text)
    component_html = f"""
    <div style="margin-bottom: 20px;">
        <textarea id="cb_{unique_key}" readonly style="width: 100%; height: {height}px; padding: 10px; background: #0e1117; color: #fafafa; font-family: monospace; font-size: 13px; border-radius: 5px; border: 1px solid #4a4a4a;">{escaped_text}</textarea>
        <button onclick="copy_{unique_key}()" style="margin-top: 8px; background: #ff4b4b; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold;">Copiar {title}</button>
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
# INTERFAZ DE ENTRADA
# =========================
col_in, col_btn = st.columns([6, 1])
with col_in:
    raw_iocs = st.text_area("Introduce IOCs", key="ioc_input", height=120)
with col_btn:
    st.write(" ")
    st.write(" ")
    st.button("Limpiar", on_click=clear_text)

if st.button("Analizar IOC(s)", type="primary", use_container_width=True):
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
                c_n = country_name_from_code(v_attr.get("country"))
                vt_l, ab_l = f"https://www.virustotal.com/gui/ip-address/{ioc}", f"https://www.abuseipdb.com/check/{ioc}"
                
                summary_rows.append({
                    "Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "IP", "País": c_n, "Firmado": "N/A", "Veredicto": verd, 
                    "VT Malicious": vt_m, "Abuse Score": f"{ab_s}%", "VirusTotal": vt_l, "AbuseIPDB": ab_l
                })
                
                host = "N/A"
                try: host = socket.gethostbyaddr(ioc)[0]
                except: pass
                
                internal = build_ticket_text_ip(ioc, vt_m, vt_t, vt_s, v_attr.get("reputation", 0), ab_s, a_data.get("totalReports", 0), c_n, v_attr.get("country", "N/A"), v_attr.get("as_owner", "N/A"), v_attr.get("asn", "N/A"), v_attr.get("network", "N/A"), host, vt_l, ab_l, verd, "IP analizada.")
                short = build_short_analysis(ioc, "IP Address", verd, vt_l, ab_l)
                ticket_data_list.append((ioc, internal, short))

            elif t == "Hash":
                sig_info = v_attr.get("signature_info", {})
                sig = {"is_signed": bool(sig_info), "is_valid": sig_info.get("verified") == "Valid"}
                verd = get_verdict(vt_m, vt_s)
                firm_txt = "✅ Válida" if sig["is_valid"] else ("⚠️ No válida" if sig["is_signed"] else "❌ No")
                vt_l = f"https://www.virustotal.com/gui/file/{ioc}"
                
                summary_rows.append({
                    "Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "Hash", "País": "N/A", "Firmado": firm_txt, "Veredicto": verd, 
                    "VT Malicious": vt_m, "Abuse Score": "N/A", "VirusTotal": vt_l, "AbuseIPDB": None
                })
                
                internal = build_ticket_text_hash(ioc, v_attr.get("sha256", ioc), v_attr.get("meaningful_name", "N/A"), v_attr.get("type_description", "N/A"), v_attr.get("size", 0), sig, vt_m, vt_t, vt_s, vt_l, verd, "Hash analizado.")
                short = build_short_analysis(ioc, "Archivo (Hash)", verd, vt_l)
                ticket_data_list.append((ioc, internal, short))

            elif t == "URL":
                verd = get_verdict(vt_m, vt_s)
                vt_l = f"https://www.virustotal.com/gui/url/{vt_url_id(ioc)}"
                summary_rows.append({
                    "Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "URL", "País": "N/A", "Firmado": "N/A", "Veredicto": verd, 
                    "VT Malicious": vt_m, "Abuse Score": "N/A", "VirusTotal": vt_l, "AbuseIPDB": None
                })
                
                internal = build_ticket_text_url(ioc, v_attr.get("url", ioc), vt_m, vt_t, vt_s, v_attr.get("categories", {}), vt_l, verd, "URL analizada.")
                short = build_short_analysis(ioc, "URL", verd, vt_l)
                ticket_data_list.append((ioc, internal, short))

    # VISUALIZACIÓN DE TABLA
    st.header("Resumen global")
    df = pd.DataFrame(summary_rows)
    cols_order = ["Estado", "IOC", "Tipo", "País", "Firmado", "Veredicto", "VT Malicious", "Abuse Score", "VirusTotal", "AbuseIPDB"]
    st.dataframe(df[cols_order], use_container_width=True, hide_index=True, column_config={
        "VirusTotal": st.column_config.LinkColumn("VirusTotal", display_text="Abrir enlace"),
        "AbuseIPDB": st.column_config.LinkColumn("AbuseIPDB", display_text="Abrir enlace"),
    })

    st.markdown("---")
    st.header("Sección de Tickets")
    
    for ioc_val, internal_txt, short_txt in ticket_data_list:
        st.markdown(f"### IOC: `{ioc_val}`")
        col1, col2 = st.columns(2)
        with col1:
            render_copy_box("Investigación Interna", internal_txt, f"int_{escape_key(ioc_val)}")
        with col2:
            render_copy_box("Análisis de IOC", short_txt, f"short_{escape_key(ioc_val)}")
        st.markdown("---")
