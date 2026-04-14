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
# GENERACIÓN DE TEXTO UNIFICADO
# =========================
def build_combined_ticket(ioc, type, verd, vt_m, vt_t, vt_s, vt_l, details_dict):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ab_l = details_dict.get('ab_l')
    
    # Bloque 1: Investigación Interna
    text = f"--- INVESTIGACIÓN INTERNA ---\n"
    text += f"IOC:         {ioc}\n"
    text += f"TIPO:        {type}\n"
    text += f"ESTADO:      {verd.upper()}\n"
    text += f"FECHA:       {now}\n\n"
    text += f"[1] REPUTACIÓN\n"
    text += f"--------------------------------------------------\n"
    text += f"VirusTotal:    {vt_m}/{vt_t} detecciones maliciosas\n"
    if "ab_s" in details_dict:
        text += f"AbuseIPDB:     {details_dict['ab_s']}% Confidence Score\n"
    
    text += f"\n[2] DETALLES TÉCNICOS\n"
    text += f"--------------------------------------------------\n"
    for k, v in details_dict.items():
        if k not in ['ab_s', 'ab_l']: text += f"{k}: {v}\n"
        
    text += f"\n[3] EVIDENCIAS\n"
    text += f"--------------------------------------------------\n"
    text += f"- VirusTotal: {vt_l}\n"
    if ab_l: text += f"- AbuseIPDB:  {ab_l}\n"
    
    # Separador visual entre bloques
    text += f"\n\n" + "="*50 + "\n\n"
    
    # Bloque 2: Análisis de IOC
    text += f"--- ANÁLISIS DE IOC ---\n"
    text += f"IOC:      {ioc}\n"
    text += f"TIPO:     {type}\n"
    text += f"ESTADO:    {verd.upper()}\n"
    text += f"--------------------------------------------------\n"
    text += f"EVIDENCIAS:\n"
    text += f"- VirusTotal: {vt_l}\n"
    if ab_l: text += f"- AbuseIPDB:  {ab_l}\n"
    text += f"--------------------------------------------------"
    
    return text

def render_copy_box_single(text: str, unique_key: str, height: int = 450):
    escaped_text = html.escape(text)
    component_html = f"""
    <div style="margin-bottom: 30px; margin-top: 10px;">
        <textarea id="cb_{unique_key}" readonly style="width: 100%; height: {height}px; padding: 15px; background: #0e1117; color: #fafafa; font-family: monospace; font-size: 13px; border-radius: 5px; border: 1px solid #4a4a4a;">{escaped_text}</textarea>
        <button onclick="copy_{unique_key}()" style="margin-top: 10px; background: #ff4b4b; color: white; border: none; padding: 10px 25px; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 14px;">Copiar Información Completa</button>
    </div>
    <script>
    function copy_{unique_key}() {{
        var txt = document.getElementById("cb_{unique_key}");
        txt.select();
        navigator.clipboard.writeText(txt.value);
    }}
    </script>
    """
    components.html(component_html, height=height + 100)

# =========================
# INTERFAZ DE ENTRADA
# =========================
col_in, col_btn = st.columns([6, 1])
with col_in:
    raw_iocs = st.text_area("Introduce IOCs", key="ioc_input", height=150)
with col_btn:
    st.write(" ")
    st.write(" ")
    st.button("Limpiar", on_click=clear_text)

if st.button("Analizar IOC(s)", type="primary", use_container_width=True):
    input_list = list(dict.fromkeys([x.strip() for x in raw_iocs.splitlines() if x.strip()]))
    
    if not input_list:
        st.warning("Por favor, introduce al menos un IOC.")
        st.stop()

    summary_rows = []
    final_texts = []

    with st.spinner(f"Analizando {len(input_list)} IOC(s)..."):
        for ioc in input_list:
            t = detect_ioc_type(ioc)
            vt_res = requests.get(f"https://www.virustotal.com/api/v3/{'ip_addresses' if t=='IP' else 'files' if t=='Hash' else 'urls'}/{vt_url_id(ioc) if t=='URL' else ioc}", headers=VT_HEADERS)
            v_attr = safe_json(vt_res).get("data", {}).get("attributes", {})
            
            vt_m, vt_s, vt_t = 0, 0, 0
            if vt_res.status_code == 200:
                stats = v_attr.get("last_analysis_stats", {})
                vt_m, vt_s, vt_t = stats.get("malicious", 0), stats.get("suspicious", 0), total_engines_from_stats(stats)

            details = {}
            vt_l = f"https://www.virustotal.com/gui/{'ip-address' if t=='IP' else 'file' if t=='Hash' else 'url'}/{vt_url_id(ioc) if t=='URL' else ioc}"

            if t == "IP":
                a_res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=ABUSE_HEADERS, params={"ipAddress": ioc})
                a_data = safe_json(a_res).get("data", {})
                ab_s = a_data.get("abuseConfidenceScore", 0)
                ab_l = f"https://www.abuseipdb.com/check/{ioc}"
                verd = get_verdict(vt_m, vt_s, ab_s)
                c_n = country_name_from_code(v_attr.get("country"))
                details = {"ab_s": ab_s, "País": c_n, "ASN": v_attr.get("asn", "N/A"), "Proveedor": v_attr.get("as_owner", "N/A"), "ab_l": ab_l}
                summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "IP", "País": c_n, "Firmado": "N/A", "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": f"{ab_s}%", "VirusTotal": vt_l, "AbuseIPDB": ab_l})

            elif t == "Hash":
                sig_info = v_attr.get("signature_info", {})
                firm_txt = "✅ Válida" if sig_info.get("verified") == "Valid" else ("⚠️ No válida" if sig_info else "❌ No")
                verd = get_verdict(vt_m, vt_s)
                details = {"Nombre": v_attr.get("meaningful_name", "N/A"), "Tipo": v_attr.get("type_description", "N/A"), "SHA256": v_attr.get("sha256", "N/A")}
                summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "Hash", "País": "N/A", "Firmado": firm_txt, "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": "N/A", "VirusTotal": vt_l, "AbuseIPDB": None})

            elif t == "URL":
                verd = get_verdict(vt_m, vt_s)
                details = {"URL Final": v_attr.get("url", ioc), "Categorías": str(v_attr.get("categories", "N/A"))}
                summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "URL", "País": "N/A", "Firmado": "N/A", "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": "N/A", "VirusTotal": vt_l, "AbuseIPDB": None})
            
            if t != "Desconocido":
                final_texts.append(build_combined_ticket(ioc, t, verd, vt_m, vt_t, vt_s, vt_l, details))

    # RESUMEN GLOBAL
    st.header("Resumen global")
    if summary_rows:
        df = pd.DataFrame(summary_rows)
        cols_order = ["Estado", "IOC", "Tipo", "País", "Firmado", "Veredicto", "VT Malicious", "Abuse Score", "VirusTotal", "AbuseIPDB"]
        st.dataframe(df[cols_order], use_container_width=True, hide_index=True, column_config={
            "VirusTotal": st.column_config.LinkColumn("VirusTotal", display_text="Enlace VT"),
            "AbuseIPDB": st.column_config.LinkColumn("AbuseIPDB", display_text="Enlace ABUSEIP")
        })

    st.markdown("---")
    st.header("Texto para tickets")
    
    # Renderizar cada bloque de texto unificado
    for idx, txt in enumerate(final_texts):
        render_copy_box_single(txt, f"box_{idx}")
