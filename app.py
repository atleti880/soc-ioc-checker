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

# Intentar importar whois de forma segura
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# =========================
# CONFIGURACIÓN Y APIS
# =========================
VT_API = st.secrets["VT_API"]
ABUSE_API = st.secrets["ABUSE_API"]

VT_HEADERS = {"x-apikey": VT_API}
ABUSE_HEADERS = {"Key": ABUSE_API, "Accept": "application/json"}

st.set_page_config(page_title="SOC IOC Checker v2.0", page_icon="🛡️", layout="wide")

st.title("🛡️ SOC IOC Checker - Report Generator")
st.caption("Análisis avanzado de amenazas con reporte automatizado para Tickets")

# =========================
# LÓGICA DE LIMPIEZA
# =========================
if "ioc_input" not in st.session_state:
    st.session_state["ioc_input"] = ""

def clear_text():
    st.session_state["ioc_input"] = ""

# =========================
# UTILIDADES TÉCNICAS
# =========================
def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception: return False

def is_hash(value: str) -> bool:
    return re.fullmatch(r"([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", value.strip()) is not None

def normalize_url(value: str) -> str:
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    return value

def detect_ioc_type(value: str) -> str:
    value = value.strip()
    if is_ip(value): return "IP"
    if is_hash(value): return "Hash"
    if "." in value and not is_ip(value): return "URL"
    return "Desconocido"

def get_whois_info(target):
    if not WHOIS_AVAILABLE:
        return "⚠️ Error: Librería 'python-whois' no instalada."
    try:
        if not is_ip(target):
            target = urlparse(normalize_url(target)).netloc
        w = whois.whois(target)
        info = []
        if w.registrar: info.append(f"Registrar: {w.registrar}")
        if w.creation_date:
            date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            info.append(f"Creation Date: {date}")
        if w.country: info.append(f"Registration Country: {w.country}")
        if w.org: info.append(f"Organization: {w.org}")
        return "\n".join(info) if info else "WHOIS: No public details found."
    except Exception as e:
        return f"WHOIS: Data not available ({str(e)})"

def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def get_verdict(vt_m=0, vt_s=0, ab_s=0):
    if ab_s >= 80 or vt_m >= 5: return "Malicioso"
    if ab_s >= 25 or vt_m >= 1 or vt_s >= 2: return "Sospechoso"
    return "Bajo riesgo"

def get_status_icon(verdict: str) -> str:
    icons = {"Malicioso": "🔴", "Sospechoso": "🟠", "Bajo riesgo": "🟢"}
    return icons.get(verdict, "⚪")

# =========================
# PLANTILLAS DE COMUNICACIÓN (MEJORADAS)
# =========================
def get_recommendations(verdict, ioc_type):
    if verdict == "Malicioso":
        rec = "- 🛑 BLOQUEO INMEDIATO: Añadir a lista negra en Firewall/Proxy/EDR.\n"
        rec += "- 🔍 INVESTIGAR: Revisar logs en busca de conexiones previas desde este IOC.\n"
        rec += "- ⚠️ ALERTA: Notificar a los administradores de sistemas sobre posible compromiso."
    elif verdict == "Sospechoso":
        rec = "- 🛡️ MONITORIZACIÓN: Mantener vigilancia activa sobre este activo.\n"
        rec += "- 🕵️ ANÁLISIS: Realizar búsqueda proactiva (Threat Hunting) en el SIEM.\n"
        rec += "- 📝 DOCUMENTAR: Registrar en el ticket para seguimiento futuro."
    else:
        rec = "- ✅ NINGUNA: No se requiere acción inmediata.\n"
        rec += "- 📁 ARCHIVAR: Cerrar como 'Falso Positivo' o 'Lícito'."
    return rec

def build_internal_block(ioc, ioc_type, verd, vt_m, vt_t, vt_l, details, whois_text):
    icon = get_status_icon(verd)
    text = f"╔════════════════════════════════════════════════════════════╗\n"
    text += f"   INFORME DE INVESTIGACIÓN INTERNA - {icon} {verd.upper()}\n"
    text += f"╚════════════════════════════════════════════════════════════╝\n\n"
    text += f"● IOC ANALIZADO: {ioc}\n"
    text += f"● TIPO DE ACTIVO: {ioc_type}\n"
    text += f"● ESTADO FINAL:  {verd.upper()}\n\n"
    
    text += f"📊 [ REPUTACIÓN Y SCORE ]\n"
    text += f"--------------------------------------------------\n"
    text += f"VirusTotal:    {vt_m}/{vt_t} motores detectan malware\n"
    if 'ab_s' in details:
        text += f"AbuseIPDB:     {details['ab_s']}% Confidence Score\n"
    if 'Hostname' in details:
        text += f"Hostname:      {details['Hostname']}\n"
    
    if whois_text:
        text += f"\n📋 [ INFORMACIÓN REGISTRAR / WHOIS ]\n"
        text += f"--------------------------------------------------\n"
        text += f"{whois_text}\n"
        
    text += f"\n⚡ [ ACCIONES RECOMENDADAS ]\n"
    text += f"--------------------------------------------------\n"
    text += get_recommendations(verd, ioc_type) + "\n"

    text += f"\n🔗 [ EVIDENCIAS TÉCNICAS ]\n"
    text += f"--------------------------------------------------\n"
    text += f"- VirusTotal: {vt_l}\n"
    if 'ab_l' in details: text += f"- AbuseIPDB:  {details['ab_l']}\n"
    
    text += "\n" + "═"*60 + "\n\n"
    return text

def build_analysis_block(ioc, verd, vt_l, ab_l=None):
    icon = get_status_icon(verd)
    text = f"📢 ANÁLISIS DE IOC - {ioc}\n"
    text += f"--------------------------------------------------\n"
    text += f"RESULTADO: {icon} {verd.upper()}\n"
    text += f"DETALLES:  Se ha verificado la reputación en fuentes de inteligencia de amenazas.\n"
    text += f"EVIDENCIA PRINCIPAL: {vt_l}\n"
    if ab_l: text += f"EVIDENCIA ADICIONAL: {ab_l}\n"
    text += "--------------------------------------------------\n\n"
    return text

def render_copy_box(title: str, text: str, unique_key: str):
    st.subheader(title)
    escaped_text = html.escape(text)
    comp_html = f"""
    <div style="margin-bottom: 25px;">
        <textarea id="{unique_key}" readonly style="width: 100%; height: 450px; padding: 15px; background: #0b0e14; color: #00ff41; font-family: 'Courier New', Courier, monospace; font-size: 13px; border: 1px solid #2d333b; border-radius: 8px; line-height: 1.4; resize: none;">{escaped_text}</textarea>
        <button onclick="copy_{unique_key}()" style="margin-top: 10px; background: #238636; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; font-family: sans-serif; transition: 0.3s;">📋 Copiar para el Ticket</button>
    </div>
    <script>
    function copy_{unique_key}() {{
        var t = document.getElementById("{unique_key}");
        t.select();
        navigator.clipboard.writeText(t.value);
    }}
    </script>
    """
    components.html(comp_html, height=550)

# =========================
# INTERFAZ PRINCIPAL
# =========================
col1, col2 = st.columns([5, 1])
with col1:
    raw_iocs = st.text_area("Lista de IOCs (IPs, URLs o Hashes)", key="ioc_input", height=100, placeholder="8.8.8.8\nhttps://google.com\n5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
with col2:
    st.write(" ")
    st.write(" ")
    st.button("🧹 Limpiar Todo", on_click=clear_text, use_container_width=True)

if st.button("🚀 Iniciar Análisis", type="primary", use_container_width=True):
    input_list = list(dict.fromkeys([x.strip() for x in raw_iocs.splitlines() if x.strip()]))
    if not input_list: 
        st.warning("⚠️ No has introducido ningún IOC.")
        st.stop()

    summary_rows = []
    full_internal = ""
    full_analysis = ""

    with st.status("Ejecutando consultas de inteligencia...", expanded=True) as status:
        for ioc in input_list:
            st.write(f"Analizando: `{ioc}`")
            t = detect_ioc_type(ioc)
            if t == "Desconocido": continue
            
            # VirusTotal
            vt_id = vt_url_id(ioc) if t == "URL" else ioc
            vt_res = requests.get(f"https://www.virustotal.com/api/v3/{'ip_addresses' if t=='IP' else 'files' if t=='Hash' else 'urls'}/{vt_id}", headers=VT_HEADERS)
            v_attr = vt_res.json().get("data", {}).get("attributes", {}) if vt_res.status_code == 200 else {}
            
            stats = v_attr.get("last_analysis_stats", {})
            vt_m, vt_t = stats.get("malicious", 0), sum(stats.values())
            vt_l = f"https://www.virustotal.com/gui/{'ip-address' if t=='IP' else 'file' if t=='Hash' else 'url'}/{vt_id}"
            
            details = {}
            whois_info = ""

            if t == "IP":
                a_res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=ABUSE_HEADERS, params={"ipAddress": ioc})
                a_data = a_res.json().get("data", {}) if a_res.status_code == 200 else {}
                ab_s = a_data.get("abuseConfidenceScore", 0)
                ab_h = a_data.get("domainName", "N/A")
                ab_l = f"https://www.abuseipdb.com/check/{ioc}"
                
                verd = get_verdict(vt_m, 0, ab_s)
                details = {"ab_s": ab_s, "ab_l": ab_l, "Hostname": ab_h}
                whois_info = get_whois_info(ioc)
            else:
                verd = get_verdict(vt_m, 0, 0)
                if t == "URL": whois_info = get_whois_info(ioc)
                details = {}

            # Acumular
            summary_rows.append({
                "Estado": get_status_icon(verd), 
                "IOC": ioc, 
                "Tipo": t, 
                "Veredicto": verd, 
                "VT": f"{vt_m}/{vt_t}", 
                "Abuse": f"{details.get('ab_s', 'N/A')}%" if t == "IP" else "N/A"
            })
            full_internal += build_internal_block(ioc, t, verd, vt_m, vt_t, vt_l, details, whois_info)
            full_analysis += build_analysis_block(ioc, verd, vt_l, details.get('ab_l'))
        
        status.update(label="Análisis completado", state="complete", expanded=False)

    # UI RESULTADOS
    st.header("📋 Resumen de la Investigación")
    st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)

    st.divider()
    
    # Cuadros de Comunicación
    c1, c2 = st.columns(2)
    with c1: 
        render_copy_box("📁 Reporte de Investigación (SOC Interno)", full_internal, "int_box")
    with c2: 
        render_copy_box("✉️ Comunicación de Análisis (Resumido)", full_analysis, "ana_box")
