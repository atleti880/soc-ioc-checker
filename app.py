import base64
import html
import ipaddress
import re
import requests
import pandas as pd
import pycountry
import streamlit as st
import streamlit.components.v1 as components
from urllib.parse import urlparse

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

st.set_page_config(page_title="SOC IOC Checker v2.6", page_icon="🛡️", layout="wide")

st.title("🛡️ SOC IOC Checker - Ultra")
st.caption("Análisis de Inteligencia de Amenazas | VT • AbuseIPDB • Network Context")

# =========================
# UTILIDADES
# =========================
def get_full_country_name(code):
    try:
        if not code or code == "N/A": return "N/A"
        country = pycountry.countries.get(alpha_2=code.upper())
        return country.name if country else code
    except: return code

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except: return False

def is_hash(value: str) -> bool:
    return re.fullmatch(r"([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", value.strip()) is not None

def normalize_url(value: str) -> str:
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    return value

def detect_ioc_type(value: str) -> str:
    value = value.strip()
    if is_ip(value): return "IP"
    if is_hash(value): return "Hash"
    if "." in value and not is_ip(value): return "URL"
    return "Desconocido"

def get_whois_info(target):
    if not WHOIS_AVAILABLE: return "⚠️ WHOIS no disponible.", "N/A"
    try:
        if not is_ip(target):
            target = urlparse(normalize_url(target)).netloc
        w = whois.whois(target)
        info = []
        c_code = w.country if w.country else "N/A"
        if w.registrar: info.append(f"Registrar: {w.registrar}")
        if w.org: info.append(f"Organización: {w.org}")
        if w.creation_date:
            d = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            info.append(f"Fecha Creación: {d.strftime('%Y-%m-%d') if d else 'N/A'}")
        return "\n".join(info) if info else "WHOIS: Sin datos públicos.", c_code
    except: return "WHOIS: Error en consulta.", "N/A"

def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def get_verdict(vt_m=0, ab_s=0):
    if ab_s >= 80 or vt_m >= 5: return "Malicioso"
    if ab_s >= 20 or vt_m >= 1: return "Sospechoso"
    return "Bajo riesgo"

def get_status_icon(verdict: str) -> str:
    icons = {"Malicioso": "🔴", "Sospechoso": "🟠", "Bajo riesgo": "🟢"}
    return icons.get(verdict, "⚪")

# =========================
# CONSTRUCCIÓN DE REPORTES
# =========================
def build_internal_block(ioc, ioc_type, verd, vt_m, vt_t, vt_l, details, whois_text):
    icon = get_status_icon(verd)
    text = f"╔════════════════════════════════════════════════════════════╗\n"
    text += f"   INVESTIGACIÓN TÉCNICA SOC - {icon} {verd.upper()}\n"
    text += f"╚════════════════════════════════════════════════════════════╝\n\n"
    text += f"■ ACTIVO ANALIZADO : {ioc}\n"
    text += f"■ TIPO DE IOC      : {ioc_type}\n"
    text += f"■ VERDICTO FINAL   : {verd.upper()}\n\n"
    
    text += f"📊 [ REPUTACIÓN Y ANÁLISIS ]\n"
    text += f"--------------------------------------------------\n"
    text += f"● VirusTotal detection:  [{vt_m}/{vt_t}]\n"
    
    if ioc_type == "IP":
        text += f"● AbuseIPDB Score:      [{details.get('ab_s', 0)}%]\n"
        text += f"● Proveedor (ISP):      {details.get('ISP', 'N/A')}\n"
        text += f"● Red (ASN):            {details.get('ASN', 'N/A')}\n"
        text += f"● Ubicación:            {details.get('CountryName', 'N/A')}\n"
        if details.get('Hostname') and details.get('Hostname') != "N/A":
            text += f"● Hostname:             {details.get('Hostname')}\n"
    
    if whois_text and ioc_type != "Hash":
        text += f"\n📋 [ DETALLES DE REGISTRO / WHOIS ]\n"
        text += f"--------------------------------------------------\n"
        text += f"{whois_text}\n"
        
    text += f"\n🔗 [ EVIDENCIAS TÉCNICAS ]\n"
    text += f"--------------------------------------------------\n"
    text += f"URL VT: {vt_l}\n"
    if 'ab_l' in details: text += f"URL AB: {details['ab_l']}\n"
    text += "\n" + "═"*60 + "\n\n"
    return text

def build_analysis_block(ioc, verd, vt_l, ab_l=None):
    icon = get_status_icon(verd)
    text = f"📢 ANÁLISIS DE SEGURIDAD - {ioc}\n"
    text += f"--------------------------------------------------\n"
    text += f"ESTADO: {icon} {verd.upper()}\n"
    text += f"Se ha verificado la reputación en motores de búsqueda de amenazas.\n"
    text += f"EVIDENCIA PRINCIPAL: {vt_l}\n"
    if ab_l: text += f"EVIDENCIA ADICIONAL: {ab_l}\n"
    text += "--------------------------------------------------\n\n"
    return text

def render_copy_box(title: str, text: str, unique_key: str):
    st.subheader(title)
    escaped_text = html.escape(text)
    comp_html = f"""
    <div style="margin-bottom: 25px;">
        <textarea id="{unique_key}" readonly style="width: 100%; height: 450px; padding: 15px; background: #0b0e14; color: #00ff41; font-family: 'Courier New', monospace; font-size: 13px; border: 1px solid #2d333b; border-radius: 8px; line-height: 1.5;">{escaped_text}</textarea>
        <button onclick="copy_{unique_key}()" style="margin-top: 12px; background: #238636; color: white; border: none; padding: 10px 24px; border-radius: 6px; cursor: pointer; font-weight: bold; font-family: sans-serif;">📋 Copiar Reporte</button>
    </div>
    <script>
    function copy_{unique_key}() {{
        var t = document.getElementById("{unique_key}"); t.select(); navigator.clipboard.writeText(t.value);
    }}
    </script>
    """
    components.html(comp_html, height=560)

# =========================
# LÓGICA PRINCIPAL Streamlit
# =========================
if "ioc_input" not in st.session_state: st.session_state["ioc_input"] = ""
def clear_text(): st.session_state["ioc_input"] = ""

c_input, c_btn = st.columns([5, 1])
with c_input:
    raw_iocs = st.text_area("Entrada de IOCs (IP, Hash, URL)", key="ioc_input", height=100)
with c_btn:
    st.write(" ")
    st.write(" ")
    st.button("🧹 Limpiar", on_click=clear_text, use_container_width=True)

if st.button("🚀 ANALIZAR AHORA", type="primary", use_container_width=True):
    input_list = list(dict.fromkeys([x.strip() for x in raw_iocs.splitlines() if x.strip()]))
    if not input_list: st.stop()

    summary_rows = []
    full_internal = ""
    full_analysis = ""

    with st.spinner("Consultando APIs de seguridad..."):
        for ioc in input_list:
            t = detect_ioc_type(ioc)
            if t == "Desconocido": continue
            
            # 1. VirusTotal
            vt_id = vt_url_id(ioc) if t == "URL" else ioc
            vt_res = requests.get(f"https://www.virustotal.com/api/v3/{'ip_addresses' if t=='IP' else 'files' if t=='Hash' else 'urls'}/{vt_id}", headers=VT_HEADERS)
            v_attr = vt_res.json().get("data", {}).get("attributes", {}) if vt_res.status_code == 200 else {}
            
            stats = v_attr.get("last_analysis_stats", {})
            vt_m, vt_t = stats.get("malicious", 0), sum(stats.values())
            vt_l = f"https://www.virustotal.com/gui/{'ip-address' if t=='IP' else 'file' if t=='Hash' else 'url'}/{vt_id}"
            
            details = {}
            whois_info = ""
            pais_full = "N/A"

            # 2. Detalles específicos por tipo
            if t == "IP":
                a_res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=ABUSE_HEADERS, params={"ipAddress": ioc, "verbose": True})
                a_data = a_res.json().get("data", {}) if a_res.status_code == 200 else {}
                
                ab_s = a_data.get("abuseConfidenceScore", 0)
                pais_full = get_full_country_name(a_data.get("countryCode", "N/A"))
                isp = a_data.get("isp", "N/A")
                asn = f"AS{a_data.get('asn', 'N/A')}"
                
                h_list = a_data.get("hostnames", [])
                h_str = ", ".join(h_list) if h_list else "N/A"
                
                ab_l = f"https://www.abuseipdb.com/check/{ioc}"
                verd = get_verdict(vt_m, ab_s)
                
                details = {"ab_s": ab_s, "ab_l": ab_l, "Hostname": h_str, "CountryName": pais_full, "ISP": isp, "ASN": asn}
                whois_info, _ = get_whois_info(ioc)
                
                summary_rows.append({
                    "Estado": get_status_icon(verd), "IOC": ioc, "Tipo": t, "País": pais_full, 
                    "Veredicto": verd, "VT Malicious": f"{vt_m}/{vt_t}", "Abuse Score": f"{ab_s}%", 
                    "ISP": isp, "VirusTotal": vt_l, "AbuseIPDB": ab_l
                })

            elif t == "Hash":
                sig = v_attr.get("signature_info", {})
                firmado = "✅ Válida" if sig.get("verified") == "Valid" else ("⚠️ Invalida" if sig else "❌ No")
                verd = get_verdict(vt_m, 0)
                summary_rows.append({
                    "Estado": get_status_icon(verd), "IOC": ioc, "Tipo": t, "País": "N/A", 
                    "Veredicto": verd, "VT Malicious": f"{vt_m}/{vt_t}", "Firmado": firmado,
                    "VirusTotal": vt_l, "AbuseIPDB": None
                })

            elif t == "URL":
                verd = get_verdict(vt_m, 0)
                whois_info, p_code = get_whois_info(ioc)
                pais_full = get_full_country_name(p_code)
                summary_rows.append({
                    "Estado": get_status_icon(verd), "IOC": ioc, "Tipo": t, "País": pais_full, 
                    "Veredicto": verd, "VT Malicious": f"{vt_m}/{vt_t}", 
                    "VirusTotal": vt_l, "AbuseIPDB": None
                })

            full_internal += build_internal_block(ioc, t, verd, vt_m, vt_t, vt_l, details, whois_info)
            full_analysis += build_analysis_block(ioc, verd, vt_l, details.get('ab_l'))

    # RENDERIZADO DE TABLA
    st.header("📋 Resultados del Escaneo")
    if summary_rows:
        df = pd.DataFrame(summary_rows)
        st.dataframe(df, use_container_width=True, hide_index=True, column_config={
            "VirusTotal": st.column_config.LinkColumn("VirusTotal", display_text="Abrir VT"),
            "AbuseIPDB": st.column_config.LinkColumn("AbuseIPDB", display_text="Abrir Abuse")
        })

    st.divider()
    
    # RENDERIZADO DE CAJAS
    col_left, col_right = st.columns(2)
    with col_left:
        render_copy_box("📁 Reporte Técnico (Investigación Interna)", full_internal, "internal_txt")
    with col_right:
        render_copy_box("✉️ Comunicación SOC (Resumen)", full_analysis, "analysis_txt")
