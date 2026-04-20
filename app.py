import base64
import html
import ipaddress
import re
import socket
import requests
import pandas as pd
import pycountry
import streamlit as st
import streamlit.components.v1 as components
from urllib.parse import urlparse

# Intento de importación de WHOIS
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

st.set_page_config(page_title="SOC IOC Checker v3.5", page_icon="🛡️", layout="wide")

st.title("🛡️ SOC IOC Checker")
st.caption("Análisis de IOC VirusTotal & AbuseIP")

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

def detect_ioc_type(value: str) -> str:
    value = value.strip()
    if is_ip(value): return "IP"
    if is_hash(value): return "Hash"
    if "." in value and not is_ip(value): return "URL"
    return "Desconocido"

def get_whois_info(target):
    if not WHOIS_AVAILABLE: return "WHOIS no disponible.", "N/A"
    try:
        if not is_ip(target):
            target = urlparse(target if "://" in target else "https://"+target).netloc
        w = whois.whois(target)
        info = []
        c_code = w.country if w.country else "N/A"
        if w.registrar: info.append(f"Registrar: {w.registrar}")
        if w.org: info.append(f"Organización: {w.org}")
        return "\n".join(info) if info else "WHOIS: Sin detalles públicos.", c_code
    except: return "WHOIS: No disponible.", "N/A"

def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def get_verdict(vt_m=0, ab_s=0, found_in_vt=True):
    if not found_in_vt and ab_s == 0: return "No encontrado"
    if ab_s >= 80 or vt_m >= 5: return "Malicioso"
    if ab_s >= 25 or vt_m >= 1: return "Sospechoso"
    return "Bajo riesgo"

def get_status_icon(verdict: str) -> str:
    icons = {
        "Malicioso": "🔴", 
        "Sospechoso": "🟠", 
        "Bajo riesgo": "🟢", 
        "No encontrado": "⚪", 
        "Error API": "❌"
    }
    return icons.get(verdict, "❓")

# =========================
# CONSTRUCCIÓN DE REPORTES
# =========================
def build_context_block(ioc_type, vt_m, vt_t, details, found_vt):
    text = f"REPUTACIÓN Y CONTEXTO\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━-\n"
    if not found_vt:
        text += f"● VirusTotal:       IOC NO ENCONTRADO EN BASE DE DATOS\n"
    else:
        text += f"● VirusTotal:       {vt_m}/{vt_t} detecciones\n"
    
    if "ab_s" in details: text += f"● AbuseIPDB Score:  {details['ab_s']}%\n"
    
    if ioc_type == "IP" or "Resolved_IP" in details:
        if "Resolved_IP" in details: text += f"● IP Resuelta:      {details['Resolved_IP']}\n"
        text += f"● Uso detectado:    {details.get('UsageType', 'N/A')}\n"
        text += f"● Proveedor (ISP):  {details.get('ISP', 'N/A')}\n"
        text += f"● País:             {details.get('CountryName', 'N/A')}\n"
        text += f"● Hostname:         {details.get('Hostname', 'N/A')}\n"
    elif ioc_type == "Hash":
        text += f"● Tipo Archivo:     {details.get('FileType', 'N/A')}\n"
        text += f"● Nombre visto:     {details.get('FileName', 'N/A')}\n"
        text += f"● Firma Digital:    {details.get('Firmado', 'N/A')}\n"
    elif ioc_type == "URL":
        text += f"● Categoría:        {details.get('Category', 'N/A')}\n"
    return text

def build_internal_block(ioc, ioc_type, verd, vt_m, vt_t, vt_l, details, whois_text, found_vt):
    icon = get_status_icon(verd)
    text += f"   ANALISIS INTERNO SOC - {verd.upper()}\n"
    text += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    text += f"● IOC ANALIZADO: {ioc}\n"
    text += f"● TIPO:          {ioc_type}\n\n"
    
    text += build_context_block(ioc_type, vt_m, vt_t, details, found_vt)
    
    if whois_text:
        text += f"\nWHOIS / REGISTRO\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━n{whois_text}\n"
        
    text += f"\n[ ENLACES ]\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━n- VT: {vt_l}\n"
    if 'ab_l' in details: text += f"- Abuse: {details['ab_l']}\n"
    text += "\n" + "═"*60 + "\n\n"
    return text

def build_analysis_block(ioc, ioc_type, verd, vt_m, vt_t, vt_l, details, found_vt):
    icon = get_status_icon(verd)
    text = f"ANÁLISIS IOC - {ioc}\n"
    text += f━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━n"
    text += f"RESULTADO: {verd.upper()}\n\n"
    text += build_context_block(ioc_type, vt_m, vt_t, details, found_vt)
    text += f"\nENLACES\n--------------------------------------------------\n- VT: {vt_l}\n"
    if 'ab_l' in details: text += f"- Abuse: {details['ab_l']}\n"
    text += "--------------------------------------------------\n\n"
    return text

def render_copy_box(title: str, text: str, unique_key: str):
    st.subheader(title)
    escaped_text = html.escape(text)
    comp_html = f"""
    <textarea id="{unique_key}" readonly style="width: 100%; height: 400px; padding: 15px; background: #0b0e14; color: #00ff41; font-family: monospace; border-radius: 8px; border: 1px solid #2d333b;">{escaped_text}</textarea>
    <button onclick="navigator.clipboard.writeText(document.getElementById('{unique_key}').value)" style="margin-top: 10px; background: #238636; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold;">Copiar {title}</button>
    """
    components.html(comp_html, height=480)

# =========================
# LÓGICA PRINCIPAL
# =========================
if "ioc_input" not in st.session_state: st.session_state["ioc_input"] = ""
def clear_text(): st.session_state["ioc_input"] = ""

c_in, c_cl = st.columns([5, 1])
with c_in: raw_iocs = st.text_area("IOCs a analizar", key="ioc_input", height=100)
with c_cl: 
    st.write(" ")
    st.write(" ")
    st.button("Limpiar", on_click=clear_text, use_container_width=True)

if st.button("Iniciar Análisis", type="primary", use_container_width=True):
    input_list = list(dict.fromkeys([x.strip() for x in raw_iocs.splitlines() if x.strip()]))
    if not input_list: st.stop()

    list_ips, list_hashes, list_urls = [], [], []
    full_internal, full_analysis = "" , ""

    with st.spinner("Analizando..."):
        for ioc in input_list:
            t = detect_ioc_type(ioc)
            if t == "Desconocido": continue
            
            vt_id = vt_url_id(ioc) if t == "URL" else ioc
            v_res = requests.get(f"https://www.virustotal.com/api/v3/{'ip_addresses' if t=='IP' else 'files' if t=='Hash' else 'urls'}/{vt_id}", headers=VT_HEADERS)
            
            found_vt = True
            if v_res.status_code == 404:
                found_vt = False
                v_attr = {}
                vt_m, vt_t = 0, 0
            elif v_res.status_code != 200:
                found_vt = False
                v_attr = {}
                vt_m, vt_t = 0, 0
                verd = "Error API"
            else:
                v_attr = v_res.json().get("data", {}).get("attributes", {})
                vt_m = v_attr.get("last_analysis_stats", {}).get("malicious", 0)
                vt_t = sum(v_attr.get("last_analysis_stats", {}).values())

            vt_l = f"https://www.virustotal.com/gui/{'ip-address' if t=='IP' else 'file' if t=='Hash' else 'url'}/{vt_id}"
            details, whois_info = {}, ""

            if t == "IP":
                a_res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=ABUSE_HEADERS, params={"ipAddress": ioc})
                a_data = a_res.json().get("data", {}) if a_res.status_code == 200 else {}
                ab_s = a_data.get("abuseConfidenceScore", 0)
                pais = get_full_country_name(a_data.get("countryCode", "N/A"))
                isp = a_data.get("isp", "N/A")
                verd = get_verdict(vt_m, ab_s, found_vt)
                ab_l = f"https://www.abuseipdb.com/check/{ioc}"
                details.update({"ab_s": ab_s, "ab_l": ab_l, "ISP": isp, "CountryName": pais, "UsageType": a_data.get("usageType", "N/A"), "Hostname": ", ".join(a_data.get("hostnames", [])) or "N/A"})
                whois_info, _ = get_whois_info(ioc)
                list_ips.append({"Estado": get_status_icon(verd), "IP": ioc, "País": pais, "ISP": isp, "Abuse": f"{ab_s}%", "VT": f"{vt_m}/{vt_t}" if found_vt else "No encontrado", "VirusTotal": vt_l, "AbuseIPDB": ab_l})

            elif t == "Hash":
                sig = v_attr.get("signature_info", {})
                firm = "Válida" if sig.get("verified") == "Valid" else ("No válida" if sig else "No")
                if v_res.status_code == 404: verd = "No encontrado"
                elif v_res.status_code != 200: verd = "Error API"
                else: verd = get_verdict(vt_m, 0, found_vt)
                
                details.update({"FileType": v_attr.get("type_description", "N/A"), "FileName": v_attr.get("meaningful_name", "N/A"), "Firmado": firm if found_vt else "N/A"})
                list_hashes.append({"Estado": get_status_icon(verd), "Hash": ioc, "Nombre": details['FileName'], "Firmado": details['Firmado'], "VT": f"{vt_m}/{vt_t}" if found_vt else "No encontrado", "VirusTotal": vt_l})

            elif t == "URL":
                ab_s, ab_l = 0, None
                try:
                    domain = urlparse(ioc if "://" in ioc else "http://"+ioc).netloc
                    rip = socket.gethostbyname(domain)
                    a_res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=ABUSE_HEADERS, params={"ipAddress": rip})
                    a_data = a_res.json().get("data", {}) if a_res.status_code == 200 else {}
                    ab_s = a_data.get("abuseConfidenceScore", 0)
                    ab_l = f"https://www.abuseipdb.com/check/{rip}"
                    details.update({"ab_s": ab_s, "ab_l": ab_l, "Resolved_IP": rip, "ISP": a_data.get("isp", "N/A")})
                except: pass
                
                if not found_vt and ab_s == 0: verd = "No encontrado"
                elif v_res.status_code != 200 and v_res.status_code != 404: verd = "Error API"
                else: verd = get_verdict(vt_m, ab_s, found_vt)
                
                whois_info, p_code = get_whois_info(ioc)
                details.update({"Category": v_attr.get("categories", {}).get("Forcepoint", "N/A"), "CountryName": get_full_country_name(p_code)})
                list_urls.append({"Estado": get_status_icon(verd), "URL/Dominio": ioc, "Categoría": details['Category'], "IP Resuelta": details.get('Resolved_IP', 'N/A'), "VT": f"{vt_m}/{vt_t}" if found_vt else "No encontrado", "VirusTotal": vt_l, "AbuseIPDB": ab_l})

            full_internal += build_internal_block(ioc, t, verd, vt_m, vt_t, vt_l, details, whois_info, found_vt)
            full_analysis += build_analysis_block(ioc, t, verd, vt_m, vt_t, vt_l, details, found_vt)

    # RENDERIZADO DE TABLAS
    st.header("📋 IOC Analizados")
    t_ip, t_hash, t_url = st.tabs([f"🌐 IPs ({len(list_ips)})", f"📄 Archivos ({len(list_hashes)})", f"🔗 URLs/Dominios ({len(list_urls)})"])
    
    link_config = {"VirusTotal": st.column_config.LinkColumn("VirusTotal", display_text="Ver"), "AbuseIPDB": st.column_config.LinkColumn("AbuseIPDB", display_text="Ver")}

    with t_ip: 
        if list_ips: st.dataframe(pd.DataFrame(list_ips), use_container_width=True, hide_index=True, column_config=link_config)
    with t_hash:
        if list_hashes: st.dataframe(pd.DataFrame(list_hashes), use_container_width=True, hide_index=True, column_config=link_config)
    with t_url:
        if list_urls: st.dataframe(pd.DataFrame(list_urls), use_container_width=True, hide_index=True, column_config=link_config)

    st.divider()
    c1, c2 = st.columns(2)
    with c1: render_copy_box("Investigación Interna", full_internal, "int_box")
    with c2: render_copy_box("Análisis de IOC", full_analysis, "ana_box")
