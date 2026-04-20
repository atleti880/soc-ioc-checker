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
from collections import Counter

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
    icons = {"Malicioso": "🔴", "Sospechoso": "🟠", "Bajo riesgo": "🟢", "No encontrado": "⚪", "Error API": "❌"}
    return icons.get(verdict, "❓")

# =========================
# CONSTRUCCIÓN DE REPORTES (TEXTO PLANO + RESUMEN)
# =========================
def build_summary_block(ioc_results):
    if not ioc_results: return ""
    v_counts = Counter([res['verd'] for res in ioc_results])
    t_counts = Counter([res['type'] for res in ioc_results])
    
    text = "RESUMEN EJECUTIVO DE IOCs\n========================================\n"
    text += f"Total analizados: {len(ioc_results)}\n\nDISTRIBUCION POR TIPO:\n"
    for t, count in t_counts.items(): text += f"- {t}: {count}\n"
    text += "\nVEREDICTOS:\n"
    for v, count in v_counts.items(): text += f"- {v.upper()}: {count}\n"
    text += "\nENLACES DE ACCESO RAPIDO:\n"
    for res in ioc_results: text += f"- {res['ioc']} ({res['type']}): {res['vt_l']}\n"
    text += "========================================\n\n"
    return text

def build_context_block(ioc_type, vt_m, vt_t, details, found_vt):
    text = "REPUTACION Y CONTEXTO\n----------------------------------------\n"
    text += f"VirusTotal: {'NO ENCONTRADO' if not found_vt else str(vt_m) + '/' + str(vt_t) + ' detecciones'}\n"
    if "ab_s" in details: text += f"AbuseIPDB: Score {details['ab_s']}%\n"
    text += "\nDETALLES TECNICOS\n----------------------------------------\n"
    if ioc_type == "IP" or "Resolved_IP" in details:
        text += f"IP Resuelta: {details.get('Resolved_IP', 'N/A')}\nUso: {details.get('UsageType', 'N/A')}\nISP: {details.get('ISP', 'N/A')}\nPais: {details.get('CountryName', 'N/A')}\nHostname: {details.get('Hostname', 'N/A')}\n"
    elif ioc_type == "Hash":
        text += f"Tipo: {details.get('FileType', 'N/A')}\nNombre: {details.get('FileName', 'N/A')}\nFirma: {details.get('Firmado', 'N/A')}\n"
    elif ioc_type == "URL":
        text += f"Categoria: {details.get('Category', 'N/A')}\n"
    return text

def build_internal_block(ioc, ioc_type, verd, vt_m, vt_t, vt_l, details, whois_text, found_vt):
    text = f"ANALISIS INTERNO SOC - {verd.upper()}\n========================================\n"
    text += f"IOC: {ioc}\nTipo: {ioc_type}\n\n" + build_context_block(ioc_type, vt_m, vt_t, details, found_vt)
    if whois_text and whois_text != "WHOIS no disponible.": text += f"\nINFORMACION WHOIS:\n{whois_text}\n"
    text += f"\nENLACES DE INVESTIGACION\nVT: {vt_l}\n"
    if 'ab_l' in details: text += f"AbuseIPDB: {details['ab_l']}\n"
    text += "========================================\n\n"
    return text

def build_analysis_block(ioc, ioc_type, verd, vt_m, vt_t, vt_l, details, found_vt):
    text = f"REPORTE DE IOC: {ioc}\nVeredicto: {verd.upper()}\n----------------------------------------\n"
    text += build_context_block(ioc_type, vt_m, vt_t, details, found_vt)
    text += f"\nENLACES: {vt_l}"
    if 'ab_l' in details: text += f" | {details['ab_l']}"
    text += "\n\n----------------------------------------\n"
    return text

def render_copy_box(title, text, unique_key):
    st.subheader(title)
    comp_html = f"""<textarea id="{unique_key}" readonly style="width: 100%; height: 400px; padding: 15px; background: #0b0e14; color: #00ff41; font-family: monospace; border-radius: 8px; border: 1px solid #2d333b;">{text}</textarea>
    <button onclick="navigator.clipboard.writeText(document.getElementById('{unique_key}').value)" style="margin-top: 10px; background: #238636; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold;">Copiar {title}</button>"""
    components.html(comp_html, height=480)

# =========================
# LÓGICA PRINCIPAL
# =========================
if "ioc_input" not in st.session_state: st.session_state["ioc_input"] = ""
def clear_text(): st.session_state["ioc_input"] = ""

c_in, c_cl = st.columns([5, 1])
with c_in: raw_iocs = st.text_area("IOCs a analizar", key="ioc_input", height=100)
with c_cl: 
    st.write(" "); st.write(" "); st.button("Limpiar", on_click=clear_text, use_container_width=True)

if st.button("Iniciar Análisis", type="primary", use_container_width=True):
    input_list = list(dict.fromkeys([x.strip() for x in raw_iocs.splitlines() if x.strip()]))
    if not input_list: st.stop()
    ioc_results, full_internal, full_analysis = [], "", ""
    with st.spinner("Analizando..."):
        for ioc in input_list:
            t = detect_ioc_type(ioc)
            if t == "Desconocido": continue
            vt_id = vt_url_id(ioc) if t == "URL" else ioc
            v_res = requests.get(f"https://www.virustotal.com/api/v3/{'ip_addresses' if t=='IP' else 'files' if t=='Hash' else 'urls'}/{vt_id}", headers=VT_HEADERS)
            found_vt = v_res.status_code == 200
            v_attr = v_res.json().get("data", {}).get("attributes", {}) if found_vt else {}
            vt_m = v_attr.get("last_analysis_stats", {}).get("malicious", 0) if found_vt else 0
            vt_t = sum(v_attr.get("last_analysis_stats", {}).values()) if found_vt else 0
            vt_l = f"https://www.virustotal.com/gui/{'ip-address' if t=='IP' else 'file' if t=='Hash' else 'url'}/{vt_id}"
            details, whois_info = {}, ""
            if t == "IP":
                a_res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=ABUSE_HEADERS, params={"ipAddress": ioc})
                a_data = a_res.json().get("data", {}) if a_res.status_code == 200 else {}
                ab_s = a_data.get("abuseConfidenceScore", 0)
                verd = get_verdict(vt_m, ab_s, found_vt)
                details.update({"ab_s": ab_s, "ab_l": f"https://www.abuseipdb.com/check/{ioc}", "ISP": a_data.get("isp", "N/A"), "CountryName": get_full_country_name(a_data.get("countryCode", "N/A")), "UsageType": a_data.get("usageType", "N/A"), "Hostname": ", ".join(a_data.get("hostnames", [])) or "N/A"})
                whois_info, _ = get_whois_info(ioc)
            elif t == "Hash":
                verd = get_verdict(vt_m, 0, found_vt)
                details.update({"FileType": v_attr.get("type_description", "N/A"), "FileName": v_attr.get("meaningful_name", "N/A"), "Firmado": ("Válida" if v_attr.get("signature_info", {}).get("verified") == "Valid" else "No") if found_vt else "N/A"})
            elif t == "URL":
                ab_s, ab_l = 0, None
                try:
                    domain = urlparse(ioc if "://" in ioc else "http://"+ioc).netloc
                    rip = socket.gethostbyname(domain)
                    a_res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=ABUSE_HEADERS, params={"ipAddress": rip})
                    a_data = a_res.json().get("data", {}) if a_res.status_code == 200 else {}
                    ab_s = a_data.get("abuseConfidenceScore", 0)
                    ab_l = f"https://www.abuseipdb.com/check/{rip}"
                    details.update({"ab_s": ab_s, "ab_l": ab_l, "Resolved_IP": rip})
                except: pass
                verd = get_verdict(vt_m, ab_s, found_vt)
                whois_info, p_code = get_whois_info(ioc)
                details.update({"Category": v_attr.get("categories", {}).get("Forcepoint", "N/A"), "CountryName": get_full_country_name(p_code)})
            ioc_results.append({'ioc': ioc, 'type': t, 'verd': verd, 'vt_l': vt_l})
            full_internal += build_internal_block(ioc, t, verd, vt_m, vt_t, vt_l, details, whois_info, found_vt)
            full_analysis += build_analysis_block(ioc, t, verd, vt_m, vt_t, vt_l, details, found_vt)
    resumen = build_summary_block(ioc_results)
    render_copy_box("Investigación Interna", resumen + full_internal, "int_box")
    render_copy_box("Análisis de IOC", resumen + full_analysis, "ana_box")
