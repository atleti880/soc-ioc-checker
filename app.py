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
    try:
        if not is_ip(target): target = urlparse(target if "://" in target else "https://"+target).netloc
        import whois
        w = whois.whois(target)
        info = [f"Registrar: {w.registrar}"] if w.registrar else []
        if w.org: info.append(f"Organización: {w.org}")
        return "\n".join(info) if info else "WHOIS: Sin detalles públicos.", w.country if w.country else "N/A"
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
# BLOQUES DE TEXTO PLANO (PARA ITOP)
# =========================
def build_summary_block(ioc_results):
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

# =========================
# LÓGICA PRINCIPAL
# =========================
if "ioc_input" not in st.session_state: st.session_state["ioc_input"] = ""
raw_iocs = st.text_area("IOCs a analizar", key="ioc_input", height=100)

if st.button("Iniciar Análisis", type="primary"):
    input_list = list(dict.fromkeys([x.strip() for x in raw_iocs.splitlines() if x.strip()]))
    ioc_results, list_ips, list_hashes, list_urls = [], [], [], []
    full_internal, full_analysis = "", ""

    for ioc in input_list:
        t = detect_ioc_type(ioc)
        if t == "Desconocido": continue
        # ... (Tu lógica de peticiones API sigue aquí igual)
        
        # Guardar para tablas y reportes
        ioc_results.append({'ioc': ioc, 'type': t, 'verd': verd, 'vt_l': vt_l})
        # (Aquí añadirías el append a list_ips, list_hashes, list_urls como tenías)

    # RENDERIZADO DE TABLAS (Visual para ti)
    st.header("📋 IOC Analizados")
    t1, t2, t3 = st.tabs(["IPs", "Archivos", "URLs"])
    with t1: st.dataframe(pd.DataFrame(list_ips), use_container_width=True)
    with t2: st.dataframe(pd.DataFrame(list_hashes), use_container_width=True)
    with t3: st.dataframe(pd.DataFrame(list_urls), use_container_width=True)

    # RENDERIZADO DE CAJAS DE COPIA (Texto plano para iTop)
    resumen = build_summary_block(ioc_results)
    c1, c2 = st.columns(2)
    with c1: st.text_area("Investigación Interna", resumen + full_internal, height=400)
    with c2: st.text_area("Análisis de IOC", resumen + full_analysis, height=400)
