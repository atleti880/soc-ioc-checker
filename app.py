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
# CONFIGURACIÓN
# =========================
VT_API = st.secrets["VT_API"]
ABUSE_API = st.secrets["ABUSE_API"]
VT_HEADERS = {"x-apikey": VT_API}
ABUSE_HEADERS = {"Key": ABUSE_API, "Accept": "application/json"}

st.set_page_config(page_title="SOC IOC Checker", layout="wide")
st.title("🛡️ SOC IOC Checker")

# =========================
# FUNCIONES DE CONSTRUCCIÓN
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

# =========================
# LÓGICA PRINCIPAL
# =========================
if "ioc_input" not in st.session_state: st.session_state["ioc_input"] = ""
raw_iocs = st.text_area("IOCs a analizar", key="ioc_input", height=100)

if st.button("Iniciar Análisis", type="primary"):
    input_list = list(dict.fromkeys([x.strip() for x in raw_iocs.splitlines() if x.strip()]))
    
    # INICIALIZACIÓN DE VARIABLES CRÍTICAS
    ioc_results = []
    full_internal = ""
    full_analysis = ""
    
    with st.spinner("Analizando..."):
        for ioc in input_list:
            # (Aquí tu lógica de análisis previa...)
            # ... asegurando que 'verd', 'vt_l', 'vt_m', 'vt_t', 'details', 'found_vt', 't' estén definidos
            
            # GUARDAR RESULTADOS PARA EL RESUMEN
            ioc_results.append({'ioc': ioc, 'type': t, 'verd': verd, 'vt_l': vt_l})
            
            # CONSTRUIR BLOQUES DE TEXTO
            full_internal += f"ANALISIS INTERNO SOC - {verd.upper()}\n=================\nIOC: {ioc}\n\n" + build_context_block(t, vt_m, vt_t, details, found_vt) + "\n\n"
            full_analysis += f"REPORTE IOC: {ioc}\n-----------------\n" + build_context_block(t, vt_m, vt_t, details, found_vt) + "\n\n"

    # GENERAR RESUMEN FINAL
    resumen_texto = build_summary_block(ioc_results)
    
    # MOSTRAR Y PERMITIR COPIA
    c1, c2 = st.columns(2)
    with c1: st.text_area("Investigación Interna", resumen_texto + full_internal, height=400)
    with c2: st.text_area("Análisis de IOC", resumen_texto + full_analysis, height=400)
