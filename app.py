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

# CONFIGURACIÓN DE APIS (Desde .streamlit/secrets.toml)
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
        if not host:
            return False
        if is_ip(host):
            return True
        domain_regex = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$"
        return re.fullmatch(domain_regex, host) is not None
    except Exception:
        return False

def detect_ioc_type(value: str) -> str:
    value = value.strip()
    if is_ip(value):
        return "IP"
    if is_hash(value):
        return "Hash"
    if is_url(value):
        return "URL"
    return "Desconocido"

def safe_json(response: requests.Response) -> dict:
    try:
        return response.json()
    except Exception:
        return {}

def country_name_from_code(code: str) -> str:
    if not code or code == "N/A":
        return "N/A"
    try:
        country = pycountry.countries.get(alpha_2=code.upper())
        return country.name if country else code
    except Exception:
        return code

def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def total_engines_from_stats(stats: dict) -> int:
    if not isinstance(stats, dict):
        return 0
    return sum(v for v in stats.values() if isinstance(v, int))

def format_file_size(size):
    if not isinstance(size, (int, float)):
        return str(size)
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024

def format_unix_timestamp(ts):
    if ts in (None, "", "N/A"):
        return "N/A"
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)

def format_categories(categories) -> str:
    if not categories:
        return "N/A"
    if isinstance(categories, dict):
        return ", ".join(f"{k}: {v}" for k, v in categories.items())
    if isinstance(categories, list):
        return ", ".join(str(x) for x in categories)
    return str(categories)

def normalize_reputation(value):
    if value in (None, "", "N/A"):
        return "N/A"
    return value

def escape_key(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", value)

def get_status_icon(verdict: str) -> str:
    if verdict == "Malicioso":
        return "🔴"
    if verdict == "Sospechoso":
        return "🟠"
    if verdict == "Bajo riesgo":
        return "🟢"
    return "⚪"

# =========================
# NUEVA FUNCIÓN TABLA ITOP
# =========================
def df_to_markdown_table(df):
    """Convierte el DataFrame resumen a una tabla Markdown para iTop."""
    cols_to_show = ["Estado", "IOC", "Tipo", "Veredicto", "VT Malicious", "Abuse Score"]
    existing_cols = [c for c in cols_to_show if c in df.columns]
    sub_df = df[existing_cols].copy()
    
    header = "| " + " | ".join(sub_df.columns) + " |"
    separator = "| " + " | ".join(["---"] * len(sub_df.columns)) + " |"
    rows = []
    for _, row in sub_df.iterrows():
        rows.append("| " + " | ".join(str(x) for x in row.values) + " |")
    return "\n".join([header, separator] + rows)

# =========================
# VEREDICTO / OBSERVACIONES
# =========================
def get_verdict(vt_malicious: int = 0, vt_suspicious: int = 0, abuse_score: int = 0):
    if abuse_score >= 80 or vt_malicious >= 5:
        return "Malicioso", "high"
    if abuse_score >= 30 or vt_malicious >= 1 or vt_suspicious >= 3:
        return "Sospechoso", "medium"
    return "Bajo riesgo", "low"

def get_verdict_icon(severity: str) -> str:
    if severity == "high": return "🔴"
    if severity == "medium": return "🟠"
    return "🟢"

def get_verdict_hint(severity: str) -> str:
    if severity == "high": return "Requiere revisión inmediata."
    if severity == "medium": return "Conviene validar el contexto y revisar eventos asociados."
    return "Sin indicadores claros en las fuentes consultadas."

def show_verdict_banner(verdict: str, severity: str):
    icon = get_verdict_icon(severity)
    hint = get_verdict_hint(severity)
    if severity == "high": st.error(f"{icon} Veredicto: {verdict}")
    elif severity == "medium": st.warning(f"{icon} Veredicto: {verdict}")
    else: st.success(f"{icon} Veredicto: {verdict}")
    st.caption(hint)

def get_observations_ip(vt_malicious, vt_suspicious, abuse_score, reports, as_owner, hostname):
    obs = []
    if vt_malicious > 0: obs.append(f"La IP presenta {vt_malicious} detecciones maliciosas en VirusTotal.")
    elif vt_suspicious > 0: obs.append(f"La IP tiene {vt_suspicious} detecciones sospechosas en VT.")
    else: obs.append("Sin detecciones claras en VT.")
    if abuse_score >= 30: obs.append(f"AbuseIPDB score: {abuse_score}% con {reports} reportes.")
    if as_owner != "N/A": obs.append(f"AS Owner: {as_owner}.")
    return " ".join(obs)

def get_observations_hash(vt_malicious, vt_suspicious, signature):
    obs = []
    if vt_malicious > 0: obs.append(f"El hash presenta {vt_malicious} detecciones maliciosas en VT.")
    if signature["is_signed"] and signature["is_valid"]: obs.append("Archivo firmado y firma válida.")
    elif signature["is_signed"]: obs.append("Archivo firmado, validez no concluyente.")
    else: obs.append("Archivo no firmado digitalmente.")
    return " ".join(obs)

def get_observations_url(vt_malicious, vt_suspicious, categories):
    obs = []
    if vt_malicious > 0: obs.append(f"La URL presenta {vt_malicious} detecciones maliciosas en VT.")
    if categories: obs.append(f"Categorías VT: {format_categories(categories)}.")
    return " ".join(obs)

# =========================
# RENDER VISUAL
# =========================
def render_vt_score_card(malicious: int, total: int):
    percent = 0 if total == 0 else round((malicious / total) * 100)
    card_html = f"""
    <div style="background:#1f2a44; border-radius:14px; padding:22px 18px; text-align:center; width:220px; margin-bottom:12px;">
        <div style="width:120px; height:120px; border-radius:50%; margin:0 auto 12px auto; background: conic-gradient(#ff5a52 {percent}%, #31456e 0%); display:flex; align-items:center; justify-content:center;">
            <div style="width:88px; height:88px; border-radius:50%; background:#1f2a44; display:flex; flex-direction:column; align-items:center; justify-content:center;">
                <div style="font-size:22px; color:#ff5a52; line-height:1; font-weight:700;">{malicious}</div>
                <div style="font-size:14px; color:#c9d4ea; line-height:1.2; margin-top:4px;">/ {total}</div>
            </div>
        </div>
        <div style="font-size:14px; color:#c9d4ea; font-weight:600;">VT Community Score</div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)

def render_abuse_score_bar(score: int, reports: int):
    st.subheader("AbuseIPDB Score")
    st.write(f"Reportes: **{reports}** | Confidence: **{score}%**")
    st.progress(min(max(score, 0), 100))

def render_severity_badge(label: str, value, severity: str):
    colors = {"high": ("#ffdddd", "#8b0000"), "medium": ("#fff4d6", "#8a5a00"), "low": ("#ddffea", "#0a6b33")}
    bg, fg = colors[severity]
    st.markdown(f'<div style="background:{bg}; color:{fg}; border-radius:10px; padding:10px 12px; margin-bottom:8px; font-weight:600;">{label}: {value}</div>', unsafe_allow_html=True)

def render_copy_box(title: str, text: str, unique_key: str, height: int = 320):
    st.subheader(title)
    escaped_text = html.escape(text)
    component_html = f"""
    <div style="margin-top: 0.5rem; margin-bottom: 1rem;">
        <textarea id="copy_box_{unique_key}" readonly style="width: 100%; height: {height}px; padding: 12px; border-radius: 8px; border: 1px solid #4a4a4a; background: #0e1117; color: #fafafa; font-family: monospace; font-size: 14px; line-height: 1.5; resize: vertical; box-sizing: border-box;">{escaped_text}</textarea>
        <button onclick="copyText_{unique_key}()" style="margin-top: 10px; background: #ff4b4b; color: white; border: none; padding: 10px 16px; border-radius: 8px; cursor: pointer; font-weight: 600;">Copiar al portapapeles</button>
        <span id="copy_msg_{unique_key}" style="margin-left: 12px; color: #7dd87d; font-weight: 600;"></span>
    </div>
    <script>
    function copyText_{unique_key}() {{
        const textarea = document.getElementById("copy_box_{unique_key}");
        textarea.select();
        navigator.clipboard.writeText(textarea.value).then(() => {{
            const msg = document.getElementById("copy_msg_{unique_key}");
            msg.innerText = "Copiado ✅";
            setTimeout(() => {{ msg.innerText = ""; }}, 2000);
        }});
    }}
    </script>
    """
    components.html(component_html, height=height + 80)

# =========================
# EXTRACCIÓN AVANZADA VT
# =========================
def extract_signature_info(vt_attributes: dict) -> dict:
    res = {"is_signed": False, "is_valid": False, "signers": [], "verified": "N/A", "publisher": "N/A", "date_signed": "N/A", "product": "N/A", "description": "N/A", "file_version": "N/A", "original_name": "N/A"}
    sig_info = vt_attributes.get("signature_info", {})
    pe_info = vt_attributes.get("pe_info", {})
    if sig_info:
        res["is_signed"] = True
        res["publisher"] = sig_info.get("publisher", "N/A")
        res["verified"] = sig_info.get("verified", "N/A")
        if res["verified"] == "Valid": res["is_valid"] = True
    v_info = vt_attributes.get("file_version_info", {})
    res["product"] = v_info.get("Product", "N/A")
    res["description"] = v_info.get("FileDescription", "N/A")
    return res

def extract_history_info(vt_attributes: dict) -> dict:
    return {
        "fecha_creacion": format_unix_timestamp(vt_attributes.get("creation_date")),
        "primera_subida_vt": format_unix_timestamp(vt_attributes.get("first_submission_date")),
        "ultima_subida_vt": format_unix_timestamp(vt_attributes.get("last_submission_date")),
        "ultimo_analisis": format_unix_timestamp(vt_attributes.get("last_analysis_date")),
    }

@st.cache_data(ttl=3600, show_spinner=False)
def reverse_dns_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"

# =========================
# API WRAPPERS
# =========================
def get_metric_severity_for_vt(mal): return "high" if mal >= 5 else "medium" if mal >= 1 else "low"
def get_metric_severity_for_abuse(sc): return "high" if sc >= 80 else "medium" if sc >= 30 else "low"

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
# TICKET FORMATS (iTOP)
# =========================
def build_ticket_text_ip(ioc, vt_m, vt_t, vt_s, rep, ab_s, reps, country, c_code, as_o, asn, net, host, vt_l, ab_l, verd, obs):
    return f"""--- DETALLES DEL INDICADOR (IOC) ---
IOC:         {ioc}
TIPO:        IP Address
ESTADO:      {verd.upper()}
FECHA:       {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

[1] REPUTACIÓN Y SCORE
--------------------------------------------------
VirusTotal:    {vt_m}/{vt_t} detecciones
AbuseIPDB:     {ab_s}% ({reps} reportes)

[2] INFORMACIÓN DE CONTEXTO
--------------------------------------------------
País:        {country} ({c_code})
Proveedor:   {as_o} (ASN: {asn})
Hostname:    {host}

[3] OBSERVACIONES
--------------------------------------------------
{obs}

[4] EVIDENCIAS
--------------------------------------------------
- VT: {vt_l}
- Abuse: {ab_l}
--------------------------------------------------"""

def build_ticket_text_hash(ioc, sha, name, f_type, size, hist, sig, vt_m, vt_t, vt_s, vt_l, verd, obs):
    return f"""--- ANÁLISIS DE ARCHIVO (HASH) ---
IOC (Hash):  {ioc}
ESTADO:      {verd.upper()}

[1] IDENTIFICACIÓN
--------------------------------------------------
Nombre:      {name}
Tipo:        {f_type}
SHA256:      {sha}

[2] FIRMA DIGITAL
--------------------------------------------------
Firmado:     {"SÍ" if sig["is_signed"] else "NO"}
Válida:      {"SÍ" if sig["is_valid"] else "N/A"}
Publisher:   {sig["publisher"]}

[3] OBSERVACIONES
--------------------------------------------------
{obs}

[4] EVIDENCIA
--------------------------------------------------
VT: {vt_l}
--------------------------------------------------"""

def build_ticket_text_url(ioc, final, vt_m, vt_t, vt_s, cats, vt_l, verd, obs):
    return f"""--- ANÁLISIS DE URL ---
URL:         {ioc}
ESTADO:      {verd.upper()}

[1] DETALLES
--------------------------------------------------
URL Final:   {final}
Categoría:   {format_categories(cats)}

[2] REPUTACIÓN
--------------------------------------------------
VirusTotal:  {vt_m}/{vt_t} detecciones

[3] OBSERVACIONES
--------------------------------------------------
{obs}

[4] EVIDENCIA
--------------------------------------------------
VT: {vt_l}
--------------------------------------------------"""

# =========================
# INTERFAZ Y PROCESO
# =========================
def clear_ioc_input(): st.session_state["ioc_input"] = ""

col_i, col_a = st.columns([6, 1])
with col_i: raw_iocs = st.text_area("IOCs (uno por línea)", key="ioc_input", height=120)
with col_a: 
    st.write(""); st.write("")
    st.button("Limpiar", on_click=clear_ioc_input)

if st.button("Analizar IOC(s)", type="primary", use_container_width=True):
    iocs = list(dict.fromkeys([x.strip() for x in raw_iocs.splitlines() if x.strip()]))
    if not iocs: st.warning("Introduce IOCs."); st.stop()

    summary_rows, detailed_results = [], []

    with st.spinner("Escaneando..."):
        for ioc in iocs:
            t = detect_ioc_type(ioc)
            if t == "IP":
                v, a = vt_lookup(ioc, "IP"), abuse_lookup(ioc)
                vt_m, vt_s, vt_t, sc, reps, as_o, country, c_code, asn, net, rep = 0, 0, 0, 0, 0, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"
                if v["ok"]:
                    attr = v["json"]["data"]["attributes"]
                    stats = attr["last_analysis_stats"]
                    vt_m, vt_s, vt_t = stats["malicious"], stats["suspicious"], total_engines_from_stats(stats)
                    as_o, country, c_code, asn, net, rep = attr.get("as_owner","N/A"), country_name_from_code(attr.get("country")), attr.get("country","N/A"), attr.get("asn","N/A"), attr.get("network","N/A"), attr.get("reputation","N/A")
                if a["ok"]:
                    d = a["json"]["data"]
                    sc, reps = d.get("abuseConfidenceScore", 0), d.get("totalReports", 0)
                
                verd, sev = get_verdict(vt_m, vt_s, sc)
                host = reverse_dns_lookup(ioc)
                obs = get_observations_ip(vt_m, vt_s, sc, reps, as_o, host)
                
                summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "IP", "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": f"{sc}%"})
                detailed_results.append({"ioc": ioc, "type": "IP", "verd": verd, "sev": sev, "data": {"vt_m": vt_m, "vt_s": vt_s, "vt_t": vt_t, "sc": sc, "reps": reps, "as_o": as_o, "country": country, "c_code": c_code, "asn": asn, "net": net, "rep": rep, "host": host, "obs": obs, "vt_l": f"https://www.virustotal.com/gui/ip-address/{ioc}", "ab_l": f"https://www.abuseipdb.com/check/{ioc}"}})

            elif t == "Hash":
                v = vt_lookup(ioc, "Hash")
                if v["ok"]:
                    attr = v["json"]["data"]["attributes"]
                    stats = attr["last_analysis_stats"]
                    vt_m, vt_s, vt_t = stats["malicious"], stats["suspicious"], total_engines_from_stats(stats)
                    verd, sev = get_verdict(vt_m, vt_s)
                    sig, hist = extract_signature_info(attr), extract_history_info(attr)
                    obs = get_observations_hash(vt_m, vt_s, sig)
                    summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "Hash", "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": "N/A"})
                    detailed_results.append({"ioc": ioc, "type": "Hash", "verd": verd, "sev": sev, "data": {"vt_m": vt_m, "vt_s": vt_s, "vt_t": vt_t, "name": attr.get("meaningful_name","N/A"), "f_type": attr.get("type_description","N/A"), "size": attr.get("size",0), "sha": attr.get("sha256","N/A"), "sig": sig, "hist": hist, "obs": obs, "vt_l": f"https://www.virustotal.com/gui/file/{ioc}"}})

            elif t == "URL":
                v = vt_lookup(ioc, "URL")
                if v["ok"]:
                    attr = v["json"]["data"]["attributes"]
                    stats = attr["last_analysis_stats"]
                    vt_m, vt_s, vt_t = stats["malicious"], stats["suspicious"], total_engines_from_stats(stats)
                    verd, sev = get_verdict(vt_m, vt_s)
                    obs = get_observations_url(vt_m, vt_s, attr.get("categories"))
                    summary_rows.append({"Estado": get_status_icon(verd), "IOC": ioc, "Tipo": "URL", "Veredicto": verd, "VT Malicious": vt_m, "Abuse Score": "N/A"})
                    detailed_results.append({"ioc": ioc, "type": "URL", "verd": verd, "sev": sev, "data": {"vt_m": vt_m, "vt_s": vt_s, "vt_t": vt_t, "final": attr.get("url", ioc), "cats": attr.get("categories"), "obs": obs, "vt_l": f"https://www.virustotal.com/gui/url/{vt_url_id(ioc)}"}})

    # RENDER RESUMEN
    st.header("Resumen global")
    df = pd.DataFrame(summary_rows)
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    # TABLA PARA ITOP
    render_copy_box("Tabla para iTop (Markdown)", df_to_markdown_table(df), "itop_table", height=150)

    # DETALLES
    for r in detailed_results:
        st.markdown("---")
        st.subheader(f"IOC: {r['ioc']}")
        show_verdict_banner(r['verd'], r['sev'])
        d = r['data']
        
        if r['type'] == "IP":
            c1, c2 = st.columns([1, 2])
            with c1: render_vt_score_card(d['vt_m'], d['vt_t'])
            with c2: render_abuse_score_bar(d['sc'], d['reps'])
            st.write(f"**Contexto:** {d['country']} | {d['as_o']} | {d['host']}")
            render_copy_box("Ticket iTop", build_ticket_text_ip(r['ioc'], d['vt_m'], d['vt_t'], d['vt_s'], d['rep'], d['sc'], d['reps'], d['country'], d['c_code'], d['as_o'], d['asn'], d['net'], d['host'], d['vt_l'], d['ab_l'], r['verd'], d['obs']), f"tk_{r['ioc']}")
            
        elif r['type'] == "Hash":
            render_vt_score_card(d['vt_m'], d['vt_t'])
            st.write(f"**Archivo:** {d['name']} ({d['f_type']})")
            render_copy_box("Ticket iTop", build_ticket_text_hash(r['ioc'], d['sha'], d['name'], d['f_type'], d['size'], d['hist'], d['sig'], d['vt_m'], d['vt_t'], d['vt_s'], d['vt_l'], r['verd'], d['obs']), f"tk_{r['ioc']}")

        elif r['type'] == "URL":
            render_vt_score_card(d['vt_m'], d['vt_t'])
            st.write(f"**URL Final:** {d['final']}")
            render_copy_box("Ticket iTop", build_ticket_text_url(r['ioc'], d['final'], d['vt_m'], d['vt_t'], d['vt_s'], d['cats'], d['vt_l'], r['verd'], d['obs']), f"tk_{r['ioc']}")
