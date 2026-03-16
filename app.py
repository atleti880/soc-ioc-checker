import streamlit as st
import requests
import re

VT_API = "a2e11c16ab7df4754b0b4ebf4feaa9320a96415cacc73065ffade9720411b916"
ABUSE_API = "4edd8009768e2dce4160c8646b7990ac74e4f0d90840701d4fb81004dd629b5b916b5edfb8a404af"

st.set_page_config(page_title="SOC IOC Checker", page_icon="🛡️", layout="wide")

st.title("SOC IOC Checker")
st.caption("Consulta IP / URL / Hash en VirusTotal y AbuseIPDB")

ioc = st.text_input("Introduce IP / URL / Hash")

def is_ip(value):
    return re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value) is not None

def is_hash(value):
    return re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value) is not None

def vt_ip_lookup(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API}
    r = requests.get(url, headers=headers, timeout=15)
    return r

def vt_hash_lookup(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VT_API}
    r = requests.get(url, headers=headers, timeout=15)
    return r

def abuse_lookup(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_API, "Accept": "application/json"}
    params = {"ipAddress": ip}
    r = requests.get(url, headers=headers, params=params, timeout=15)
    return r

def get_verdict(vt_malicious=0, vt_suspicious=0, abuse_score=0):
    if abuse_score >= 80 or vt_malicious >= 5:
        return "Malicioso", "high"
    elif abuse_score >= 30 or vt_malicious >= 1 or vt_suspicious >= 3:
        return "Sospechoso", "medium"
    return "Bajo riesgo", "low"

if ioc:
    ioc = ioc.strip()

    if is_ip(ioc):
        st.info(f"Tipo detectado: IP")

        vt_response = vt_ip_lookup(ioc)
        abuse_response = abuse_lookup(ioc)

        vt_ok = vt_response.status_code == 200
        abuse_ok = abuse_response.status_code == 200

        vt_malicious = 0
        vt_suspicious = 0
        vt_harmless = 0
        abuse_score = 0
        reports = 0
        country = "N/A"
        as_owner = "N/A"

        if vt_ok:
            vt = vt_response.json()
            attr = vt["data"]["attributes"]
            stats = attr["last_analysis_stats"]
            vt_malicious = stats.get("malicious", 0)
            vt_suspicious = stats.get("suspicious", 0)
            vt_harmless = stats.get("harmless", 0)
            country = attr.get("country", "N/A")
            as_owner = attr.get("as_owner", "N/A")

        if abuse_ok:
            abuse = abuse_response.json()
            abuse_score = abuse["data"].get("abuseConfidenceScore", 0)
            reports = abuse["data"].get("totalReports", 0)

        verdict, severity = get_verdict(vt_malicious, vt_suspicious, abuse_score)

        if severity == "high":
            st.error(f"Veredicto: {verdict}")
        elif severity == "medium":
            st.warning(f"Veredicto: {verdict}")
        else:
            st.success(f"Veredicto: {verdict}")

        st.subheader("Resumen")
        st.write(
            f"La IP **{ioc}** presenta "
            f"**{vt_malicious} detecciones maliciosas** en VirusTotal y "
            f"**abuse score {abuse_score}** en AbuseIPDB."
        )

        col1, col2, col3 = st.columns(3)
        col1.metric("VT Malicious", vt_malicious)
        col2.metric("VT Suspicious", vt_suspicious)
        col3.metric("VT Harmless", vt_harmless)

        col4, col5 = st.columns(2)
        col4.metric("Abuse Score", abuse_score)
        col5.metric("Reports", reports)

        st.subheader("Contexto")
        c1, c2 = st.columns(2)
        c1.write(f"**País:** {country}")
        c2.write(f"**AS Owner:** {as_owner}")

        st.subheader("Enlaces")
        vt_link = f"https://www.virustotal.com/gui/ip-address/{ioc}"
        abuse_link = f"https://www.abuseipdb.com/check/{ioc}"
        st.markdown(f"[Abrir en VirusTotal]({vt_link})")
        st.markdown(f"[Abrir en AbuseIPDB]({abuse_link})")

        ticket_text = f"""IOC analizado: {ioc}
Tipo: IP
VirusTotal: malicious={vt_malicious}, suspicious={vt_suspicious}, harmless={vt_harmless}
AbuseIPDB: abuseConfidenceScore={abuse_score}, totalReports={reports}
País: {country}
AS Owner: {as_owner}
Conclusión: {verdict}
"""
        st.subheader("Texto para ticket")
        st.code(ticket_text, language="text")

    elif is_hash(ioc):
        st.info("Tipo detectado: Hash")

        vt_response = vt_hash_lookup(ioc)

        if vt_response.status_code == 200:
            vt = vt_response.json()
            attr = vt["data"]["attributes"]
            stats = attr["last_analysis_stats"]

            vt_malicious = stats.get("malicious", 0)
            vt_suspicious = stats.get("suspicious", 0)
            vt_harmless = stats.get("harmless", 0)
            file_name = attr.get("meaningful_name", "N/A")
            file_type = attr.get("type_description", "N/A")

            verdict, severity = get_verdict(vt_malicious, vt_suspicious, 0)

            if severity == "high":
                st.error(f"Veredicto: {verdict}")
            elif severity == "medium":
                st.warning(f"Veredicto: {verdict}")
            else:
                st.success(f"Veredicto: {verdict}")

            col1, col2, col3 = st.columns(3)
            col1.metric("VT Malicious", vt_malicious)
            col2.metric("VT Suspicious", vt_suspicious)
            col3.metric("VT Harmless", vt_harmless)

            st.subheader("Contexto")
            st.write(f"**Nombre de archivo:** {file_name}")
            st.write(f"**Tipo de archivo:** {file_type}")

            vt_link = f"https://www.virustotal.com/gui/file/{ioc}"
            st.markdown(f"[Abrir en VirusTotal]({vt_link})")

            ticket_text = f"""IOC analizado: {ioc}
Tipo: Hash
Nombre de archivo: {file_name}
Tipo de archivo: {file_type}
VirusTotal: malicious={vt_malicious}, suspicious={vt_suspicious}, harmless={vt_harmless}
Conclusión: {verdict}
"""
            st.subheader("Texto para ticket")
            st.code(ticket_text, language="text")
        else:
            st.error("Hash no encontrado en VirusTotal o error de API.")

    else:
        st.warning("Tipo de IOC aún no soportado.")
