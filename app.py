import streamlit as st
import requests
import re

VT_API = "a2e11c16ab7df4754b0b4ebf4feaa9320a96415cacc73065ffade9720411b916"
ABUSE_API = "4edd8009768e2dce4160c8646b7990ac74e4f0d90840701d4fb81004dd629b5b916b5edfb8a404af"

st.title("SOC IOC Checker")

ioc = st.text_input("Introduce IP / URL / Hash")

# ------------------------
# Detectar tipo de IOC
# ------------------------

def is_ip(value):
    return re.match(r"\d+\.\d+\.\d+\.\d+", value)

def is_hash(value):
    return re.match(r"^[A-Fa-f0-9]{32,64}$", value)

# ------------------------
# VirusTotal IP
# ------------------------

def vt_ip_lookup(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VT_API
    }

    response = requests.get(url, headers=headers)

    return response.json()

# ------------------------
# VirusTotal HASH
# ------------------------

def vt_hash_lookup(hash_value):

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

    headers = {
        "x-apikey": VT_API
    }

    response = requests.get(url, headers=headers)

    return response.json()

# ------------------------
# AbuseIPDB
# ------------------------

def abuse_lookup(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSE_API,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip
    }

    response = requests.get(url, headers=headers, params=params)

    return response.json()

# ------------------------
# Lógica principal
# ------------------------

if ioc:

    # ----------------
    # IP
    # ----------------

    if is_ip(ioc):

        st.subheader("VirusTotal")

        vt = vt_ip_lookup(ioc)

        try:
            stats = vt["data"]["attributes"]["last_analysis_stats"]

            st.write("Malicious:", stats["malicious"])
            st.write("Suspicious:", stats["suspicious"])
            st.write("Harmless:", stats["harmless"])

        except:
            st.write("No data")

        st.subheader("AbuseIPDB")

        abuse = abuse_lookup(ioc)

        try:
            score = abuse["data"]["abuseConfidenceScore"]
            reports = abuse["data"]["totalReports"]

            st.write("Abuse score:", score)
            st.write("Reports:", reports)

        except:
            st.write("No data")

    # ----------------
    # HASH
    # ----------------

    elif is_hash(ioc):

        st.subheader("VirusTotal File Analysis")

        vt = vt_hash_lookup(ioc)

        try:

            stats = vt["data"]["attributes"]["last_analysis_stats"]
            name = vt["data"]["attributes"]["meaningful_name"]

            st.write("File name:", name)
            st.write("Malicious:", stats["malicious"])
            st.write("Suspicious:", stats["suspicious"])
            st.write("Harmless:", stats["harmless"])

        except:

            st.write("Hash no encontrado en VirusTotal")

    else:

        st.write("Tipo de IOC aún no soportado")
