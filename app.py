import streamlit as st
import requests
import re

VT_API = "a2e11c16ab7df4754b0b4ebf4feaa9320a96415cacc73065ffade9720411b916"
ABUSE_API = "TU_API_ABUSE"

st.title("SOC IOC Checker")

ioc = st.text_input("Introduce IP / URL / Hash")

def is_ip(value):
    return re.match(r"\d+\.\d+\.\d+\.\d+", value)

def vt_ip_lookup(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VT_API
    }

    response = requests.get(url, headers=headers)

    return response.json()

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

if ioc:

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

    else:

        st.write("Tipo de IOC aún no soportado")
