import streamlit as st

st.title("SOC IOC Checker")

ioc = st.text_input("Introduce una IP")

if ioc:
    st.write("IOC introducido:", ioc)
