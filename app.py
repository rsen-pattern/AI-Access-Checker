# -*- coding: utf-8 -*-
"""
app.py — Pattern LLM Access Checker
Entry point for the multi-page Streamlit app.
"""
import streamlit as st
import base64

FAVICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 28 22"><path fill-rule="evenodd" clip-rule="evenodd" d="M0.197401 16.3997L16.2682 0.835708C16.5314 0.580806 16.9649 0.580806 17.2281 0.835708L21.1839 4.66673C21.4471 4.92913 21.4471 5.34148 21.1839 5.59638L5.11308 21.1604C4.84214 21.4153 4.41637 21.4153 4.15317 21.1604L0.197401 17.3294C-0.0658005 17.0745 -0.0658005 16.6546 0.197401 16.3997ZM13.4348 16.3997L22.8869 7.24577C23.1501 6.99086 23.5836 6.99086 23.8468 7.24577L27.8026 11.0768C28.0658 11.3392 28.0658 11.7515 27.8026 12.0064L18.3505 21.1604C18.0796 21.4153 17.6538 21.4153 17.3906 21.1604L13.4348 17.3294C13.1716 17.0745 13.1716 16.6546 13.4348 16.3997Z" fill="%23009bff"/></svg>'
FAVICON_B64 = base64.b64encode(FAVICON_SVG.encode()).decode()

st.set_page_config(
    page_title="Pattern — LLM Access Checker",
    page_icon=f"data:image/svg+xml;base64,{FAVICON_B64}",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.switch_page("pages/7_🔒_LLM_Access_Checker.py")
