# dashboard.py
import streamlit as st
import pandas as pd
import sqlite3

DB_PATH = 'nids.db'

def read_table(name):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(f"SELECT * FROM {name} ORDER BY ts DESC LIMIT 500", conn)
    conn.close()
    return df

st.title("NIDS Dashboard")
st.header("Recent Packets")
packets = read_table("packets")
st.dataframe(packets)

st.header("Recent Alerts")
alerts = read_table("alerts")
st.dataframe(alerts)
