import streamlit as st
import sqlite3
import hashlib
import uuid
from datetime import datetime

# --- Setup ---
st.set_page_config(page_title="Portfolio Accounting", layout="wide")
conn = sqlite3.connect(":memory:", check_same_thread=False)
cursor = conn.cursor()

# --- DB Init ---
def init_db():
    cursor.execute("""CREATE TABLE users (
        user_id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        tenant_id TEXT
    )""")
    cursor.execute("""CREATE TABLE accounts (
        account_id TEXT PRIMARY KEY,
        tenant_id TEXT,
        name TEXT,
        type TEXT
    )""")
    cursor.execute("""CREATE TABLE positions (
        position_id TEXT PRIMARY KEY,
        tenant_id TEXT,
        account_id TEXT,
        symbol TEXT,
        quantity REAL,
        market_value REAL,
        as_of_date TEXT
    )""")
    cursor.execute("""CREATE TABLE audit_logs (
        log_id TEXT PRIMARY KEY,
        tenant_id TEXT,
        user_id TEXT,
        event TEXT,
        timestamp TEXT
    )""")
    conn.commit()

init_db()

# --- Auth ---
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def register_user(username, password, role):
    tenant_id = str(uuid.uuid4()) if role == "advisor" else "admin"
    user_id = str(uuid.uuid4())
    try:
        cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?)",
                       (user_id, username, hash_pw(password), role, tenant_id))
        conn.commit()
        return True
    except:
        return False

def login_user(username, password):
    cursor.execute("SELECT user_id, role, tenant_id FROM users WHERE username=? AND password_hash=?",
                   (username, hash_pw(password)))
    return cursor.fetchone()

# --- UI ---
if "user" not in st.session_state:
    st.title("🔐 Login or Register")
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        uname = st.text_input("Username", key="login_user")
        pw = st.text_input("Password", type="password", key="login_pw")
        if st.button("Login"):
            user = login_user(uname, pw)
            if user:
                st.session_state.user = {"id": user[0], "role": user[1], "tenant": user[2]}
                st.rerun()
            else:
                st.error("Invalid credentials")

    with tab2:
        new_user = st.text_input("New Username")
        new_pw = st.text_input("New Password", type="password")
        role = st.selectbox("Role", ["advisor", "admin"])
        if st.button("Register"):
            if register_user(new_user, new_pw, role):
                st.success("Registered! Please login.")
            else:
                st.error("Username already exists")
else:
    user = st.session_state.user
    st.sidebar.title("📁 Navigation")
    page = st.sidebar.radio("Go to", ["Dashboard", "Holdings", "Performance", "Compliance", "Reconciliation", "Query Console", "Logout"])

    def log_event(event):
        cursor.execute("INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?)",
                       (str(uuid.uuid4()), user["tenant"], user["id"], event, datetime.now().isoformat()))
        conn.commit()

    if page == "Logout":
        st.session_state.clear()
        st.rerun()

    elif page == "Dashboard":
        st.title("📊 Portfolio Dashboard")
        cursor.execute("SELECT COUNT(*) FROM accounts WHERE tenant_id=?", (user["tenant"],))
        acct_count = cursor.fetchone()[0]
        st.metric("Accounts", acct_count)
        log_event("Viewed Dashboard")

    elif page == "Holdings":
        st.title("📄 Holdings")
        cursor.execute("SELECT * FROM positions WHERE tenant_id=?", (user["tenant"],))
        rows = cursor.fetchall()
        st.dataframe(rows)
        log_event("Viewed Holdings")

    elif page == "Performance":
        st.title("📈 Performance")
        st.info("Performance agent would calculate TWR/MWR returns here.")
        log_event("Viewed Performance")

    elif page == "Compliance":
        st.title("✅ Compliance")
        st.warning("Compliance agent would flag rule violations here.")
        log_event("Viewed Compliance")

    elif page == "Reconciliation":
        st.title("🔍 Reconciliation")
        st.info("Reconciliation agent would match internal vs custodian data.")
        log_event("Viewed Reconciliation")

    elif page == "Query Console":
        st.title("🧠 Ask the AI")
        q = st.text_input("Ask a question about your portfolio")
        if st.button("Submit") and q:
            st.success(f"Mock response for: '{q}'")
            log_event(f"Queried: {q}")
