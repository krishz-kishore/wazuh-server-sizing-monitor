#!/usr/bin/env python3
"""
Comprehensive SIEM Server Sizing Monitor
- Collects disk usage in GB
- Collects Wazuh agent count
- Uses agent log size instead of alerts
- Appends to CSV
- Generates HTML report with tables + graphs
"""

import os
from pathlib import Path
import subprocess
import datetime
import pandas as pd
import matplotlib.pyplot as plt
from jinja2 import Template
from dotenv import load_dotenv
import requests
import urllib3
import matplotlib.dates as mdates

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- CONFIG ----------
load_dotenv("/home/wazuh-user/.env")
WAZUH_API = "https://localhost:55000"  # API URL (unused for alerts now)
USERNAME = os.getenv("WAZUH_USER")
PASSWORD = os.getenv("WAZUH_PASS")
VERIFY_SSL = False

# Get current user's home directory
HOME_DIR = str(Path.home())

# Set output directory inside the home folder
OUTPUT_DIR = os.path.join(HOME_DIR, "monitor")

# Ensure the directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

CSV_FILE = os.path.join(OUTPUT_DIR, 'server_sizing_master.csv')
HTML_FILE = os.path.join(OUTPUT_DIR, 'server_sizing_report.html')

# Directories to monitor
# Base directories to consider
POTENTIAL_DIRS = {
    'var': '/var',
    'var_log': '/var/log',
    'var_lib': '/var/lib',
    'var_ossec': '/var/ossec',
    'root': '/',
    'usr': '/usr',
    'home': '/home',
    'opt': '/opt'
}

# Dynamically check which exist
TRACK_DIRS = [(name, path) for name, path in POTENTIAL_DIRS.items() if os.path.exists(path)]

print("Directories to track:", TRACK_DIRS)

# ---------- HELPERS ----------
def debug_print(msg):
    print(f"[INFO] {msg}")

def du_gb(path):
    """Return directory size in GB, skipping virtual filesystems"""
    if path.startswith(('/proc', '/sys', '/dev')):
        return 0
    if not os.path.exists(path):
        return 0
    try:
        completed = subprocess.run(['du','-sk', path], capture_output=True, text=True, timeout=30)
        if completed.returncode != 0:
            debug_print(f"du failed for {path}: {completed.stderr.strip()}")
            return 0
        kb = int(completed.stdout.strip().split()[0])
        gb = round(kb / 1024 / 1024, 2)
        return gb
    except Exception as e:
        debug_print(f"du error for {path}: {e}")
        return 0

def ensure_output():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def append_csv(row):
    ensure_output()
    df = pd.DataFrame([row])
    if not os.path.exists(CSV_FILE):
        df.to_csv(CSV_FILE, index=False)
    else:
        df.to_csv(CSV_FILE, mode='a', header=False, index=False)

def read_history():
    if os.path.exists(CSV_FILE):
        try:
            return pd.read_csv(CSV_FILE, parse_dates=['date'])
        except Exception:
            return None
    return None

def get_token():
    """Authenticate to Wazuh API (used only for agents)"""
    url = f"{WAZUH_API}/security/user/authenticate"
    try:
        r = requests.post(url, auth=(USERNAME, PASSWORD), verify=VERIFY_SSL, timeout=15)
        r.raise_for_status()
        token = r.json().get('data', {}).get('token')
        if not token:
            raise ValueError('Token missing')
        return token
    except Exception as e:
        raise RuntimeError(f"Wazuh API authentication failed: {e}")

def get_agents(token):
    """Fetch Wazuh agents"""
    url = f"{WAZUH_API}/agents"
    headers = {'Authorization': f"Bearer {token}"}
    try:
        r = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=15)
        r.raise_for_status()
        data = r.json().get('data', {})
        items = data.get('affected_items') or data.get('items') or []
        return items
    except Exception as e:
        debug_print(f"Warning: could not fetch agents: {e}")
        return []

def get_agents_log_size_gb():
    """Return total Wazuh agent log size in GB"""
    return du_gb("/var/ossec/logs")

def generate_graphs(df):
    ensure_output()
    cols = [k[0] + '_gb' for k in TRACK_DIRS]
    cols_present = [c for c in cols if c in df.columns]

    # Make sure date is datetime
    df['date'] = pd.to_datetime(df['date'])
    df = df.sort_values(by="date")

    # Get dynamic range
    start_date = df['date'].min()
    end_date = df['date'].max()

    # Disk growth
    plt.figure(figsize=(10,6))
    for c in cols_present:
        plt.plot(df['date'], df[c], marker='o', label=c.replace('_gb',''))
    plt.title('Disk Growth (GB)')
    plt.xlabel('Date')
    plt.ylabel('GB')
    plt.legend()
    plt.grid(True)

    # Format x-axis dynamically
    ax = plt.gca()
    ax.xaxis.set_major_locator(mdates.AutoDateLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
    plt.xticks(rotation=45)
    plt.xlim(start_date, end_date)

    plt.tight_layout()
    disk_png = os.path.join(OUTPUT_DIR, 'disk_growth.png')
    plt.savefig(disk_png)
    plt.clf()

    # Daily ingestion (/var)
    if 'var_gb' in df.columns:
        df['var_delta'] = df['var_gb'].diff().fillna(0)
        plt.figure(figsize=(10,4))
        plt.bar(df['date'], df['var_delta'])
        plt.title('Daily /var Ingestion (GB)')
        plt.xlabel('Date')
        plt.ylabel('GB/day')
        plt.grid(True)

        ax = plt.gca()
        ax.xaxis.set_major_locator(mdates.AutoDateLocator())
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
        plt.xticks(rotation=45)
        plt.xlim(start_date, end_date)

        plt.tight_layout()
        ingest_png = os.path.join(OUTPUT_DIR, 'daily_ingestion.png')
        plt.savefig(ingest_png)
        plt.clf()
    else:
        ingest_png = None

    # Agent count
    if 'agent_count' in df.columns:
        plt.figure(figsize=(10,4))
        plt.plot(df['date'], df['agent_count'], marker='s', color='orange')
        plt.title('Wazuh Agent Count')
        plt.xlabel('Date')
        plt.ylabel('Agents')
        plt.grid(True)

        ax = plt.gca()
        ax.xaxis.set_major_locator(mdates.AutoDateLocator())
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
        plt.xticks(rotation=45)
        plt.xlim(start_date, end_date)

        plt.tight_layout()
        agents_png = os.path.join(OUTPUT_DIR, 'agent_growth.png')
        plt.savefig(agents_png)
        plt.clf()
    else:
        agents_png = None

    return disk_png, ingest_png, agents_png

def make_projection(df, days_forward=180):
    try:
        if len(df) < 2:
            return None
        first = df.iloc[0]['var_gb']
        last = df.iloc[-1]['var_gb']
        days = (df.iloc[-1]['date'] - df.iloc[0]['date']).days or 1
        slope = (last - first) / days
        proj = round(last + slope * days_forward,2)
        return proj
    except Exception as e:
        debug_print(f"Projection failed: {e}")
        return None

def render_html(df, latest_row, disk_png, ingest_png, agents_png, proj_180, proj_365):
    ensure_output()
    recent_table_html = df.tail(30).to_html(index=False, classes='table', border=0)
    tmpl = Template(r"""
<html>
<head>
<meta charset="utf-8">
<title>SIEM Server Sizing Report - {{date}}</title>
<style>
/* General page */
body {
    font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
    margin: 20px;
    background-color: #f7f9fb;
    color: #333;
}

/* Headings */
h1, h2, h3 {
    color: #1e3a8a; /* deep blue */
    margin-bottom: 10px;
}

/* Summary cards */
.card {
    background-color: #ffffff;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    padding: 15px;
    margin-bottom: 20px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.05);
}

/* Lists inside cards */
.card ul {
    list-style-type: none;
    padding-left: 0;
}

.card ul li {
    padding: 4px 0;
    border-bottom: 1px solid #e5e7eb;
}

/* Tables */
.table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
}

.table th, .table td {
    border: 1px solid #d1d5db;
    padding: 8px;
    text-align: left;
}

.table th {
    background-color: #1e40af; /* dark blue */
    color: #ffffff;
}

.table tr:nth-child(even) {
    background-color: #f3f4f6;
}

/* Images/Graphs */
img {
    max-width: 100%;
    height: auto;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    margin-top: 10px;
}

/* Footer */
footer {
    margin-top: 30px;
    color: #6b7280;
    font-size: 12px;
    text-align: center;
}
</style>
</head>
<body>
<h1>SIEM Server Sizing Report</h1>
<div class="card">
<strong>Date:</strong> {{date}}<br>
<strong>Agent count:</strong> {{agent_count}}<br>
<strong>Total Agent Logs (GB):</strong> {{agents_log_gb}}<br>
</div>
<div class="card">
<strong>Latest sizes (GB):</strong>
<ul>
{% for k,v in latest.items() %}
  <li>{{k}} : {{v}}</li>
{% endfor %}
</ul>
</div>
<div class="card">
<strong>Projection (linear)</strong>
<ul>
  <li>Projected /var in 180 days: {{proj_180}} GB</li>
  <li>Projected /var in 365 days: {{proj_365}} GB</li>
</ul>
</div>
<h2>Graphs</h2>
<div class="card">
<h3>Disk Growth</h3>
{% if disk_png %}<img src="{{disk_png}}">{% else %}<p>No disk graph</p>{% endif %}
</div>
<div class="card">
<h3>Daily Ingestion</h3>
{% if ingest_png %}<img src="{{ingest_png}}">{% else %}<p>No ingestion graph</p>{% endif %}
</div>
<div class="card">
<h3>Agent Growth</h3>
{% if agents_png %}<img src="{{agents_png}}">{% else %}<p>No agent graph</p>{% endif %}
</div>
<div class="card"> {{ recent_table|safe }} </div>
<footer style="margin-top:20px;color:#666;font-size:12px"><p style="text-align:center; font-size:0.9em; color:gray;">
Wazuh Server Growth & Log Analysis Report by <strong>Krishz</strong> &copy; 2025
</p>
</footer>
</body>
</html>
""")

    html = tmpl.render(
        date=datetime.datetime.now().strftime('%Y-%m-%d'),
        agent_count=int(latest_row.get('agent_count',0)),
        agents_log_gb=latest_row.get('agents_log_gb',0),
        latest={k: latest_row.get(f"{k}_gb",0) for k,_ in TRACK_DIRS},
        disk_png=os.path.basename(disk_png) if disk_png else None,
        ingest_png=os.path.basename(ingest_png) if ingest_png else None,
        agents_png=os.path.basename(agents_png) if agents_png else None,
        recent_table=recent_table_html,
        proj_180=proj_180 or 'N/A',
        proj_365=proj_365 or 'N/A'
    )

    with open(HTML_FILE, 'w') as f:
        f.write(html)
    debug_print(f"HTML report written: {HTML_FILE}")

# ---------- MAIN ----------
def main():
    ensure_output()
    today = datetime.datetime.now().strftime('%Y-%m-%d')

    try:
        token = get_token()
    except Exception as e:
        debug_print(f"Cannot authenticate: {e}")
        token = None

    agents = get_agents(token) if token else []
    agents_log_gb = get_agents_log_size_gb()

    # Collect disk metrics in GB
    metrics = {'date': today}
    for key, path in TRACK_DIRS:
        metrics[f"{key}_gb"] = du_gb(path)
    metrics['agent_count'] = len(agents)
    metrics['agents_log_gb'] = agents_log_gb

    # Append to CSV
    append_csv(metrics)
    debug_print(f"Appended today's metrics to {CSV_FILE}")

    df = read_history()
    if df is None:
        df = pd.DataFrame([metrics])
    else:
        df['date'] = pd.to_datetime(df['date'])

    disk_png, ingest_png, agents_png = generate_graphs(df)
    proj_180 = make_projection(df, 180)
    proj_365 = make_projection(df, 365)
    latest_row = df.iloc[-1].to_dict()

    render_html(df, latest_row, disk_png, ingest_png, agents_png, proj_180, proj_365)
    print(f"Report and charts created in: {OUTPUT_DIR}")

if __name__ == '__main__':
    main()
