# Wazuh Server Sizing & Monitoring

This project provides a **server sizing monitoring tool** for Wazuh deployments. It collects disk usage, agent counts, and log ingestion metrics over time, then generates **daily reports** with tables and graphs in HTML format. The goal is to help size Wazuh servers properly based on growth trends.

---

## Features

- Monitors key directories (`/var`, `/var/log`, `/var/lib`, `/var/ossec`, `/root`, `/usr`, `/home`, `/opt`).
- Collects **agent count** from Wazuh API.
- Tracks **daily ingestion** of `/var` to estimate log growth.
- Generates:
  - **CSV file** with historical data
  - **HTML report** with tables and graphs
  - **PNG charts** for disk growth, ingestion, and agent count
- Supports **cron scheduling** with timestamped logs.

---

## Example Outputs

- `server_sizing_master.csv` → All collected metrics in table form.
- `server_sizing_report.html` → Interactive HTML report with graphs.
- Graphs:
  - Disk Growth over time
  - Daily `/var` ingestion
  - Wazuh Agent Count

---

## Setup

1. **Clone the repo:**
   ```bash
   git clone https://github.com/<your-username>/wazuh-server-sizing.git
   cd wazuh-server-sizing
   ```

2. **Install requirements:**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Set up environment file:**
   Create `.env`:
   ```env
   WAZUH_USER=your-username
   WAZUH_PASS=your-password
   ```

   ⚠️ Do not commit `.env` to GitHub.

4. **Run manually:**
   ```bash
   python3 server_sizing_monitor.py
   ```

---

## Automating with Cron

Add the following line with `crontab -e`:

```bash
0 0 * * * /bin/bash -c 'echo "===== Run started: $(date) =====" >> /home/wazuh-user/monitor/server_sizing_cron.log; /usr/bin/python3 /home/wazuh-user/monitor/server_sizing_monitor.py >> /home/wazuh-user/monitor/server_sizing_cron.log 2>&1; echo "===== Run ended: $(date) =====" >> /home/wazuh-user/monitor/server_sizing_cron.log; echo "" >> /home/wazuh-user/monitor/server_sizing_cron.log'
```

This runs the script daily at midnight and logs activity.

---

## Security Notes

- **Never commit your `.env` file** (contains API credentials).
- Add this to `.gitignore`:
  ```gitignore
  .env
  *.csv
  *.html
  *.log
  ```
- Reports and logs contain system details (disk size, ingestion rates, etc.). Keep them private.

---

## License

MIT License
