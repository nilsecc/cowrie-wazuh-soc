#!/var/ossec/framework/python/bin/python3

import sys
import json
import sqlite3
import time
import traceback

try:
    import requests
except Exception:
    sys.stderr.write("custom-abuseipdb: no se pudo importar 'requests'\n")
    sys.exit(1)

# HERE!!! use your API KEYS
ABUSEIPDB_API_KEY = ""
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""

DB_PATH = "/var/ossec/integrations/data/iocs.db"


def log(msg):
    sys.stderr.write(f"custom-abuseipdb: {msg}\n")
    sys.stderr.flush()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ips_analizadas (
            ip TEXT PRIMARY KEY,
            abuse_score INTEGER,
            total_reports INTEGER,
            country_code TEXT,
            isp TEXT,
            usage_type TEXT,
            first_seen TEXT,
            last_seen TEXT,
            veces_visto INTEGER DEFAULT 1
        )
        """
    )
    conn.commit()
    return conn

def ip_ya_analizada(conn, ip):
    cur = conn.execute("SELECT ip FROM ips_analizadas WHERE ip = ?", (ip,))
    return cur.fetchone() is not None

def actualizar_vista(conn, ip):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    conn.execute(
        "UPDATE ips_analizadas SET last_seen = ?, veces_visto = veces_visto + 1 WHERE ip = ?",
        (now, ip),
    )
    conn.commit()

def guardar_ip(conn, ip, data):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    conn.execute(
        """
        INSERT INTO ips_analizadas
            (ip, abuse_score, total_reports, country_code, isp, usage_type, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ip,
            data.get("abuseConfidenceScore"),
            data.get("totalReports"),
            data.get("countryCode"),
            data.get("isp"),
            data.get("usageType"),
            now,
            now,
        ),
    )
    conn.commit()

def consultar_abuseipdb(ip):
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {})
    except requests.RequestException as e:
        log(f"Error checking in AbuseIPDB for {ip}: {e}")
        return {}

def notificar_telegram(mensaje):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        resp = requests.post(
            url,
            json={"chat_id": TELEGRAM_CHAT_ID, "text": mensaje, "parse_mode": "Markdown"},
            timeout=10,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        log(f"Error sending message to Telegram: {e}")


def formatear_mensaje(ip, alert, data):
    username = alert.get("data", {}).get("username", "?")
    password = alert.get("data", {}).get("password", "?")
    score = data.get("abuseConfidenceScore", "N/A")
    reports = data.get("totalReports", "N/A")
    country = data.get("countryCode", "N/A")
    isp = data.get("isp", "N/A")
    usage = data.get("usageType", "N/A")

    return (
        f"*NUEVO ATAQUE - Cowrie Login*\n"
        f"IP: `{ip}`\n"
        f"Pais: {country} | ISP: {isp} | Tipo: {usage}\n"
        f"Credenciales: `{username}` / `{password}`\n"
        f"AbuseIPDB score: *{score}/100* ({reports} reportes)"
    )

def main():
    if len(sys.argv) < 2:
        log("Missing arguments")
        sys.exit(1)

    alert_file_path = sys.argv[1]

    try:
        with open(alert_file_path) as f:
            alert = json.load(f)
    except Exception as e:
        log(f"alert file cannot be parsed: {e}")
        sys.exit(1)

    ip = alert.get("data", {}).get("src_ip")
    if not ip:
        log("not src_ip in alert")
        sys.exit(0)

    conn = init_db()

    try:
        if ip_ya_analizada(conn, ip):
            log(f"{ip} already analized")
            actualizar_vista(conn, ip)
            sys.exit(0)

        log(f"New IP: {ip}")
        data = consultar_abuseipdb(ip)
        guardar_ip(conn, ip, data)

        mensaje = formatear_mensaje(ip, alert, data)
        notificar_telegram(mensaje)
        log(f"Done {ip}")

    except Exception:
        log(f"Unexpected error: {traceback.format_exc()}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
