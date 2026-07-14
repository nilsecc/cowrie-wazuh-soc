#!/var/ossec/framework/python/bin/python3

import sys
import json
import sqlite3
import time
import requests

# TUS API KEYS
VIRUSTOTAL_API_KEY = "" 
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""

DB_PATH = "/var/ossec/integrations/data/vt_hashes.db"

def log(msg):
    sys.stderr.write(f"custom-vt-hash: {msg}\n")
    sys.stderr.flush()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hash_analized (
            hash TEXT PRIMARY KEY,
            malicious_votes INTEGER,
            total_votes INTEGER,
            last_seen TEXT,
            veces_visto INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    return conn

def consultar_virustotal(hash_val):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(url, headers=headers, timeout=10)
        
        if resp.status_code == 404:
            return None 
        
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        return data.get("last_analysis_stats", {})
    except Exception as e:
        log(f"Error consulting VT for {hash_val}: {e}")
        return None

def notificar_telegram(mensaje):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": mensaje, "parse_mode": "Markdown"})

def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    with open(sys.argv[1]) as f:
        alert = json.load(f)

    # Extraer el hash y la IP de la alerta
    file_hash = alert.get("data", {}).get("shasum")
    src_ip = alert.get("data", {}).get("src_ip")
    
    if not file_hash:
        sys.exit(0)

    conn = init_db()
    
    # Comprobar si ya se analizó
    cur = conn.execute("SELECT hash FROM hash_analized WHERE hash = ?", (file_hash,))
    ya_analizado = cur.fetchone() is not None
    
    if ya_analizado:
        conn.execute("UPDATE hash_analized SET veces_visto = veces_visto + 1 WHERE hash = ?", (file_hash,))
        conn.commit()
    else:
        stats = consultar_virustotal(file_hash)
        if stats:
            malicious = stats.get("malicious", 0)
            total = malicious + stats.get("harmless", 0) + stats.get("suspicious", 0)
            
            conn.execute("INSERT INTO hash_analized (hash, malicious_votes, total_votes, last_seen) VALUES (?, ?, ?, ?)",
                         (file_hash, malicious, total, time.strftime("%Y-%m-%dT%H:%M:%S")))
            conn.commit()
            
            # Formateamos el mensaje incluyendo la IP del atacante
            if malicious > 0:
                msg = (f"*VT ALERT*: Malicious hash detected\n"
                       f"*Source IP:* `{src_ip}`\n"
                       f"*Hash:* `{file_hash}`\n"
                       f"*Result:* *{malicious}/{total}* malicious detections.")
                notificar_telegram(msg)
                
    conn.close()

if __name__ == "__main__":
    main()