import json
import sqlite3
import os
from pathlib import Path

BASE = Path(__file__).parent
DB_PATH = BASE / "hotzone.db"

config_path = BASE / "config.json.bak"
whitelist_path = BASE / "whitelist.json.bak"
vouchers_path = BASE / "vouchers.json.bak"
devices_path = BASE / "devices.json.bak"
voucher_codes_path = BASE / "voucher_codes.json.bak"


def read_json(path, default):
    # Fallback to .json if .json.bak isn't found
    if not path.exists():
        path = path.with_suffix("")
    if path.exists():
        try:
            with open(path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return default
    return default


def migrate():
    print("🚀 Connecting to hotzone.db...")
    conn = sqlite3.connect(DB_PATH)
    
    config_data = read_json(config_path, {})
    conn.execute("DELETE FROM config")
    conn.executemany("INSERT INTO config (key, value) VALUES (?, ?)", [(k, str(v)) for k, v in config_data.items()])
    print(f"✅ Migrated config: {len(config_data)} configuration keys to relational columns.")
    
    whitelist_data = read_json(whitelist_path, [])
    conn.execute("DELETE FROM whitelist")
    conn.executemany("INSERT INTO whitelist (mac, hostname, label) VALUES (?, ?, ?)", 
                     [(i.get("mac",""), i.get("hostname",""), i.get("label","")) for i in whitelist_data])
    print(f"✅ Migrated whitelist: {len(whitelist_data)} allowed MAC records.")
    
    vouchers_data = read_json(vouchers_path, [])
    conn.execute("DELETE FROM vouchers")
    conn.executemany("INSERT INTO vouchers (id, reference, mac, hostname, ip, phone, amount, currency, status, created, expires) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     [(i.get("id"), i.get("reference"), i.get("mac"), i.get("hostname"), i.get("ip"), i.get("phone"), i.get("amount"), i.get("currency"), i.get("status"), i.get("created"), i.get("expires")) for i in vouchers_data])
    print(f"✅ Migrated vouchers: {len(vouchers_data)} generated voucher records.")
    
    devices_data = read_json(devices_path, [])
    conn.execute("DELETE FROM devices")
    conn.executemany("INSERT INTO devices (mac, hostname, ip, status, voucher_id, expires) VALUES (?, ?, ?, ?, ?, ?)",
                     [(i.get("mac"), i.get("hostname"), i.get("ip"), i.get("status"), i.get("voucher_id"), i.get("expires")) for i in devices_data])
    print(f"✅ Migrated devices: {len(devices_data)} active connection devices.")
    
    codes_data = read_json(voucher_codes_path, [])
    conn.execute("DELETE FROM voucher_codes")
    conn.executemany("INSERT INTO voucher_codes (code, label, amount, duration_hours, status, created, used_by, used_at, qr_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     [(i.get("code"), i.get("label"), i.get("amount"), i.get("duration_hours"), i.get("status"), i.get("created"), i.get("used_by"), i.get("used_at"), i.get("qr_url")) for i in codes_data])
    print(f"✅ Migrated voucher codes: {len(codes_data)} static offline codes.")
    
    # Clean up the old un-normalized wrapper table completely
    try:
        conn.execute("DROP TABLE records")
        print("🗑️  Cleaned up and deleted legacy NoSQL 'records' table!")
    except sqlite3.OperationalError:
        pass
        
    conn.commit()
    conn.close()
    print("🔥 Relational Database Mapping 100% Successful!")

if __name__ == "__main__":
    migrate()
