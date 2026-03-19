import json
import sqlite3
from pathlib import Path

BASE = Path(__file__).parent
DB_PATH = BASE / "hotzone.db"

FILES = [
    ("config", BASE / "config.json", {}),
    ("whitelist", BASE / "whitelist.json", []),
    ("vouchers", BASE / "vouchers.json", []),
    ("devices", BASE / "devices.json", []),
    ("voucher_codes", BASE / "voucher_codes.json", []),
]

def migrate():
    print(f"🚀 Connecting to SQLite database at {DB_PATH}...")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS records (key TEXT PRIMARY KEY, data TEXT)")
    
    for key, path, default in FILES:
        if path.exists():
            print(f"📦 Migrating {path.name} into SQLite under the '{key}' namespace...")
            with open(path, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = default
                    print(f"  ⚠️ Warning: {path.name} was physically empty or corrupted.")
            conn.execute("INSERT OR REPLACE INTO records (key, data) VALUES (?, ?)", (key, json.dumps(data)))
            
            # Rename the old file so it doesn't cause confusion
            path.rename(path.with_suffix(".json.bak"))
            print(f"  ✅ Successfully migrated and archived as {path.name}.bak")
        else:
            print(f"⏭ Skip {path.name} (File not found, skipping cleanly)")
            
    conn.commit()
    conn.close()
    print("🔥 SQLite Migration 100% Complete! Your system is now running on the database.")

if __name__ == "__main__":
    migrate()
