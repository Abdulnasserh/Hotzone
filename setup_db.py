import sqlite3
import json
from pathlib import Path
import os
import sys

# Connect to db
BASE = Path(__file__).parent
DB_PATH = BASE / "hotzone.db"
conn = sqlite3.connect(DB_PATH)

# Create tables
conn.executescript('''
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS whitelist (
    mac TEXT PRIMARY KEY,
    hostname TEXT,
    label TEXT
);

CREATE TABLE IF NOT EXISTS vouchers (
    id TEXT PRIMARY KEY,
    reference TEXT,
    mac TEXT,
    hostname TEXT,
    ip TEXT,
    phone TEXT,
    amount INTEGER,
    currency TEXT,
    status TEXT,
    created TEXT,
    expires TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    hostname TEXT,
    ip TEXT,
    status TEXT,
    voucher_id TEXT,
    expires TEXT
);

CREATE TABLE IF NOT EXISTS voucher_codes (
    code TEXT PRIMARY KEY,
    label TEXT,
    amount INTEGER,
    duration_hours INTEGER,
    status TEXT,
    created TEXT,
    used_by TEXT,
    used_at TEXT,
    qr_url TEXT
);
''')

conn.commit()
conn.close()
print("Relational tables created.")
