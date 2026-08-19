"""
Run this on the client's PC to reset the admin PIN.
Usage: python reset_pin.py [new_pin]
Default new PIN: 2004
"""
import sqlite3, sys, os, platform
from pathlib import Path

new_pin = sys.argv[1] if len(sys.argv) > 1 else "2004"

# Find DB — same logic as server.py
if platform.system() == "Windows":
    data_dir = Path(os.environ.get("APPDATA", "")) / "HotZonePro"
else:
    data_dir = Path.home() / ".HotZonePro"

db = data_dir / "hotzone.db"

print(f"DB path : {db}")
print(f"Exists  : {db.exists()}")

if not db.exists():
    # Try next to this script (dev mode path)
    db = Path(__file__).parent / "hotzone.db"
    print(f"Trying  : {db}  exists={db.exists()}")

if not db.exists():
    print("ERROR: hotzone.db not found in either location.")
    input("Press Enter to exit...")
    sys.exit(1)

try:
    with sqlite3.connect(db) as conn:
        # Show current PIN
        row = conn.execute("SELECT value FROM config WHERE key='adminPin'").fetchone()
        print(f"Current PIN in DB: {row[0] if row else '(not set)'}")

        # Upsert new PIN
        conn.execute("DELETE FROM config WHERE key='adminPin'")
        conn.execute("INSERT INTO config (key, value) VALUES ('adminPin', ?)", (new_pin,))
        print(f"PIN reset to: {new_pin}")
except Exception as e:
    print(f"ERROR: {e}")
    input("Press Enter to exit...")
    sys.exit(1)

print("\nDone! Restart HotZone Pro and use the new PIN.")
input("Press Enter to exit...")
