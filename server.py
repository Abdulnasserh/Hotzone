import asyncio
from contextlib import asynccontextmanager
import hashlib
import hmac
import io
import json
import logging
from logging.handlers import RotatingFileHandler
import uuid
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
import webbrowser
import threading
import socket
import qrcode
from qrcode.image.styledpil import StyledPilImage

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from router_scraper import scrape_devices, block_device, unblock_device, sync_whitelist_to_router, purge_unauthorized_macs, shutdown_scraper, cleanup as pw_cleanup, disable_whitelist_mode, set_dhcp_dns

import sys
import os
import subprocess
import platform
import re


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    import platform
    BUNDLE_DIR = Path(sys._MEIPASS)
    if platform.system() == "Windows":
        DATA_DIR = Path(os.environ.get("APPDATA", os.path.expanduser("~"))) / "HotZonePro"
    else:
        DATA_DIR = Path(os.path.expanduser("~")) / ".HotZonePro"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
else:
    BUNDLE_DIR = Path(__file__).parent
    DATA_DIR = Path(__file__).parent

DB_PATH = DATA_DIR / "hotzone.db"
STATIC_DIR = BUNDLE_DIR / "static"
ADMIN_PAGE_PATH = BUNDLE_DIR / "hotzone-admin.html"

# ---------------------------------------------------------------------------
# Global Shared Loop for Threads to call Async
# ---------------------------------------------------------------------------
MAIN_LOOP = None

# ---------------------------------------------------------------------------
# Logging (Production Ready)
# ---------------------------------------------------------------------------
log_formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
log_handler = RotatingFileHandler(DATA_DIR / "hotzone.log", maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
log_handler.setFormatter(log_formatter)

class _SafeStreamHandler(logging.StreamHandler):
    """StreamHandler that never crashes on unicode chars (Windows cp1252 console)."""
    def emit(self, record):
        try:
            super().emit(record)
        except Exception:
            pass

logging.basicConfig(level=logging.INFO, handlers=[log_handler, _SafeStreamHandler(sys.stdout)])
logging.getLogger("httpx").setLevel(logging.WARNING) # Silence router API POST logs
logger = logging.getLogger("hotzone")

# ---------------------------------------------------------------------------
# System state — passive until user presses "Washa System"
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# SQLite Relational Database Layer
# ---------------------------------------------------------------------------
import sqlite3
import threading

_db_local = threading.local()

def _get_db():
    if not hasattr(_db_local, "conn"):
        _db_local.conn = sqlite3.connect(DB_PATH, timeout=20.0, check_same_thread=False)
        _db_local.conn.execute("PRAGMA journal_mode=WAL")
        _db_local.conn.execute("PRAGMA synchronous=NORMAL")
        _db_local.conn.execute("PRAGMA temp_store=MEMORY")
        _db_local.conn.execute("PRAGMA cache_size=-64000")
        
        # Initialize relational tables
        _db_local.conn.executescript('''
        CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS whitelist (mac TEXT PRIMARY KEY, hostname TEXT, label TEXT);
        CREATE TABLE IF NOT EXISTS vouchers (id TEXT PRIMARY KEY, reference TEXT, mac TEXT, hostname TEXT, ip TEXT, phone TEXT, amount INTEGER, currency TEXT, status TEXT, created TEXT, expires TEXT);
        CREATE TABLE IF NOT EXISTS devices (mac TEXT PRIMARY KEY, hostname TEXT, ip TEXT, status TEXT, voucher_id TEXT, expires TEXT);
        CREATE TABLE IF NOT EXISTS voucher_codes (code TEXT PRIMARY KEY, label TEXT, amount INTEGER, duration_hours INTEGER, status TEXT, created TEXT, used_by TEXT, used_at TEXT, qr_url TEXT);
        CREATE TABLE IF NOT EXISTS device_nicknames (mac TEXT PRIMARY KEY, nickname TEXT);
        ''')
    return _db_local.conn

def get_config() -> dict:
    try:
        with _get_db() as conn:
            return {r[0]: r[1] for r in conn.execute("SELECT key, value FROM config").fetchall()}
    except Exception:
        return {}

def _write_db(table: str, data: dict): 
    # Legacy generic fallback for simple writes if needed
    pass 

def get_whitelist() -> list:
    try:
        with _get_db() as conn:
            return [{"mac": r[0], "hostname": r[1], "label": r[2]} for r in conn.execute("SELECT mac, hostname, label FROM whitelist").fetchall()]
    except Exception: return []

def get_vouchers() -> list:
    try:
        with _get_db() as conn:
            return [{"id":r[0],"reference":r[1],"mac":r[2],"hostname":r[3],"ip":r[4],"phone":r[5],"amount":r[6],"currency":r[7],"status":r[8],"created":r[9],"expires":r[10]} 
                    for r in conn.execute("SELECT id,reference,mac,hostname,ip,phone,amount,currency,status,created,expires FROM vouchers").fetchall()]
    except Exception: return []

def save_vouchers(vlist: list):
    try:
        with _get_db() as conn:
            conn.execute("DELETE FROM vouchers")
            conn.executemany("INSERT INTO vouchers (id,reference,mac,hostname,ip,phone,amount,currency,status,created,expires) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                             [(i.get("id"),i.get("reference"),i.get("mac"),i.get("hostname"),i.get("ip"),i.get("phone"),i.get("amount"),i.get("currency"),i.get("status"),i.get("created"),i.get("expires")) for i in vlist])
    except Exception: pass

def get_devices_store() -> list:
    try:
        with _get_db() as conn:
            return [{"mac":r[0],"hostname":r[1],"ip":r[2],"status":r[3],"voucher_id":r[4],"expires":r[5]} 
                    for r in conn.execute("SELECT mac,hostname,ip,status,voucher_id,expires FROM devices").fetchall()]
    except Exception: return []

def save_devices_store(dlist: list):
    try:
        with _get_db() as conn:
            conn.execute("DELETE FROM devices")
            conn.executemany("INSERT INTO devices (mac,hostname,ip,status,voucher_id,expires) VALUES (?,?,?,?,?,?)",
                             [(i.get("mac"),i.get("hostname"),i.get("ip"),i.get("status"),i.get("voucher_id"),i.get("expires")) for i in dlist])
    except Exception: pass

def get_nicknames() -> dict:
    """Return {MAC_UPPER: nickname} mapping."""
    try:
        with _get_db() as conn:
            return {r[0].upper(): r[1] for r in conn.execute("SELECT mac, nickname FROM device_nicknames").fetchall()}
    except Exception:
        return {}

def save_nickname(mac: str, nickname: str):
    try:
        with _get_db() as conn:
            conn.execute("INSERT OR REPLACE INTO device_nicknames (mac, nickname) VALUES (?, ?)", (mac.upper(), nickname))
    except Exception: pass

def delete_nickname(mac: str):
    try:
        with _get_db() as conn:
            conn.execute("DELETE FROM device_nicknames WHERE mac = ?", (mac.upper(),))
    except Exception: pass

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

_lifespan_lock = threading.Lock()
_lifespan_initialized = False

@asynccontextmanager
async def lifespan(app: FastAPI):
    global MAIN_LOOP, _lifespan_initialized
    
    is_primary = False
    with _lifespan_lock:
        if not _lifespan_initialized:
            _lifespan_initialized = True
            is_primary = True

    if not is_primary:
        # Secondary listener (like HTTPS) just yields and returns
        yield
        return

    MAIN_LOOP = asyncio.get_running_loop()
    logger.info("🔥 HotZone WiFi Voucher Server starting...")

    # Auto-seed config on FIRST run so the system works with zero setup on any
    # machine (esp. fresh Windows installs). Detects the NIC IP & gateway; user
    # only needs to supply the router login (password) in Admin settings.
    try:
        cfg = get_config()
        if not cfg:
            detected = _detect_server_ip()
            gw = _detect_gateway_ip()
            seeds = {
                "routerIp": gw,
                "routerUser": "admin",
                "routerPass": "",
                "serverIp": detected,
                "wifiSSID": "HotZone WiFi",
                "wifiPassword": "",
                "wifiSecurity": "WPA",
                "adminPin": "2004",
                "dailyCutoff": "",
                "unblockPrice": "1000",
            }
            with _get_db() as conn:
                conn.execute("DELETE FROM config")
                conn.executemany("INSERT INTO config (key, value) VALUES (?, ?)",
                                 [(k, str(v)) for k, v in seeds.items()])
            logger.info(f"🌱 Seeded fresh config: routerIp={gw} serverIp={detected}")
    except Exception as e:
        logger.warning(f"Config auto-seed skipped: {e}")

    logger.info("ℹ️ Server passive — press 'Washa System' to enable DNS blocking + router whitelist")

    yield
    logger.info("Shutting down — cleaning up tasks and connections...")
    try:
        if _enforcer_task:
            _enforcer_task.cancel()
        await shutdown_scraper()
        await pw_cleanup()
    except Exception as e:
        logger.debug(f"Cleanup note: {e}")
    await pw_cleanup()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="HotZone WiFi Voucher System", lifespan=lifespan, docs_url=None, redoc_url=None) # Disable docs in production

from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware

# Production middlewares
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# Serve static files (customer page)
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ---------------------------------------------------------------------------
# WebSocket manager
# ---------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self.connections:
                self.connections.remove(ws)


ws_manager = ConnectionManager()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class WhitelistEntry(BaseModel):
    mac: str
    hostname: str
    label: str = ""

class ConfigUpdate(BaseModel):
    routerIp: str | None = None
    routerUser: str | None = None
    routerPass: str | None = None
    serverIp: str | None = None
    wifiSSID: str | None = None
    wifiPassword: str | None = None
    wifiSecurity: str | None = None
    adminPin: str | None = None
    dailyCutoff: str | None = None  # e.g. "08:00" — all vouchers expire at this time daily
    unblockPrice: int | None = None # Price for manual unblocking (default 1000)

class PinRequest(BaseModel):
    pin: str

# ---------------------------------------------------------------------------
# Admin session tokens (simple in-memory set)
# ---------------------------------------------------------------------------
admin_sessions: set[str] = set()
_enforcer_task = None
_instant_block_task = None

# ---------------------------------------------------------------------------
# Routes — Customer page
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def serve_customer_page():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    # Fallback to a basic portal message if index.html is missing
    return HTMLResponse("<h1>Pata Voucher ya WiFi</h1><p>Tafadhali unganisha na WiFi kisha scan QR kulipia.</p>", status_code=200)

@app.get("/admin", response_class=HTMLResponse)
async def serve_admin_page():
    if ADMIN_PAGE_PATH.exists():
        return FileResponse(str(ADMIN_PAGE_PATH))
    return HTMLResponse("<h1>Admin page not found</h1>", status_code=404)


# ---------------------------------------------------------------------------
# Routes — Admin PIN verification
# ---------------------------------------------------------------------------

@app.post("/api/admin/verify-pin")
async def verify_admin_pin(req: PinRequest):
    config = get_config()
    correct_pin = (config.get("adminPin") or "2004").strip()
    # If stored value looks masked or non-numeric, fall back to default
    if correct_pin in ("••••", "****", "", None) or not correct_pin.isdigit():
        correct_pin = "2004"
    if req.pin == correct_pin:
        token = str(uuid.uuid4())
        admin_sessions.add(token)
        return {"success": True, "token": token}
    raise HTTPException(status_code=401, detail="Incorrect PIN")


@app.get("/api/admin/check")
async def check_admin_session(request: Request):
    token = request.headers.get("X-Admin-Token", "")
    if token in admin_sessions:
        return {"authenticated": True}
    raise HTTPException(status_code=401, detail="Not authenticated")



# ---------------------------------------------------------------------------
# Routes — Devices
# ---------------------------------------------------------------------------


@app.get("/api/my-status")
async def my_status(request: Request, voucher_id: str = None):
    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else ""
    
    now = datetime.now()

    # 1. If voucher_id passed, check and auto-update MAC for new MAC rotation!
    if voucher_id:
        vouchers = get_vouchers()
        for v in vouchers:
            if v.get("id") == voucher_id and v.get("status") == "active":
                try:
                    exp_dt = datetime.fromisoformat(v["expires"])
                    if exp_dt > now:
                        mac = await _resolve_mac(client_ip)
                        if mac and mac.upper() != v.get("mac", "").upper():
                            v["mac"] = mac.upper()
                            v["ip"] = client_ip
                            save_vouchers(vouchers)
                            await unblock_device(mac)
                        return {"active": True, "expires": v["expires"]}
                except Exception:
                    pass

    # 2. Try resolving MAC for this IP
    mac = await _resolve_mac(client_ip)
    if mac:
        for v in get_vouchers():
            if v.get("mac", "").upper() == mac.upper() and v.get("status") == "active":
                try:
                    exp_dt = datetime.fromisoformat(v["expires"])
                    if exp_dt > now:
                        return {"active": True, "expires": v["expires"]}
                except (ValueError, KeyError):
                    pass
        for w in get_whitelist():
            if w["mac"].upper() == mac.upper():
                return {"active": True, "expires": None}
    
    # 3. Fallback: check by IP in devices list
    for d in get_devices_store():
        if d.get("ip") == client_ip and d.get("status") == "active":
            expires = d.get("expires")
            if expires:
                try:
                    if datetime.fromisoformat(expires) > now:
                        return {"active": True, "expires": expires}
                except ValueError:
                    pass
    return {"active": False}

# ---------------------------------------------------------------------------
# Network helpers — detect server IP, MAC, gateway
# ---------------------------------------------------------------------------

def _get_primary_iface() -> str:
    try:
        r = subprocess.run(["route", "get", "default"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            if "interface:" in line:
                return line.split()[-1]
    except Exception:
        pass
    return "en0"

def _detect_server_ip() -> str:
    """Auto-detect this machine's primary LAN IP — cross-platform."""
    try:
        if platform.system() == "Windows":
            r = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
            for m in re.finditer(r'IPv4 Address[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)', r.stdout):
                ip = m.group(1)
                if not ip.startswith("169.254") and not ip.startswith("127."):
                    return ip
        elif platform.system() == "Darwin":
            r = subprocess.run(["ipconfig", "getifaddr", _get_primary_iface()],
                               capture_output=True, text=True, timeout=3)
            ip = r.stdout.strip()
            if ip and ip.count(".") == 3:
                return ip
            r = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3)
            for m in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)', r.stdout):
                ip = m.group(1)
                if not ip.startswith("169.254") and not ip.startswith("127."):
                    return ip
    except Exception:
        pass
    # Socket trick — works on all platforms
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip.count(".") == 3 and not ip.startswith("169.254"):
            return ip
    except Exception:
        pass
    return ""

def _detect_gateway_ip() -> str:
    """Auto-detect the default gateway IP — cross-platform."""
    try:
        if platform.system() == "Windows":
            r = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
            for m in re.finditer(r'Default Gateway[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)', r.stdout):
                return m.group(1)
        else:
            r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                if "gateway:" in line:
                    return line.split()[-1]
    except Exception:
        pass
    return "192.168.1.1"

def _get_server_ip() -> str:
    """Effective server IP: config value if set, otherwise auto-detect."""
    try:
        cfg = get_config()
        ip = (cfg.get("serverIp") or "").strip()
        if ip and ip.count(".") == 3 and not ip.startswith("0."):
            return ip
    except Exception:
        pass
    return _detect_server_ip()

def _get_server_mac() -> str:
    """Return this machine's primary MAC address."""
    try:
        import uuid as _uuid
        raw = hex(_uuid.getnode())[2:].upper().zfill(12)
        return ":".join(raw[i:i+2] for i in range(0, 12, 2))
    except Exception:
        return ""

def _get_server_macs() -> set:
    """Return all MAC addresses belonging to this machine."""
    macs = set()
    try:
        import uuid as _uuid
        raw = hex(_uuid.getnode())[2:].upper().zfill(12)
        macs.add(":".join(raw[i:i+2] for i in range(0, 12, 2)))
    except Exception:
        pass
    return macs

def _portal_base_url() -> str:
    """http://<server-ip>:8000/"""
    ip = _get_server_ip() or "127.0.0.1"
    return f"http://{ip}:8000/"

# ---------------------------------------------------------------------------
# IP→MAC mapping cache — TTL-based
# ---------------------------------------------------------------------------

_MAC_CACHE_TTL = 30  # seconds — short enough to catch rotation, long enough to not hammer router
_ip_to_mac: dict[str, tuple[str, float]] = {}  # ip -> (mac, timestamp)

def _mac_cache_get(ip: str) -> str | None:
    entry = _ip_to_mac.get(ip)
    if entry and (time.time() - entry[1]) < _MAC_CACHE_TTL:
        return entry[0]
    if entry:
        del _ip_to_mac[ip]  # expired — remove so next lookup goes fresh to router
    return None

def _mac_cache_set(ip: str, mac: str):
    _ip_to_mac[ip] = (mac, time.time())

async def _resolve_mac(ip: str) -> str | None:
    """Look up a client's MAC by IP. Cache expires every 30s so MAC rotation
    (Samsung random MAC on reconnect) is detected within one cache window."""
    cached = _mac_cache_get(ip)
    if cached:
        return cached
    # Always try the router scrape first — it is the authoritative source
    try:
        devices = await scrape_devices()
        for d in devices:
            dmac = d.get("mac", "").upper()
            dip = d.get("ip")
            if dip and dmac:
                _mac_cache_set(dip, dmac)
            if dip == ip and dmac:
                return dmac
    except Exception:
        pass
    # Fallback: devices store (last known state)
    for ds in get_devices_store():
        if ds.get("ip") == ip:
            mac = ds.get("mac", "").upper()
            if mac:
                _mac_cache_set(ip, mac)
                return mac
    return None

@app.get("/api/devices")
async def list_devices():
    whitelist = get_whitelist()
    vouchers = get_vouchers()
    devices_store = get_devices_store()
    nicknames = get_nicknames()
    wl_macs = {w["mac"].upper() for w in whitelist}

    now = datetime.now()
    enriched = []
    seen_macs = set()

    # 1. Build from devices_store (DB source of truth)
    for ds in devices_store:
        mac = ds.get("mac", "").upper()
        if not mac or mac in seen_macs:
            continue
        seen_macs.add(mac)

        entry = {
            "mac": mac,
            "host": ds.get("hostname", "unknown"),
            "ip": ds.get("ip", "—"),
            "status": ds.get("status", "unknown")
        }

        # Inject nickname
        if mac in nicknames:
            entry["nickname"] = nicknames[mac]

        # Check for active voucher
        voucher = None
        for v in vouchers:
            if v.get("mac", "").upper() == mac and v.get("status") == "active":
                voucher = v
                break

        if voucher:
            try:
                exp = datetime.fromisoformat(voucher["expires"])
                if exp > now:
                    entry["expires"] = voucher["expires"]
                    entry["voucher_id"] = voucher["id"]
                    entry["time_remaining"] = int((exp - now).total_seconds())
                    entry["status"] = "active"
                else:
                    entry["voucher_id"] = voucher["id"]
                    entry["status"] = "expired"
            except ValueError:
                pass

        # Override with whitelist status
        if mac in wl_macs:
            entry["status"] = "whitelisted"

        enriched.append(entry)

    return {"loading": False, "devices": enriched}


@app.post("/api/devices/{mac}/block")
async def block_device_route(mac: str):
    mac_upper = mac.upper()
    whitelist = get_whitelist()
    if any(w["mac"].upper() == mac_upper for w in whitelist):
        raise HTTPException(status_code=403, detail="Cannot block whitelisted device")

    # Terminate any active vouchers for this MAC
    vouchers = get_vouchers()
    v_changed = False
    for v in vouchers:
        if v["mac"].upper() == mac_upper and v["status"] == "active":
            v["status"] = "expired"
            v["expires"] = datetime.now().isoformat()
            v_changed = True
    if v_changed:
        save_vouchers(vouchers)

    success = await block_device(mac)

    # Update devices store
    devices_store = get_devices_store()
    for ds in devices_store:
        if ds.get("mac", "").upper() == mac.upper():
            ds["status"] = "blocked"
            break
    save_devices_store(devices_store)

    # No need to update cached router devices since we are using dns_seen_devices and devices_store.

    await ws_manager.broadcast({"type": "device_blocked", "mac": mac})
    return {"success": success, "mac": mac}


@app.post("/api/devices/{mac}/unblock")
async def unblock_device_route(mac: str):
    mac_upper = mac.upper()
    vouchers = get_vouchers()
    now = datetime.now()
    
    # Check if there is already an active voucher
    has_active = any(v["mac"].upper() == mac_upper and v["status"] == "active" for v in vouchers)
    
    if not has_active:
        # Look up the actual hostname from the devices store
        actual_hostname = ""
        devices_store = get_devices_store()
        for ds in devices_store:
            if ds.get("mac", "").upper() == mac_upper:
                actual_hostname = ds.get("hostname", "")
                break
        if not actual_hostname:
            actual_hostname = "Kifaa (" + mac_upper[-5:] + ")"

        # Create a 24h manual bypass voucher so the background worker doesn't instantly re-block it!
        expires = now + timedelta(hours=24)
        
        # Adjust default time according to daily cutoff if configured
        config = get_config()
        cutoff = config.get("dailyCutoff", "")
        if cutoff:
            try:
                ch, cm = map(int, cutoff.split(":"))
                next_cutoff = now.replace(hour=ch, minute=cm, second=0, microsecond=0)
                if next_cutoff <= now:
                    next_cutoff += timedelta(days=1)
                if expires > next_cutoff:
                    expires = next_cutoff
            except Exception:
                pass

        vid = str(uuid.uuid4())[:8]
        config = get_config()
        price = int(config.get("unblockPrice", 1000))

        vouchers.append({
            "id": vid,
            "reference": "MANUAL-BYPASS",
            "mac": mac_upper,
            "hostname": actual_hostname,
            "ip": "",
            "phone": "ADMIN",
            "amount": price,
            "currency": "TZS",
            "status": "active",
            "created": now.isoformat(),
            "expires": expires.isoformat()
        })
        save_vouchers(vouchers)

    success = await unblock_device(mac)

    devices_store = get_devices_store()
    for ds in devices_store:
        if ds.get("mac", "").upper() == mac_upper:
            ds["status"] = "active"
            break
    save_devices_store(devices_store)

    await ws_manager.broadcast({"type": "device_unblocked", "mac": mac})
    return {"success": success, "mac": mac}

# ---------------------------------------------------------------------------
# Routes — Device Nicknames (custom names for MACs)
# ---------------------------------------------------------------------------

@app.get("/api/device-nicknames")
async def get_all_nicknames():
    return get_nicknames()

class NicknameRequest(BaseModel):
    nickname: str

@app.post("/api/device-nicknames/{mac}")
async def set_device_nickname(mac: str, req: NicknameRequest):
    nickname = req.nickname.strip()
    if not nickname:
        delete_nickname(mac)
        return {"status": "removed", "mac": mac.upper()}
    save_nickname(mac, nickname)
    await ws_manager.broadcast({"type": "nicknames_updated"})
    return {"status": "saved", "mac": mac.upper(), "nickname": nickname}

@app.delete("/api/device-nicknames/{mac}")
async def remove_device_nickname(mac: str):
    delete_nickname(mac)
    await ws_manager.broadcast({"type": "nicknames_updated"})
    return {"status": "removed", "mac": mac.upper()}

# ---------------------------------------------------------------------------
# Routes — Whitelist
# ---------------------------------------------------------------------------

@app.get("/api/whitelist")
async def get_whitelist_route():
    wl = get_whitelist()
    nick = get_nicknames()
    for w in wl:
        m = w["mac"].upper()
        if m in nick:
            w["nickname"] = nick[m]
    return wl


@app.post("/api/whitelist")
async def add_whitelist(entry: WhitelistEntry):
    wl = get_whitelist()
    
    # Actively unblock on the router and refresh DNS blocker
    asyncio.create_task(unblock_device(entry.mac))

    # Clear any explicit UI blocks in the devices_store
    devices_store = get_devices_store()
    ds_changed = False
    for ds in devices_store:
        if ds.get("mac", "").upper() == entry.mac.upper():
            if ds.get("status") == "blocked":
                ds["status"] = "active"
                ds_changed = True
    if ds_changed:
        save_devices_store(devices_store)
        
    # Check if already present
    for w in wl:
        if w["mac"].upper() == entry.mac.upper():
            w["hostname"] = entry.hostname
            w["label"] = entry.label
            try:
                with _get_db() as conn:
                    conn.execute("DELETE FROM whitelist")
                    conn.executemany("INSERT INTO whitelist (mac, hostname, label) VALUES (?, ?, ?)", 
                             [(i.get("mac",""), i.get("hostname",""), i.get("label","")) for i in wl])
            except Exception: pass
            
            # Also sync the hostname to the global nickname system
            if entry.hostname:
                save_nickname(entry.mac.upper(), entry.hostname)
                asyncio.create_task(ws_manager.broadcast({"type": "nicknames_updated"}))

            return {"status": "updated", "entry": w}

    new_entry = {"mac": entry.mac.upper(), "hostname": entry.hostname, "label": entry.label}
    wl.append(new_entry)
    try:
        with _get_db() as conn:
            conn.execute("DELETE FROM whitelist")
            conn.executemany("INSERT INTO whitelist (mac, hostname, label) VALUES (?, ?, ?)", 
                             [(i.get("mac",""), i.get("hostname",""), i.get("label","")) for i in wl])
    except Exception: pass
    
    # Also sync the hostname to the global nickname system
    if entry.hostname:
        save_nickname(entry.mac.upper(), entry.hostname)
        asyncio.create_task(ws_manager.broadcast({"type": "nicknames_updated"}))

    await ws_manager.broadcast({"type": "whitelist_updated", "whitelist": wl})
    return {"status": "added", "entry": new_entry}


@app.delete("/api/whitelist/{mac}")
async def remove_whitelist(mac: str):
    wl = get_whitelist()
    wl = [w for w in wl if w["mac"].upper() != mac.upper()]
    try:
        with _get_db() as conn:
            conn.execute("DELETE FROM whitelist")
            conn.executemany("INSERT INTO whitelist (mac, hostname, label) VALUES (?, ?, ?)", 
                             [(i.get("mac",""), i.get("hostname",""), i.get("label","")) for i in wl])
    except Exception: pass
    # Also block on the router
    asyncio.create_task(block_device(mac))
    await ws_manager.broadcast({"type": "whitelist_updated", "whitelist": wl})
    return {"status": "removed"}

# ---------------------------------------------------------------------------
# Routes — Config
# ---------------------------------------------------------------------------

@app.get("/api/config")
async def get_config_route():
    config = get_config()
    # Mask sensitive values
    safe = {**config}
    if safe.get("routerPass"):
        safe["routerPass"] = "••••••••"
    if safe.get("wifiPassword"):
        safe["wifiPassword"] = "••••••••"
    if safe.get("adminPin"):
        safe["adminPin"] = "••••"
    return safe


@app.post("/api/config")
async def update_config(update: ConfigUpdate):
    config = get_config()
    for key, val in update.dict(exclude_none=True).items():
        sval = str(val).strip()
        if sval in ("••••••••", "••••", "****", "********"):
            continue  # Ignore dummy masked placeholder strings
        config[key] = sval
    try:
        with _get_db() as conn:
            conn.execute("DELETE FROM config")
            conn.executemany("INSERT INTO config (key, value) VALUES (?, ?)", [(k, v) for k, v in config.items()])
    except Exception: pass
    await ws_manager.broadcast({"type": "config_updated"})
    return {"status": "ok"}

# ---------------------------------------------------------------------------
# Routes — Config (raw — for admin page to load full values)
# ---------------------------------------------------------------------------

@app.get("/api/config/raw")
async def get_config_raw():
    return get_config()

# ---------------------------------------------------------------------------
# Routes — Vouchers
# ---------------------------------------------------------------------------

@app.get("/api/vouchers")
async def list_vouchers():
    vouchers = get_vouchers()
    now = datetime.now()
    for v in vouchers:
        if v.get("status") == "active":
            exp = datetime.fromisoformat(v["expires"])
            if exp <= now:
                v["status"] = "expired"
            else:
                v["time_remaining"] = int((exp - now).total_seconds())
    return vouchers

# ---------------------------------------------------------------------------
# Routes — Revenue
# ---------------------------------------------------------------------------

@app.get("/api/revenue")
async def revenue():
    vouchers = get_vouchers()
    now = datetime.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=now.weekday())  # Monday
    month_start = today_start.replace(day=1)

    paid_vouchers = [v for v in vouchers if v.get("status") in ("active", "expired") and v.get("amount", 0) > 0]

    total_all = sum(v.get("amount", 0) for v in paid_vouchers)
    total_today = sum(
        v.get("amount", 0) for v in paid_vouchers
        if datetime.fromisoformat(v["created"]) >= today_start
    )
    total_week = sum(
        v.get("amount", 0) for v in paid_vouchers
        if datetime.fromisoformat(v["created"]) >= week_start
    )
    total_month = sum(
        v.get("amount", 0) for v in paid_vouchers
        if datetime.fromisoformat(v["created"]) >= month_start
    )

    # Peak hours — count vouchers created per hour (0-23) for today
    peak_hours = [0] * 24
    for v in paid_vouchers:
        try:
            created = datetime.fromisoformat(v["created"])
            if created >= today_start:
                peak_hours[created.hour] += 1
        except (KeyError, ValueError):
            pass

    # Daily revenue for last 7 days
    daily_revenue = []
    for i in range(6, -1, -1):
        day = today_start - timedelta(days=i)
        day_end = day + timedelta(days=1)
        day_total = sum(
            v.get("amount", 0) for v in paid_vouchers
            if day <= datetime.fromisoformat(v["created"]) < day_end
        )
        daily_revenue.append({
            "date": day.strftime("%a"),
            "date_full": day.strftime("%Y-%m-%d"),
            "amount": day_total
        })

    # Cutoff time info
    config = get_config()
    cutoff = config.get("dailyCutoff", "")
    next_cutoff_str = ""
    if cutoff:
        try:
            ch, cm = map(int, cutoff.split(":"))
            next_cutoff = now.replace(hour=ch, minute=cm, second=0, microsecond=0)
            if next_cutoff <= now:
                next_cutoff += timedelta(days=1)
            next_cutoff_str = next_cutoff.isoformat()
        except Exception:
            pass

    return {
        "today": total_today,
        "week": total_week,
        "month": total_month,
        "all_time": total_all,
        "currency": "TZS",
        "voucher_count": len(vouchers),
        "active_count": sum(1 for v in vouchers if v.get("status") == "active"),
        "peak_hours": peak_hours,
        "daily_revenue": daily_revenue,
        "daily_cutoff": cutoff,
        "next_cutoff": next_cutoff_str
    }

@app.delete("/api/vouchers/reset-revenue")
async def reset_revenue():
    """Deletes all 'expired' vouchers to reset revenue counter to 0."""
    vouchers = get_vouchers()
    retained_vouchers = [v for v in vouchers if v.get("status") != "expired"]
    save_vouchers(retained_vouchers)
    logger.warning(f"Admin manually cleared historical revenue (deleted {len(vouchers) - len(retained_vouchers)} expired vouchers).")
    return {"status": "success", "message": "Revenue cleared"}

# ---------------------------------------------------------------------------
# Routes — Customer Analytics
# ---------------------------------------------------------------------------

@app.get("/api/analytics/customers")
async def customer_analytics():
    """Aggregate voucher purchases per MAC. Categorize as high/medium/low usage."""
    vouchers = get_vouchers()
    devices_store = get_devices_store()
    
    # Build hostname lookup from devices_store
    hostname_map = {}
    for ds in devices_store:
        mac = ds.get("mac", "").upper()
        hostname_map[mac] = ds.get("hostname", "")
    
    # Only count paid vouchers (amount > 0, exclude manual bypass)
    paid = [v for v in vouchers if v.get("amount", 0) > 0 and v.get("status") in ("active", "expired")]
    
    # Aggregate per MAC
    from collections import defaultdict
    mac_stats = defaultdict(lambda: {"total_purchases": 0, "total_spent": 0, "total_hours": 0, "first_seen": None, "last_seen": None, "hostname": ""})
    
    for v in paid:
        mac = v.get("mac", "").upper()
        if not mac:
            continue
        s = mac_stats[mac]
        s["total_purchases"] += 1
        s["total_spent"] += v.get("amount", 0)
        
        try:
            created = datetime.fromisoformat(v["created"])
            if s["first_seen"] is None or created < s["first_seen"]:
                s["first_seen"] = created
            if s["last_seen"] is None or created > s["last_seen"]:
                s["last_seen"] = created
        except (KeyError, ValueError):
            pass
        
        s["hostname"] = v.get("hostname", "") or hostname_map.get(mac, "")
    
    # Calculate thresholds dynamically
    if not mac_stats:
        return {"customers": [], "summary": {"high": 0, "medium": 0, "low": 0, "total": 0}}
    
    purchase_counts = [s["total_purchases"] for s in mac_stats.values()]
    max_purchases = max(purchase_counts) if purchase_counts else 1
    
    # Tier thresholds: high >= 5, medium 2-4, low 1
    customers = []
    tier_counts = {"high": 0, "medium": 0, "low": 0}
    nicknames = get_nicknames()
    
    for mac, stats in mac_stats.items():
        p = stats["total_purchases"]
        if p >= 5:
            tier = "high"
        elif p >= 2:
            tier = "medium"
        else:
            tier = "low"
        
        tier_counts[tier] += 1
        display_name = nicknames.get(mac, "") or stats["hostname"] or hostname_map.get(mac, f"Kifaa ({mac[-5:]})")
        customers.append({
            "mac": mac,
            "hostname": stats["hostname"] or hostname_map.get(mac, f"Kifaa ({mac[-5:]})"),
            "nickname": nicknames.get(mac, ""),
            "display_name": display_name,
            "total_purchases": p,
            "total_spent": stats["total_spent"],
            "tier": tier,
            "first_seen": stats["first_seen"].isoformat() if stats["first_seen"] else None,
            "last_seen": stats["last_seen"].isoformat() if stats["last_seen"] else None
        })
    
    # Sort by total purchases descending
    customers.sort(key=lambda c: c["total_purchases"], reverse=True)
    
    return {
        "customers": customers,
        "summary": {
            **tier_counts,
            "total": len(customers)
        }
    }

# ---------------------------------------------------------------------------
# Routes — QR Code Generation
# ---------------------------------------------------------------------------

@app.get("/api/qr/connect")
async def qr_connect_image():
    """Generate QR code that auto-joins the WiFi network (Step 1: Scan to Connect).
    Uses the standard WIFI: QR format that phones auto-recognize.
    """
    config = get_config()
    ssid = config.get("wifiSSID", "HotZone WiFi")
    password = config.get("wifiPassword", "")
    security = config.get("wifiSecurity", "WPA")  # WPA, WEP, or nopass

    # Escape special characters in SSID and password for WiFi QR format
    def _escape_wifi(s: str) -> str:
        return s.replace('\\', '\\\\').replace('"', '\\"').replace(';', '\\;').replace(',', '\\,').replace(':', '\\:')

    if password:
        wifi_string = f"WIFI:T:{security};S:{_escape_wifi(ssid)};P:{_escape_wifi(password)};;"
    else:
        wifi_string = f"WIFI:T:nopass;S:{_escape_wifi(ssid)};;"

    img_bytes = _generate_qr(wifi_string)
    return StreamingResponse(img_bytes, media_type="image/png")


@app.get("/api/qr/portal")
async def qr_portal_image():
    """Generate QR code that opens the payment portal (Step 2: Scan to Pay)."""
    url = _portal_base_url()

    img_bytes = _generate_qr(url)
    return StreamingResponse(img_bytes, media_type="image/png")


@app.get("/api/qr/pay/{voucher_code}")
async def qr_pay_image(voucher_code: str):
    """Generate QR code for a specific voucher code (scan to pay for this voucher)."""
    url = f"{_portal_base_url()}?code={voucher_code}"

    img_bytes = _generate_qr(url)
    return StreamingResponse(img_bytes, media_type="image/png")


@app.get("/api/qr/voucher/{voucher_code}")
async def qr_voucher_image(voucher_code: str):
    """Generate generic QR for a voucher code string."""
    img_bytes = _generate_qr(voucher_code)
    return StreamingResponse(img_bytes, media_type="image/png")


def _generate_qr(data: str) -> io.BytesIO:
    """Generate a QR code PNG image and return as BytesIO."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#1a1a2e", back_color="white")
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# Routes — Voucher Codes (admin creates codes for scan-to-pay)
# ---------------------------------------------------------------------------



def get_voucher_codes() -> list:
    try:
        with _get_db() as conn:
            rows = conn.execute("SELECT code, label, amount, duration_hours, status, created, used_by, used_at, qr_url FROM voucher_codes").fetchall()
            return [{"code":r[0], "label":r[1], "amount":r[2], "duration_hours":r[3], "status":r[4], "created":r[5], "used_by":r[6], "used_at":r[7], "qr_url":r[8]} for r in rows]
    except Exception: return []

def save_voucher_codes(clist: list):
    try:
        with _get_db() as conn:
            conn.execute("DELETE FROM voucher_codes")
            conn.executemany("INSERT INTO voucher_codes (code, label, amount, duration_hours, status, created, used_by, used_at, qr_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                             [(i.get("code"), i.get("label"), i.get("amount"), i.get("duration_hours"), i.get("status"), i.get("created"), i.get("used_by"), i.get("used_at"), i.get("qr_url")) for i in clist])
    except Exception: pass


class VoucherCodeCreate(BaseModel):
    label: str = ""
    amount: int = 1000
    duration_hours: int = 24
    quantity: int = 1


@app.post("/api/voucher-codes")
async def create_voucher_codes(req: VoucherCodeCreate):
    """Admin creates voucher codes. Each code is a unique string that
    a customer can scan to go directly to the payment page with pre-filled info."""
    config = get_config()
    codes = get_voucher_codes()
    created = []

    for _ in range(req.quantity):
        code = str(uuid.uuid4())[:8].upper()
        entry = {
            "code": code,
            "label": req.label or f"WiFi {req.duration_hours}h",
            "amount": req.amount,
            "duration_hours": req.duration_hours,
            "status": "unused",
            "created": datetime.now().isoformat(),
            "used_by": None,
            "used_at": None,
            "qr_url": f"{_portal_base_url()}?code={code}"
        }
        codes.append(entry)
        created.append(entry)

    save_voucher_codes(codes)
    await ws_manager.broadcast({"type": "voucher_codes_updated"})
    return {"status": "ok", "count": len(created), "codes": created}


@app.get("/api/voucher-codes")
async def list_voucher_codes():
    return get_voucher_codes()


@app.delete("/api/voucher-codes/{code}")
async def delete_voucher_code(code: str):
    codes = get_voucher_codes()
    codes = [c for c in codes if c["code"] != code.upper()]
    save_voucher_codes(codes)
    await ws_manager.broadcast({"type": "voucher_codes_updated"})
    return {"status": "removed"}


@app.get("/api/voucher-codes/{code}/validate")
async def validate_voucher_code(code: str):
    """Customer validates a voucher code before paying."""
    codes = get_voucher_codes()
    for c in codes:
        if c["code"] == code.upper():
            if c["status"] == "unused":
                return {"valid": True, "code": c}
            else:
                return {"valid": False, "reason": "already_used", "code": c}
    return {"valid": False, "reason": "not_found"}

class RedeemRequest(BaseModel):
    code: str

@app.post("/api/voucher-codes/redeem")
async def redeem_voucher_code(req: RedeemRequest, request: Request):
    """Customer redeems a physical voucher code to gain internet access."""
    code_str = req.code.upper().strip()
    codes = get_voucher_codes()
    target_code = None
    for c in codes:
        if c["code"] == code_str:
            target_code = c
            break

    if not target_code:
        raise HTTPException(status_code=404, detail="Invalid voucher code.")

    if target_code.get("status") != "unused":
        raise HTTPException(status_code=400, detail="This voucher code has already been used.")

    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "unknown"

    mac = await _resolve_mac(client_ip)
    if not mac:
        logger.error(f"Redeem failed: No MAC found for IP {client_ip}")
        raise HTTPException(status_code=400, detail="Could not identify your device. Please ensure you are connected directly to the WiFi.")
    
    hostname = "unknown"
    for ds in get_devices_store():
        if ds.get("mac", "").upper() == mac:
            hostname = ds.get("hostname", "unknown")
            break
    
    # Check if already whitelisted
    whitelist = get_whitelist()
    if any(w["mac"].upper() == mac for w in whitelist):
        return {"status": "success", "message": "Your device is already permanently granted access."}

    # Mark voucher code as used
    target_code["status"] = "used"
    target_code["used_by"] = mac
    target_code["used_at"] = datetime.now().isoformat()
    save_voucher_codes(codes)

    # Issue an active internet session (Voucher)
    now = datetime.now()
    duration_hours = target_code.get("duration_hours", 24)
    expires = now + timedelta(hours=duration_hours)

    # Cap expiry to daily cutoff time if configured
    config = get_config()
    cutoff = config.get("dailyCutoff", "")
    if cutoff:
        try:
            ch, cm = map(int, cutoff.split(":"))
            next_cutoff = now.replace(hour=ch, minute=cm, second=0, microsecond=0)
            if next_cutoff <= now:
                next_cutoff += timedelta(days=1)
            if expires > next_cutoff:
                expires = next_cutoff
                logger.info(f"Voucher expiry capped to daily cutoff at {cutoff} → {expires.isoformat()}")
        except Exception as e:
            logger.warning(f"Invalid dailyCutoff format '{cutoff}': {e}")

    vid = str(uuid.uuid4())[:8]
    session_voucher = {
        "id": vid,
        "reference": f"VC-{code_str}",
        "mac": mac,
        "hostname": hostname,
        "ip": client_ip,
        "phone": "VOUCHER-CODE",
        "amount": target_code.get("amount", 0),
        "currency": "TZS",
        "status": "active",
        "created": now.isoformat(),
        "expires": expires.isoformat()
    }

    vouchers = get_vouchers()
    vouchers.append(session_voucher)
    save_vouchers(vouchers)

    # Unblock on the router (adds MAC to CMD 23 filter rules)
    await unblock_device(mac)
    
    # Also refresh DNS blocker cache so device gets internet immediately

    # Update state store
    devices_store = get_devices_store()
    updated = False
    for ds in devices_store:
        if ds.get("mac", "").upper() == mac:
            ds["status"] = "active"
            ds["voucher_id"] = vid
            ds["expires"] = expires.isoformat()
            updated = True
            break
    if not updated:
        devices_store.append({
            "mac": mac,
            "hostname": hostname,
            "ip": client_ip,
            "status": "active",
            "voucher_id": vid,
            "expires": expires.isoformat()
        })
    save_devices_store(devices_store)

    device = {"mac": mac, "host": hostname, "ip": client_ip}
        
    await ws_manager.broadcast({
        "type": "device_unblocked",
        "voucher": session_voucher,
        "device": device
    })
    
    await ws_manager.broadcast({"type": "voucher_codes_updated"})

    logger.info(f"Voucher code {code_str} redeemed successfully by MAC {mac}")
    
    response = JSONResponse({"status": "success", "voucher": session_voucher})
    # Set the identity mirror cookie (expires in 30 days)
    # We sign it with a simple hash for verification
    config = get_config()
    secret = config.get("adminPin", "2004")
    token = f"{vid}:{mac}:{hashlib.sha256((vid + mac + secret).encode()).hexdigest()[:16]}"
    response.set_cookie(key="hotzone_session", value=token, max_age=30*24*3600, httponly=True)
    
    return response

_log_buffer = []
_log_handler = None

class _BufferHandler(logging.Handler):
    def emit(self, record):
        _log_buffer.append(self.format(record))
        if len(_log_buffer) > 200:
            _log_buffer.pop(0)

def _setup_log_buffer():
    global _log_handler
    if _log_handler is None:
        _log_handler = _BufferHandler()
        _log_handler.setFormatter(log_formatter)
        logging.getLogger().addHandler(_log_handler)

_setup_log_buffer()

@app.get("/api/logs")
async def get_logs():
    """Return recent server logs for admin debugging."""
    return {"logs": list(reversed(_log_buffer[-50:]))}

@app.get("/api/router/test")
async def router_test():
    """Test router connection with full diagnostics — helps debug wrong IP/password."""
    config = get_config()
    router_ip = config.get("routerIp", "192.168.1.1")
    router_user = config.get("routerUser", "admin")
    router_pass = config.get("routerPass", "")
    result = {
        "router_ip": router_ip,
        "router_user": router_user,
        "ping": False,
        "login": False,
        "devices": 0,
        "error": None
    }
    # Step 1: Can we reach the router at all?
    import httpx as _httpx
    try:
        async with _httpx.AsyncClient(base_url=f"http://{router_ip}", timeout=5.0, verify=False) as c:
            r = await c.get("/")
            result["ping"] = r.status_code < 500
    except Exception as e:
        result["error"] = f"Cannot reach router at {router_ip}: {str(e)}"
        return result
    # Step 2: Try login
    try:
        from router_scraper import scrape_devices, shutdown_scraper
        import router_scraper as rs
        rs._session_id = None  # Force fresh login
        devices = await scrape_devices()
        result["login"] = True
        result["devices"] = len(devices)
    except Exception as e:
        result["error"] = f"Login failed: {str(e)}"
    return result

@app.post("/api/router/restore")
async def router_restore():
    """Emergency: disable all blocking and restore open internet access."""
    try:
        # 1. Stop enforcers
        global _enforcer_task, _instant_block_task
        if _enforcer_task and not _enforcer_task.done():
            _enforcer_task.cancel()
        if _instant_block_task and not _instant_block_task.done():
            _instant_block_task.cancel()
            _instant_block_task = None

        # 2. Restore router to open mode
        ok = await disable_whitelist_mode()

        # 3. Force reset router_scraper session so it re-detects on next call
        import router_scraper as rs
        rs._session_id   = None
        rs._ubus_session = None
        rs._router_type  = None
        rs._client       = None

        return {"status": "ok" if ok else "partial",
                "message": "Router restored to open mode. All blocking disabled."}
    except Exception as e:
        logger.error(f"Emergency restore failed: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/router/reboot")
async def router_reboot():
    """Reboot the router."""
    try:
        config = get_config()
        router_ip = config.get("routerIp", "192.168.1.1")
        import httpx as _httpx

        # Try TYPE_B (ubus) reboot first
        try:
            import router_scraper as rs
            import hashlib

            def sha256(s): return hashlib.sha256(s.encode()).hexdigest().upper()
            headers = {
                "Content-Type": "application/json",
                "Origin":  f"https://{router_ip}",
                "Referer": f"https://{router_ip}/",
            }
            NULL = "00000000000000000000000000000000"
            async with _httpx.AsyncClient(base_url=f"https://{router_ip}",
                                           verify=False, timeout=8.0) as c:
                r = await c.post("/ubus/", headers=headers, json={
                    "jsonrpc":"2.0","id":1,"method":"call",
                    "params":[NULL,"zwrt_web","web_login_info",{}]})
                sault   = r.json()["result"][1]["zte_web_sault"]
                pw      = config.get("routerPass","")
                hashed  = sha256(sha256(pw) + sault)
                r2 = await c.post("/ubus/", headers=headers, json={
                    "jsonrpc":"2.0","id":1,"method":"call",
                    "params":[NULL,"zwrt_web","web_login",{"password":hashed}]})
                session = r2.json()["result"][1]["ubus_rpc_session"]

                # Try common reboot methods
                rebooted = False
                for svc, method in [
                    ("zwrt_router.api", "router_reboot"),
                    ("system", "reboot"),
                    ("zwrt_router.api", "router_restart"),
                ]:
                    r3 = await c.post("/ubus/", headers=headers, json={
                        "jsonrpc":"2.0","id":1,"method":"call",
                        "params":[session, svc, method, {}]})
                    result = r3.json().get("result", [])
                    code = result[0] if isinstance(result, list) else result
                    if code == 0:
                        logger.info(f"Router reboot via {svc}.{method} ✅")
                        rebooted = True
                        break

                if rebooted:
                    return {"status": "ok", "message": "Router rebooting... wait 30 seconds then reconnect WiFi."}
                else:
                    return {"status": "partial", "message": "Reboot command sent but response unclear. Wait 30 seconds."}
        except Exception as e:
            logger.warning(f"TYPE_B reboot failed: {e}")
            return {"status": "error", "message": f"Could not reboot: {e}. Try unplugging the router manually."}

    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/devices/live")
async def live_devices():
    """Get all connected devices with their authorization status."""
    try:
        devices = await scrape_devices()
        now = datetime.now()
        whitelist = get_whitelist()
        vouchers = get_vouchers()
        config = get_config()
        server_ip = _get_server_ip()
        nicknames = {}
        try:
            db = _get_db()
            cur = db.execute("SELECT mac, nickname FROM device_nicknames")
            for row in cur.fetchall():
                nicknames[row[0].upper()] = row[1]
        except Exception:
            pass

        # Build set of authorized MACs
        authorized_macs = {w["mac"].upper() for w in whitelist}
        # The server PC itself always has access (auto-whitelisted to prevent
        # admin lockout) — reflect that in the UI instead of showing "BLOCKED"
        for sm in _get_server_macs():
            authorized_macs.add(sm)
        for v in vouchers:
            if v.get("status") == "active":
                try:
                    if datetime.fromisoformat(v["expires"]) > now:
                        authorized_macs.add(v["mac"].upper())
                except Exception:
                    pass

        result = []
        for d in devices:
            mac = (d.get("mac") or d.get("MacAddress", "")).upper()
            ip = d.get("ip") or d.get("IpAddress", "")
            hostname = d.get("hostname") or d.get("HostName", "")
            is_authorized = mac in authorized_macs
            is_server = (ip == server_ip)
            
            # Update IP→MAC cache (TTL-based)
            if ip and mac:
                _mac_cache_set(ip, mac)

            # Find voucher info if authorized via voucher
            voucher_info = None
            for v in vouchers:
                if v.get("mac", "").upper() == mac and v.get("status") == "active":
                    try:
                        exp = datetime.fromisoformat(v["expires"])
                        if exp > now:
                            remaining = exp - now
                            hours = int(remaining.total_seconds() // 3600)
                            mins = int((remaining.total_seconds() % 3600) // 60)
                            voucher_info = {
                                "expires": v["expires"],
                                "remaining": f"{hours}h {mins}m",
                                "duration": v.get("duration", ""),
                                "price": v.get("price", 0)
                            }
                    except Exception:
                        pass
                    break

            result.append({
                "mac": mac,
                "ip": ip,
                "hostname": hostname,
                "nickname": nicknames.get(mac, ""),
                "authorized": is_authorized,
                "is_server": is_server,
                "voucher": voucher_info,
                "status": "server" if is_server else ("authorized" if is_authorized else "unauthorized")
            })

        # Sort: server first, then authorized, then unauthorized
        result.sort(key=lambda x: (0 if x["is_server"] else 1 if x["authorized"] else 2, x["ip"]))
        
        return {
            "devices": result,
            "total": len(result),
            "authorized_count": sum(1 for d in result if d["authorized"]),
            "unauthorized_count": sum(1 for d in result if not d["authorized"] and not d["is_server"])
        }
    except Exception as e:
        logger.error(f"Live devices error: {e}")
        return {"devices": [], "total": 0, "authorized_count": 0, "unauthorized_count": 0, "error": str(e)}

# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle ping/pong or admin commands
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# ---------------------------------------------------------------------------
# Background task — device monitoring
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# System Control — Washa / Zima System
# ---------------------------------------------------------------------------

@app.post("/api/system/start")
async def system_start():
    """Sync whitelist + active vouchers to router and enable MAC filtering."""
    try:
        whitelist = get_whitelist()
        vouchers  = get_vouchers()
        now       = datetime.now()
        active_macs = {w["mac"].upper() for w in whitelist}

        # Always include server PC's own MAC
        srv_mac = _get_server_mac()
        if srv_mac:
            active_macs.add(srv_mac)

        # Include all currently active (non-expired) voucher MACs
        for v in vouchers:
            if v.get("status") == "active":
                try:
                    if datetime.fromisoformat(v["expires"]) > now:
                        active_macs.add(v["mac"].upper())
                except Exception:
                    pass

        logger.info(f"Washa System: {len(active_macs)} authorized MACs")
        allowed_list = [{"mac": mac} for mac in active_macs]

        # Scrape connected clients so we can immediately DROP unauthorized ones
        try:
            connected = await scrape_devices()
        except Exception:
            connected = []

        ok = await sync_whitelist_to_router(allowed_list, connected)
        if not ok:
            logger.warning("⚠️ Router sync failed")

        global _enforcer_task, _instant_block_task
        if not _enforcer_task or _enforcer_task.done():
            _enforcer_task = asyncio.create_task(expiry_enforcer())
            logger.info("✅ Expiry enforcer started")

        if not _instant_block_task or _instant_block_task.done():
            _instant_block_task = asyncio.create_task(instant_block_enforcer())
            logger.info("✅ Instant block enforcer started (3s interval)")

        status = "ok" if ok else "error"
        return {"status": status, "allowed_count": len(active_macs), "whitelist_empty": len(active_macs) == 0}
    except Exception as e:
        logger.error(f"System start failed: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(e)})


@app.post("/api/system/stop")
async def system_stop():
    """Stop enforcement — cancel enforcers and disable router whitelist mode."""
    global _enforcer_task, _instant_block_task
    if _enforcer_task and not _enforcer_task.done():
        _enforcer_task.cancel()
        _enforcer_task = None
    if _instant_block_task and not _instant_block_task.done():
        _instant_block_task.cancel()
        _instant_block_task = None
    await disable_whitelist_mode()
    return {"status": "stopped"}


@app.get("/api/system/status")
async def system_status():
    """Return whether the expiry enforcer is running."""
    running = bool(_enforcer_task and not _enforcer_task.done())
    return {"running": running}


# ---------------------------------------------------------------------------
# Background task — expiry enforcer (DB-driven, independent of scrape)
# ---------------------------------------------------------------------------
async def expiry_enforcer():
    """
    Every 30s: read vouchers directly from DB and enforce expiry on the router.
    - Active vouchers past their expiry → mark expired + block on router
    - Daily cutoff: at the configured time, mass-expire ALL active vouchers
    This fires independently of the DHCP scrape.
    """
    await asyncio.sleep(10)  # Short initial delay after startup
    _last_cutoff_date = None  # Track which date we last executed the cutoff for
    
    while True:
        try:
            now = datetime.now()
            config = get_config()
            vouchers = get_vouchers()
            changed = False

            # Collect all MACs that MUST be allowed on the router hardware
            verified_active_macs = set()
            try:
                whitelist = get_whitelist()
                for w in whitelist:
                    verified_active_macs.add(w["mac"].upper())
            except Exception: pass

            # ── Daily Cutoff Check ──
            cutoff_str = config.get("dailyCutoff", "")
            if cutoff_str:
                try:
                    ch, cm = map(int, cutoff_str.split(":"))
                    cutoff_today = now.replace(hour=ch, minute=cm, second=0, microsecond=0)
                    cutoff_date_key = cutoff_today.strftime("%Y-%m-%d") + "-" + cutoff_str
                    
                    if _last_cutoff_date is None:
                        # Prevent immediate triggering if we start the server after today's cutoff time
                        if now >= cutoff_today:
                            _last_cutoff_date = cutoff_date_key
                    elif now >= cutoff_today and _last_cutoff_date != cutoff_date_key:
                        _last_cutoff_date = cutoff_date_key
                        active_count = 0
                        for v in vouchers:
                            if v.get("status") == "active":
                                mac = v.get("mac", "").upper()
                                v["status"] = "expired"
                                v["expires"] = now.isoformat()
                                changed = True
                                active_count += 1
                                # NEVER block a permanent-whitelist device — it has
                                # standing access regardless of voucher status
                                if mac and mac not in verified_active_macs:
                                    await block_device(mac)
                                else:
                                    logger.info(f"[cutoff] Skipping block for whitelisted MAC {mac}")
                                
                                devices_store = get_devices_store()
                                for ds in devices_store:
                                    if ds.get("mac", "").upper() == mac:
                                        ds["status"] = "expired"
                                        break
                                save_devices_store(devices_store)
                        
                        if active_count > 0:
                            logger.info(f"🕐 [cutoff] Daily cutoff at {cutoff_str} — expired {active_count} active vouchers")
                            await ws_manager.broadcast({
                                "type": "cutoff_triggered",
                                "time": cutoff_str,
                                "expired_count": active_count
                            })
                except Exception as e:
                    logger.warning(f"Cutoff check error: {e}")

            # ── Normal per-voucher expiry ──
            # Precompute how many ACTIVE vouchers each MAC holds so that a MAC
            # with ≥1 remaining active voucher never gets router-blocked.
            active_voucher_counts: dict[str, int] = {}
            for v in vouchers:
                if v.get("status") == "active":
                    v_mac = v.get("mac", "").upper()
                    active_voucher_counts[v_mac] = active_voucher_counts.get(v_mac, 0) + 1

            for v in vouchers:
                if v.get("status") not in ("active", "expired"):
                    continue
                try:
                    exp = datetime.fromisoformat(v["expires"])
                except (KeyError, ValueError):
                    continue

                if exp <= now:
                    mac = v.get("mac", "").upper()
                    if v["status"] == "active":
                        # NEVER block the server PC itself — admin would lose internet
                        server_macs = _get_server_macs()
                        if mac and mac in server_macs:
                            logger.warning(f"[enforcer] Skipping block for server MAC {mac} (voucher expired but server is protected)")
                            v["status"] = "expired"
                            changed = True
                            continue

                        logger.info(f"[enforcer] Voucher expired for {mac} — removing from router")
                        v["status"] = "expired"
                        changed = True
                        await ws_manager.broadcast({
                            "type": "device_blocked",
                            "mac": mac,
                            "reason": "voucher_expired"
                        })
                        
                        # NEVER block a permanent-whitelist device — it has
                        # standing access regardless of voucher status.
                        # Decrement THIS voucher from the active count, then
                        # keep access only if another active voucher remains.
                        active_voucher_counts[mac] = active_voucher_counts.get(mac, 0) - 1
                        remaining_active = active_voucher_counts.get(mac, 0)
                        if mac and mac not in verified_active_macs and remaining_active <= 0:
                            await block_device(mac)
                        else:
                            logger.info(f"[enforcer] Skipping block for {mac} "
                                        f"(permanent whitelist={mac in verified_active_macs}, "
                                        f"remaining active vouchers={remaining_active})")

                        devices_store = get_devices_store()
                        for ds in devices_store:
                            if ds.get("mac", "").upper() == mac:
                                ds["status"] = "expired"
                                break
                        save_devices_store(devices_store)

            if changed:
                save_vouchers(vouchers)

        except Exception as e:
            logger.error(f"Expiry enforcer error: {e}")

        # Check expiry every 15 seconds for aggressive enforcement
        await asyncio.sleep(15) 

async def instant_block_enforcer():
    """Every 3s: scrape connected clients, immediately DROP any unknown MAC.
    This closes the window where new devices get free internet before paying.
    Authorized = permanent whitelist + active unexpired vouchers + server MAC."""
    await asyncio.sleep(5)  # short initial delay
    while True:
        try:
            now = datetime.now()
            whitelist = get_whitelist()
            vouchers  = get_vouchers()

            auth_macs = {w["mac"].upper() for w in whitelist}
            for sm in _get_server_macs():
                auth_macs.add(sm)
            for v in vouchers:
                if v.get("status") == "active":
                    try:
                        if datetime.fromisoformat(v["expires"]) > now:
                            auth_macs.add(v["mac"].upper())
                    except Exception:
                        pass

            # Scrape currently connected clients
            devices = await scrape_devices()
            for d in devices:
                mac = (d.get("mac") or "").upper()
                if not mac or mac in auth_macs:
                    continue
                # Unknown/unauthorized MAC — block immediately
                await block_device(mac)
                logger.info(f"⚡ Instant block: {mac} ({d.get('hostname','?')}) not authorized")

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug(f"instant_block_enforcer error: {e}")

        await asyncio.sleep(3)


# ---------------------------------------------------------------------------
# Catch-all — serve portal for any unknown path
# ---------------------------------------------------------------------------

@app.api_route("/{path_name:path}", methods=["GET", "HEAD"])
async def catch_all_portal(request: Request, path_name: str):
    if path_name.startswith(("api/", "static/", "ws", "admin")):
        raise HTTPException(status_code=404)
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return HTMLResponse("<h1>HotZone WiFi</h1><p>Ingiza voucher code yako.</p>")

# ---------------------------------------------------------------------------
# Main Entry
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import uvicorn
    import signal
    import os
    import time
    import webbrowser
    import threading
    import platform
    import subprocess
    
    # 1. Cleanup on Ctrl+C before exit
    def _force_exit(sig, frame):
        print("\n🛑 Server stopping... cleaning up...")
        os._exit(0)
    signal.signal(signal.SIGINT, _force_exit)
    signal.signal(signal.SIGTERM, _force_exit)

    # 2. Start Web Portal on port 8000 (stable, no admin rights needed)
    logger.info("🚀 Starting Web Portal on port 8000...")
    _CURRENT_PORT = 8000
    admin_url = "http://127.0.0.1:8000/admin"
    def _open_admin():
        time.sleep(2)
        logger.info(f"🌐 Opening admin: {admin_url}")
        webbrowser.open(admin_url)

    threading.Thread(target=_open_admin, daemon=True).start()
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info", reload=False)
