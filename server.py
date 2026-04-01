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
import qrcode
from qrcode.image.styledpil import StyledPilImage

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from router_scraper import scrape_devices, block_device, unblock_device, sync_whitelist_to_router, purge_unauthorized_macs, shutdown_scraper, cleanup as pw_cleanup

import sys
import os
import socket
from dnslib import DNSRecord, QTYPE, RR, A

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
# Global Speed Cache (Reduces DB load for DNS Queries)
# ---------------------------------------------------------------------------
_AUTH_CACHE = set()  # Set of authorized MAC addresses (UPPER)
_WL_CACHE = set()    # Set of whitelisted MAC addresses (UPPER)
_LAST_CACHE_REFRESH = 0
_LAST_HARDWARE_AUDIT = 0
_discovery_cooldown = {} # {ip: timestamp} to prevent router hammering

# ---------------------------------------------------------------------------
# Global Shared Loop for Threads to call Async
# ---------------------------------------------------------------------------
MAIN_LOOP = None

# ---------------------------------------------------------------------------
# Logging (Production Ready)
# ---------------------------------------------------------------------------
log_formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
log_handler = RotatingFileHandler(DATA_DIR / "hotzone.log", maxBytes=10*1024*1024, backupCount=5)
log_handler.setFormatter(log_formatter)

logging.basicConfig(level=logging.INFO, handlers=[log_handler, logging.StreamHandler(sys.stdout)])
logging.getLogger("httpx").setLevel(logging.WARNING) # Silence router API POST logs
logger = logging.getLogger("hotzone")

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
# Global Shared Loop for Threads to call Async
# ---------------------------------------------------------------------------
MAIN_LOOP = None

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

    # Lightweight startup: just log what's in the DB, no router scraping
    global _initial_scrape_done
    whitelist = get_whitelist()
    wl_macs = {w["mac"].upper() for w in whitelist}
    now = datetime.now()
    vouchers = get_vouchers()
    active_voucher_macs = {
        v["mac"].upper() for v in vouchers
        if v.get("status") == "active"
        and datetime.fromisoformat(v["expires"]) > now
    }
    allowed = wl_macs | active_voucher_macs
    logger.info(f"Startup: allowed MACs (from DB) = {allowed}")
    
    # Enforce Whitelist MAC Filtering on router
    allowed_list = [{"mac": mac} for mac in allowed]
    asyncio.create_task(sync_whitelist_to_router(allowed_list))
    asyncio.create_task(purge_unauthorized_macs(allowed))
    
    # 🛡️ Restore Identity Mirror Grace Table (survives restarts)
    for v in vouchers:
        v_mac = v.get("mac", "").upper()
        v_ip = v.get("ip")
        if v.get("status") == "active" and v_ip and v_mac:
            # Re-seed the grace table with all active voucher IPs
            # This allows the 'Identity Mirror' to catch switches after a restart
            _ip_auth_grace[v_ip] = (v_mac, datetime.now())
    
    _initial_scrape_done = True  # No router scrape needed anymore

    # Only the expiry enforcer runs now (checks DB every 30s, calls router ONLY to block)
    enforcer_task = asyncio.create_task(expiry_enforcer())

    # Start SmartDNS Hijacker (this IS the gatekeeper now)
    dns_server = SmartDNS()
    dns_thread = threading.Thread(target=dns_server.start, daemon=True)
    dns_thread.start()
    app.state.dns_server = dns_server
    logger.info("✅ DNS-based captive portal is the gatekeeper. No constant router polling.")

    yield
    logger.info("Shutting down — cleaning up tasks and connections...")
    try:
        enforcer_task.cancel()
        dns_server.stop()
        await shutdown_scraper()
        await pw_cleanup()
    except Exception as e:
        logger.debug(f"Cleanup note: {e}")
    await pw_cleanup()

def start_dummy_https_server():
    """Start a lightweight dummy TLS server on port 443 to immediately reset connections.
    This forces Android/iOS devices to instantly fallback to HTTP port 80 for captive portal detection."""
    def _dummy_server_loop():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 443))
            sock.listen(100)
            logger.info("🔒 Dummy HTTPS (443) interceptor running (forces instant captive portal HTTP fallback)...")
            while True:
                conn, _ = sock.accept()
                # Immediately close to force an SSL reset, triggering OS fallback
                conn.close()
        except PermissionError:
            logger.warning("Port 443 interceptor needs root/sudo. Proceeding without dummy HTTPS server.")
        except Exception as e:
            logger.debug(f"Port 443 interceptor error: {e}")
            
    threading.Thread(target=_dummy_server_loop, daemon=True).start()

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

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse, HTMLResponse
from fastapi import Request, HTTPException
import uuid

class CaptivePortalMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        host = request.headers.get("host", "").split(":")[0]
        ua = request.headers.get("user-agent", "").lower()
        path = request.url.path
        
        config = get_config()
        server_ip = config.get("serverIp", "192.168.1.162")
        portal_domain = "hotzone.portal"
        
        # 1. Skip middleware for internal app routes AND captive portal detection URLs
        # (Let dedicated handlers send correct OS-specific responses)
        captive_portal_paths = [
            "/generate_204", "/gen_204", "/hotspot-detect.html",
            "/ncsi.txt", "/connecttest.txt", "/success.txt",
            "/success.html", "/check_network_status"
        ]
        if (path.startswith(("/api/", "/static/", "/ws", "/admin")) or
            path in captive_portal_paths or
            host in (server_ip, "localhost", "127.0.0.1", portal_domain)):
            return await call_next(request)

        # 2. Check Authorization Status (The "Anti-Loop" Check)
        dns_server = getattr(request.app.state, "dns_server", None)
        is_authorized = False
        if dns_server:
            is_authorized = dns_server.is_mac_authorized(client_ip)
            
        # 🛡️ IDENTITY MIRROR: Check for session cookie if not authorized via MAC
        if not is_authorized:
            session_cookie = request.cookies.get("hotzone_session")
            if session_cookie and dns_server:
                # Attempt to mirror this session to the new identity
                logger.info(f"🧬 [MIRROR] Unauthorized client {client_ip} has session cookie. Attempting sync...")
                synced_mac = dns_server.sync_from_cookie(session_cookie, client_ip)
                if synced_mac:
                    logger.info(f"✅ [MIRROR] Identity mirrored successfully! New MAC: {synced_mac}")
                    is_authorized = True

            
        # 3. Handle Authorized Devices (DNS Cache Fallback)
        if is_authorized:
            # If an authorized device hits a tracking probe, give it the "all clear" signal
            if path in ["/generate_204", "/gen_204", "/hotspot-detect.html", "/ncsi.txt", "/connecttest.txt", "/success.txt", "/check_network_status"]:
                logger.info(f"✅ [POST-AUTH] Authorized client {client_ip} hit {path}. Returning 204.")
                return Response(status_code=204)
            
            # If they hit us with a regular domain (e.g. google.com) due to old DNS cache
            if host and host not in (server_ip, "localhost", "127.0.0.1", portal_domain):
                logger.info(f"💡 [POST-AUTH] Authorized client {client_ip} hit cached {host}. Showing Success page.")
                return HTMLResponse(content=f"""
                    <html><head><meta name="viewport" content="width=device-width, initial-scale=1">
                    <title>Connected!</title>
                    </head><body style="text-align:center; font-family:sans-serif; padding-top:20%; background:#e8f5e9;">
                        <h1 style="color:#2e7d32;">SUCCESS!</h1>
                        <p>Internet yako sasa iko tayari.</p>
                        <p style="font-size:0.9em; color:#666;">Devices sometimes remember the login page for a few minutes.</p>
                        <a href="http://www.google.com/?refresh={uuid.uuid4()}" style="display:inline-block; padding:15px 30px; background:#2e7d32; color:white; text-decoration:none; border-radius:5px; font-weight:bold;">TUMIA INTERNET</a>
                        <script>setTimeout(()=>{{ window.location.href="http://www.google.com/?ref=hotzone"; }}, 3000);</script>
                    </body></html>
                """, status_code=200)
                
            return await call_next(request)

        # 4. If NOT authorized, apply Captive Portal Hijack
        logger.info(f"🔒 [UNAUTHORIZED] Hijacking {client_ip} ({host}{path})")
        os_check_patterns = [
            "gstatic.com", "google.com", "apple.com", "akamai", 
            "msftconnecttest", "connectivitycheck", "clients3.google.com", 
            "connectivity-check.ubuntu.com", "detectportal.firefox.com"
        ]
        is_os_probe = any(p in host for p in os_check_patterns)
        
        # 2. Aggressive Trigger Response
        logger.info(f"🚩 Captive Portal TRIGGER: {host}{path} (Method: {request.method}, Client: {client_ip})")
        
        headers = {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
            "Connection": "close"
        }
        
        # For pure background "pings", return a high-priority 302 to the raw IP
        if path in ["/generate_204", "/gen_204", "/hotspot-detect.html", "/ncsi.txt", "/connecttest.txt", "/success.txt"]:
            return RedirectResponse(url=f"http://{server_ip}/", status_code=302, headers=headers)
        
        # 3. Interactive 'Wake-up' Page (The "Landing Site" Trick)
        content = f"""
        <!DOCTYPE html>
        <html><head>
        <meta http-equiv="refresh" content="0;url=http://{server_ip}/">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>WiFi Login</title>
        </head><body style="background:#f0f2f5; font-family:sans-serif; text-align:center; padding-top:50px;">
            <div style="background:white; padding:30px; border-radius:10px; display:inline-block; box-shadow:0 2px 10px rgba(0,0,0,0.1);">
                <h2>HotZone WiFi</h2>
                <p>Redirecting to login page...</p>
                <a href="http://{server_ip}/" style="padding:12px 24px; background:#007bff; color:white; text-decoration:none; border-radius:5px; font-weight:bold;">Connect Now</a>
            </div>
            <script>window.location.href="http://{server_ip}/";</script>
        </body></html>
        """
        return HTMLResponse(content=content, status_code=200, headers=headers)
            
        return await call_next(request)

app.add_middleware(CaptivePortalMiddleware)

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

# ---------------------------------------------------------------------------
# OS Captive Portal Detection Routes
# ---------------------------------------------------------------------------

@app.get("/generate_204")
@app.head("/generate_204")
@app.get("/gen_204")
@app.head("/gen_204")
async def handle_android_check(request: Request):
    """Handle Android/Chrome captive portal check."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"📱 [ANDROID] Captive portal check from {client_ip} - Redirecting to portal")
    config = get_config()
    server_ip = config.get("serverIp", "192.168.1.162")
    headers = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }
    # 🛡️ Android 14 Fix: Redirect to IP directly, avoiding second DNS lookup that can fail
    portal_url = f"http://{server_ip}/"
    return RedirectResponse(url=portal_url, status_code=302, headers=headers)

@app.get("/hotspot-detect.html")
async def handle_apple_check(request: Request):
    """Handle Apple captive portal check (captive.apple.com)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"🍎 [APPLE] Captive portal check from {client_ip} - Redirecting to portal")
    config = get_config()
    server_ip = config.get("serverIp", "192.168.1.162")
    headers = {"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"}
    return RedirectResponse(url=f"http://{server_ip}/", status_code=302, headers=headers)

@app.get("/ncsi.txt")
@app.head("/ncsi.txt")
@app.get("/connecttest.txt")
@app.head("/connecttest.txt")
async def handle_windows_check(request: Request):
    """Handle Windows connectivity checks."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"🪟 [WINDOWS] Captive portal check from {client_ip} - Redirecting to portal")
    config = get_config()
    server_ip = config.get("serverIp", "192.168.1.162")
    headers = {"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"}
    return RedirectResponse(url=f"http://{server_ip}/", status_code=302, headers=headers)

@app.get("/success.html")
async def handle_generic_check():
    """Generic success page for some devices."""
    return HTMLResponse("<TITLE>Success</TITLE><body>Connected</body>", status_code=200)

# Additional Android detection endpoint
@app.get("/gen_204")
async def handle_gen_204(request: Request):
    """Alternative Android detection endpoint."""
    return await handle_android_check(request)

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
    correct_pin = config.get("adminPin", "2004")
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
async def my_status(request: Request):
    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else ""
        
    res = await list_devices()
    devices = res.get("devices", [])
    for d in devices:
        if d.get("ip") == client_ip and d.get("status") == "active":
            expires = d.get("expires")
            if expires:
                try:
                    exp_dt = datetime.fromisoformat(expires)
                    if exp_dt > datetime.now():
                        return {"active": True, "expires": expires}
                except ValueError:
                    pass
    return {"active": False}

# ---------------------------------------------------------------------------
# DNS-tracked devices (replaces constant router DHCP polling)
# When a device makes a DNS query, we record its IP here.
# The SmartDNS handler populates this dict.
# ---------------------------------------------------------------------------
_dns_seen_devices = {}  # {ip: {"mac": "...", "last_seen": "...", "hostname": "..."}}
_ip_auth_grace = {}     # {ip: (mac, timestamp)} - Grace period for MAC randomization
_initial_scrape_done = True  # Always ready — no router scrape needed

def dns_track_device(client_ip, mac=None, hostname=None):
    """Called by SmartDNS when a device makes a DNS query."""
    now = datetime.now().isoformat()
    if client_ip not in _dns_seen_devices:
        _dns_seen_devices[client_ip] = {"ip": client_ip, "mac": mac or "", "hostname": hostname or "unknown", "first_seen": now}
    entry = _dns_seen_devices[client_ip]
    entry["last_seen"] = now
    if mac:
        entry["mac"] = mac
        # Also ensure it's in the persistent devices_store (DB)
        devices_store = get_devices_store()
        updated = False
        existing = None
        for ds in devices_store:
            if ds.get("mac", "").upper() == mac.upper():
                existing = ds
                break
        
        if existing:
            if existing.get("ip") != client_ip or (hostname and existing.get("hostname") != hostname):
                existing["ip"] = client_ip
                if hostname and hostname != "unknown":
                    existing["hostname"] = hostname
                existing["last_seen"] = now
                updated = True
        else:
            devices_store.append({
                "mac": mac.upper(),
                "hostname": hostname or "unknown",
                "ip": client_ip,
                "status": "unknown",
                "first_seen": now,
                "last_seen": now
            })
            updated = True
            
        if updated:
            save_devices_store(devices_store)

    if hostname and hostname != "unknown":
        entry["hostname"] = hostname

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

        # Update IP from DNS tracking
        for ip, dns_dev in _dns_seen_devices.items():
            if dns_dev.get("mac", "").upper() == mac:
                entry["ip"] = ip
                break

        enriched.append(entry)

    # 2. Add DNS-seen devices not yet in devices_store
    for ip, dns_dev in _dns_seen_devices.items():
        mac = dns_dev.get("mac", "").upper()
        if mac and mac not in seen_macs:
            seen_macs.add(mac)
            entry = {
                "mac": mac,
                "host": dns_dev.get("hostname", "unknown"),
                "ip": ip,
                "status": "unknown"
            }
            if mac in nicknames:
                entry["nickname"] = nicknames[mac]
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
    
    # Actively unblock on the router
    # Run in the background so the HTTP response returns instantly
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
        config[key] = val
    try:
        with _get_db() as conn:
            conn.execute("DELETE FROM config")
            conn.executemany("INSERT INTO config (key, value) VALUES (?, ?)", [(k, str(v)) for k, v in config.items()])
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
    
    # Build hostname lookup from devices_store and _dns_seen_devices
    hostname_map = {}
    for ds in devices_store:
        mac = ds.get("mac", "").upper()
        hostname_map[mac] = ds.get("hostname", "")
    for ip, dns_dev in _dns_seen_devices.items():
        mac = dns_dev.get("mac", "").upper()
        if mac not in hostname_map or not hostname_map[mac]:
            hostname_map[mac] = dns_dev.get("hostname", "")
    
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
    config = get_config()
    server_ip = config.get("serverIp", "192.168.1.162")
    url = f"http://{server_ip}:8000/"

    img_bytes = _generate_qr(url)
    return StreamingResponse(img_bytes, media_type="image/png")


@app.get("/api/qr/pay/{voucher_code}")
async def qr_pay_image(voucher_code: str):
    """Generate QR code for a specific voucher code (scan to pay for this voucher)."""
    config = get_config()
    server_ip = config.get("serverIp", "192.168.1.162")
    url = f"http://{server_ip}:8000/?code={voucher_code}"

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
    img.save(buf, format="PNG")
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
    server_ip = config.get("serverIp", "192.168.1.162")
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
            "qr_url": f"http://{server_ip}:8000/?code={code}"
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
        # 🛡️ Voucher Repair: If already used, check if this user has the matching session cookie
        session_cookie = request.cookies.get("hotzone_session")
        if session_cookie:
            dns_server = getattr(request.app.state, "dns_server", None)
            if dns_server:
                res = dns_server.sync_from_cookie(session_cookie, client_ip)
                if res:
                    logger.info(f"✨ [REPAIR] Session restored for {client_ip} using already-used code {code_str}")
                    return {"status": "success", "message": "Session restored! You are now connected."}

        raise HTTPException(status_code=400, detail="This voucher code has already been used.")

    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "unknown"

    mac = None
    hostname = "unknown"
    
    # Try to find device in SmartDNS tracker
    dns_dev = _dns_seen_devices.get(client_ip)
    if dns_dev and dns_dev.get("mac"):
        mac = dns_dev.get("mac").upper()
        hostname = dns_dev.get("hostname", "unknown")
    
    if not mac:
        # Fallback to persistent local storage
        devices_store = get_devices_store()
        for ds in devices_store:
            if ds.get("ip") == client_ip:
                mac = ds.get("mac", "").upper()
                hostname = ds.get("hostname", "unknown")
                break
                
    if not mac:
        logger.error(f"Redeem failed: No MAC found for IP {client_ip}")

        raise HTTPException(status_code=400, detail="Could not identify your device. Please ensure you are connected directly to the WiFi.")
    
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

    # Unblock on the router
    await unblock_device(mac)

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
    
    # 🛡️ Track Authorization Grace (Anti-MAC Randomization)
    _ip_auth_grace[client_ip] = (mac, datetime.now())
    
    response = JSONResponse({"status": "success", "voucher": session_voucher})
    # Set the identity mirror cookie (expires in 30 days)
    # We sign it with a simple hash for verification
    config = get_config()
    secret = config.get("adminPin", "2004")
    token = f"{vid}:{mac}:{hashlib.sha256((vid + mac + secret).encode()).hexdigest()[:16]}"
    response.set_cookie(key="hotzone_session", value=token, max_age=30*24*3600, httponly=True)
    
    return response

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
# Background task — expiry enforcer (DB-driven, independent of scrape)
# ---------------------------------------------------------------------------
_LAST_HARDWARE_AUDIT = 0 

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
                                await block_device(mac)
                                
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
            current_active_macs = set()
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
                        logger.info(f"[enforcer] Voucher expired for {mac} — removing from router")
                        v["status"] = "expired"
                        changed = True
                        await ws_manager.broadcast({
                            "type": "device_blocked",
                            "mac": mac,
                            "reason": "voucher_expired"
                        })
                        
                        await block_device(mac)

                        devices_store = get_devices_store()
                        for ds in devices_store:
                            if ds.get("mac", "").upper() == mac:
                                ds["status"] = "expired"
                                break
                        save_devices_store(devices_store)
                elif v["status"] == "active":
                    # If active, ensure it's physically unblocked on router hardware
                    v_mac = v["mac"].upper()
                    verified_active_macs.add(v_mac)
                    current_active_macs.add(v_mac)

            # 🛡️ REFRESH HIGH-SPEED CACHE
            global _AUTH_CACHE, _WL_CACHE
            _AUTH_CACHE = current_active_macs
            _WL_CACHE = {w["mac"].upper() for w in get_whitelist()}

            if changed:
                save_vouchers(vouchers)
            
            # --- Proactive Hardware Verification ---
            # 🛡️ Audit hardware sparingly (every 5 minutes) to protect router memory
            global _LAST_HARDWARE_AUDIT
            if MAIN_LOOP and (time.time() - _LAST_HARDWARE_AUDIT) > 300:
                _LAST_HARDWARE_AUDIT = time.time()
                async def _verify_hardware():
                    try:
                        # Fetch what the router ACTUALLY thinks is allowed
                        hardware_devices = await scrape_devices()
                        router_allowed = {d["mac"].upper() for d in hardware_devices if d.get("router_allowed")}
                        
                        # 1. Verify Active devices are unblocked
                        for mac in verified_active_macs:
                            if mac not in router_allowed:
                                logger.warning(f"🚨 [HARDWARE DESYNC] {mac} is ACTIVE in server but BLOCKED in router hardware! FORCING ACCESS...")
                                await unblock_device(mac)
                        
                        # 2. Verify Blocked devices are NOT allowed
                        for mac in router_allowed:
                            if mac not in verified_active_macs:
                                logger.warning(f"🚨 [HARDWARE DESYNC] {mac} is BLOCKED in server but ALLOWED in router hardware! FORCING BLOCK...")
                                await block_device(mac)
                                
                    except Exception as e:
                        logger.error(f"Hardware sync check failed: {e}")

                asyncio.run_coroutine_threadsafe(_verify_hardware(), MAIN_LOOP)

        except Exception as e:
            logger.error(f"Expiry enforcer error: {e}")

        # Reduce router load: Expiry check every 60s, hardware audit every 5 minutes
        await asyncio.sleep(60) 


# ---------------------------------------------------------------------------
# device_monitor REMOVED — DNS is the gatekeeper now.
# Router API is ONLY called when blocking/unblocking a device.
# The expiry_enforcer (above) handles expired vouchers.
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# SmartDNS Hijacker
# ---------------------------------------------------------------------------

class SmartDNS:
    def __init__(self, listen_ip="0.0.0.0", port=53, upstream="8.8.8.8"):
        self.listen_ip = listen_ip
        self.port = port
        self.upstream = upstream
        self.running = False
        self.udp_sock = None
        self.tcp_sock = None
        self.proxy_sock = None
        self._executor = None

    def start(self):
        try:
            from concurrent.futures import ThreadPoolExecutor
            self._executor = ThreadPoolExecutor(max_workers=30)
            
            # 1. UDP Handler
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.bind((self.listen_ip, self.port))
            self.udp_sock.settimeout(1.0)
            
            # 2. TCP Handler (Critical for modern OS reliability)
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_sock.bind((self.listen_ip, self.port))
            self.tcp_sock.listen(5)
            self.tcp_sock.settimeout(1.0)
            
            # 3. Proxy Handler
            self.proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.proxy_sock.settimeout(1.0) # Faster timeout for mobile responsiveness

            self.running = True
            logger.info(f"📡 SmartDNS Hijacker listening (UDP & TCP) on {self.listen_ip}:{self.port}")
            
            # Start the main UDP loop in a thread
            threading.Thread(target=self._udp_loop, daemon=True).start()
            # Start the main TCP loop in a thread
            threading.Thread(target=self._dns_tcp_loop, daemon=True).start()
            # Start the proactive maintenance loop (MAC Discovery Pulse)
            threading.Thread(target=self._maintenance_loop, daemon=True).start()
            
        except PermissionError:
            logger.error("❌ DNS Permission Error: Port 53 requires sudo privileges.")
        except Exception as e:
            import traceback
            logger.error(f"❌ DNS Start Error: {e}")
            logger.error(traceback.format_exc())

    def _udp_loop(self):
        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(512)
                if self._executor:
                    self._executor.submit(self.handle_query, data, addr, proto="udp")
            except socket.timeout: continue
            except Exception as e:
                if self.running: logger.debug(f"UDP Error: {e}")

    def _dns_tcp_loop(self):
        """Dedicated loop for DNS-over-TCP requests."""
        while self.running:
            try:
                conn, addr = self.tcp_sock.accept()
                if self._executor:
                    self._executor.submit(self.handle_tcp_conn, conn, addr)
            except socket.timeout: continue
            except Exception as e:
                if self.running: logger.debug(f"TCP Error: {e}")

    def _maintenance_loop(self):
        """Proactively refreshes the device table from the router to catch identities early."""
        while self.running:
            try:
                # Every 5 minutes (300s), trigger a global device discovery pulse
                if MAIN_LOOP:
                    asyncio.run_coroutine_threadsafe(self._refresh_all_macs(), MAIN_LOOP)
            except Exception: pass
            time.sleep(300) 

    async def _refresh_all_macs(self):
        """High-level wrapper to refresh all IP mappings."""
        try:
            # We use an arbitrary IP to trigger the global scrape within the existing method
            await self._resolve_mac_from_router("0.0.0.0", silent=True)
        except: pass

    def handle_tcp_conn(self, conn, addr):
        try:
            conn.settimeout(2.0)
            data = conn.recv(1024)
            if len(data) > 2:
                # DNS over TCP sends 2 bytes length first
                query_data = data[2:]
                response = self.handle_query(query_data, addr, proto="tcp", return_only=True)
                if response:
                    # Prepend length for TCP
                    length = len(response)
                    conn.sendall(length.to_bytes(2, byteorder='big') + response)
        except Exception as e:
            logger.debug(f"TCP session error ({addr[0]}): {e}")
        finally:
            conn.close()

    def stop(self):
        self.running = False
        if self._executor:
            self._executor.shutdown(wait=False)
        if self.sock:
            self.sock.close()
        if self.proxy_sock:
            self.proxy_sock.close()

    def handle_query(self, data, addr, proto="udp", return_only=False):
        """Handle incoming DNS queries."""
        client_ip = addr[0]
        try:
            if len(data) < 12: return None
            
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).lower().rstrip('.')
            qtype = request.q.qtype
            
            # Deep Log
            if qtype == QTYPE.A:
                logger.debug(f"🔍 DNS ({proto.upper()}): {client_ip} -> {qname}")
            
            # Check if this IP is actually whitelisted/voucher-active
            is_authorized = self.is_mac_authorized(client_ip)
            
            # Special case: Don't hijack the server itself if checking for updates/etc.
            # but allow hijacking for testing if it's localhost
            if client_ip == "127.0.0.1":
                is_authorized = False # Force hijack locally to test the portal

            if is_authorized:
                # 🚀 Nuclear Triple DNS: Try multiple providers simultaneously
                try:
                    if qtype == QTYPE.AAAA:
                        reply = request.reply()
                        reply.header.rcode = 3 # NXDOMAIN
                    else:
                        proxy_data = self._query_upstream_nuclear(data)
                        if proxy_data:
                            reply = DNSRecord.parse(proxy_data)
                        else:
                            # Fallback if all fail
                            reply = request.reply()
                            reply.header.rcode = 2 # SERVFAIL
                except Exception as e:
                    logger.warning(f"DNS Nuclear Failure for {qname}: {e}")
                    reply = request.reply()
            else:
                # Hijack to Local IP
                config = get_config()
                server_ip = config.get("serverIp", "192.168.1.162")
                portal_domain = "hotzone.portal"
                
                reply = request.reply()
                # 🛡️ Fix for Android 14/15: Set RA/AA flags so OS trusts our hijacked response
                reply.header.ra = 1 
                reply.header.aa = 1
                
                if qtype == QTYPE.A:
                    # Point BOTH the original query AND our local portal domain to our IP
                    reply.add_answer(RR(qname + ".", QTYPE.A, rdata=A(server_ip), ttl=1))
                    if qname != portal_domain:
                        logger.info(f"🛡️ DNS Hijacked: {client_ip} -> {qname} redirected to {server_ip}")
                elif qtype == QTYPE.AAAA:
                    # Returning NXDOMAIN forces the device to use the Hijacked A record (IPv4)
                    # This is CRITICAL for Android 14/15
                    reply.header.rcode = 3 # NXDOMAIN
                
                if self.udp_sock and proto == "udp":
                    self.udp_sock.sendto(reply.pack(), addr)
                
                if return_only:
                    return reply.pack()
                return None

        except Exception as e:
            # Log full traceback if it's a critical error
            if "DNSRecord" in str(e):
                logger.debug(f"DNS Parsing Noise from {client_ip}")
            else:
                logger.error(f"DNS Query Handling Error ({client_ip}): {e}")

    def _get_local_ip(self):
        """Helper to find the best local IP if not configured."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't need to actually connect
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # Cache for mapping IP to MAC on discovery
    _ip_to_mac_lookup = {}
    _pending_lookups = set()

    def is_mac_authorized(self, client_ip):
        """Check if the client IP belongs to an authorized MAC using Cache + DB."""
        # Whitelist the server itself to prevent it from hijacking its own internet/monitoring
        config = get_config()
        server_ip = config.get("serverIp", "")
        local_ip = self._get_local_ip()

        if client_ip in (server_ip, local_ip, "127.0.0.1") and client_ip:
            if client_ip == "127.0.0.1":
                return False
            logger.debug(f"✅ DNS Auth: Server itself ({client_ip}) authorized.")
            return True

        logger.debug(f"🔍 [DNS AUTH] Checking authorization for {client_ip}")

        # 🛡️ Identity Mirror & Grace Period
        grace = _ip_auth_grace.get(client_ip)
        if grace:
            auth_mac, ts = grace
            # If in 5 min grace window
            if (datetime.now() - ts).total_seconds() < 300: 
                # PROACTIVE: If we haven't resolved this IP's MAC in the last 20s, trigger refresh
                now_ts = time.time()
                last_call = _discovery_cooldown.get(client_ip, 0)
                if (now_ts - last_call) > 20 and client_ip not in self._pending_lookups and MAIN_LOOP:
                    _discovery_cooldown[client_ip] = now_ts
                    self._pending_lookups.add(client_ip)
                    asyncio.run_coroutine_threadsafe(self._resolve_mac_from_router(client_ip), MAIN_LOOP)

                # Check if current (possibly newly resolved) MAC differs from redemption MAC
                current_mac = self._ip_to_mac_lookup.get(client_ip)
                if current_mac and current_mac.upper() != auth_mac.upper():
                    new_mac = current_mac.upper()
                    logger.info(f"🔄 [MIRROR] MAC Switch detected on {client_ip}! {auth_mac} -> {new_mac}")
                    
                    vouchers = get_vouchers()
                    source_v = next((v for v in vouchers if v["mac"].upper() == auth_mac.upper() and v["status"] == "active"), None)
                    if source_v:
                        self._sync_voucher_to_new_identity(source_v, new_mac, client_ip)
                    else:
                        # Ensure new identity is enabled on router anyway
                        asyncio.run_coroutine_threadsafe(unblock_device(new_mac), MAIN_LOOP)

                return True
            else:
                try: del _ip_auth_grace[client_ip]
                except: pass

        # Step 1: Check Local Cache for MAC
        mac = self._ip_to_mac_lookup.get(client_ip)
        
        if not mac:
            # Check devices_store (DB) for a previous mapping
            for ds in get_devices_store():
                if ds.get("ip") == client_ip:
                    mac = ds.get("mac", "").upper()
                    self._ip_to_mac_lookup[client_ip] = mac
                    break
        
        if not mac:
            # UNKNOWN IP: Trigger background router API call with 30s cooldown
            now_ts = time.time()
            last_call = _discovery_cooldown.get(client_ip, 0)
            if (now_ts - last_call) > 30 and client_ip not in self._pending_lookups and MAIN_LOOP:
                _discovery_cooldown[client_ip] = now_ts
                logger.debug(f"🔍 DNS Auth: No MAC for {client_ip}, triggering discovery...")
                self._pending_lookups.add(client_ip)
                asyncio.run_coroutine_threadsafe(self._resolve_mac_from_router(client_ip), MAIN_LOOP)
            
            # Hijack immediately (safe default) while we resolve the MAC
            return False

        mac = mac.upper()
        
        # Track this device for the Admin UI
        dns_track_device(client_ip, mac=mac)

        # ⚡ HIGH SPEED MEMORY CHECK (Minimal Latency)
        if mac in _WL_CACHE:
            logger.debug(f"✅ DNS Auth (CACHE): MAC {mac} is whitelisted.")
            return True
        if mac in _AUTH_CACHE:
            logger.debug(f"✅ DNS Auth (CACHE): MAC {mac} has active voucher.")
            return True

        logger.info(f"🚫 [DNS AUTH] Device {client_ip} (MAC: {mac}) is NOT authorized - WILL HIJACK")
        return False

    async def _resolve_mac_from_router(self, client_ip, silent=False):
        """Calls the router API ONCE to find the MAC for a new IP discovery."""
        try:
            if not silent:
                logger.debug(f"🔍 Discovery: Calling router API to map IP {client_ip} to MAC...")
            devices = await scrape_devices()
            found_mac = None
            for d in devices:
                dev_ip = d.get("ip")
                dev_mac = d.get("mac", "").upper()
                if dev_mac:
                    # Cache all mappings found to save future calls
                    self._ip_to_mac_lookup[dev_ip] = dev_mac
                    if dev_ip == client_ip:
                        found_mac = dev_mac
            
            if not silent and found_mac:
                logger.debug(f"✅ Discovery: IP {client_ip} is MAC {found_mac}")
                dns_track_device(client_ip, mac=found_mac)
            elif not silent:
                logger.debug(f"⚠️ Discovery: Router didn't list a MAC for IP {client_ip}")
                
        except Exception as e:
            logger.debug(f"Discovery failed for {client_ip}: {e}")
        finally:
            if client_ip in self._pending_lookups:
                self._pending_lookups.remove(client_ip)

    def sync_from_cookie(self, cookie_val, ip):
        """Verifies session cookie and mirrors voucher to the current client identity."""
        try:
            parts = cookie_val.split(":")
            if len(parts) != 3: return None
            vid, old_mac, signature = parts
            
            config = get_config()
            secret = config.get("adminPin", "2004")
            expected = hashlib.sha256((vid + old_mac + secret).encode()).hexdigest()[:16]
            
            if signature != expected:
                return None
                
            # Verify the voucher is still active in DB
            now = datetime.now()
            vouchers = get_vouchers()
            source_v = next((v for v in vouchers if v["id"] == vid and v["status"] == "active"), None)
            
            if not source_v:
                return None
                
            if datetime.fromisoformat(source_v["expires"]) <= now:
                return None
                
            # We have a valid active session! Find current MAC for this IP
            # We might need to force a router refresh if the MAC is unknown
            current_mac = self._ip_to_mac_lookup.get(ip)
            if not current_mac:
                # Non-blocking refresh - results will be available on next request or DNS query
                if ip not in self._pending_lookups and MAIN_LOOP:
                    self._pending_lookups.add(ip)
                    asyncio.run_coroutine_threadsafe(self._resolve_mac_from_router(ip), MAIN_LOOP)
                return None # Try again on next poll
                
            if current_mac.upper() != old_mac.upper():
                # MIRROR TRIGGERED
                self._sync_voucher_to_new_identity(source_v, current_mac, ip)
                return current_mac.upper()
                
            return old_mac.upper() # Already synced
        except Exception as e:
            logger.error(f"Cookie sync error: {e}")
            return None

    def _query_upstream_nuclear(self, data):
        """Simultaneously query multiple DNS providers and return the fastest response."""
        dnsservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1"]
        results = []
        lock = threading.Lock()
        stop_event = threading.Event()

        def worker(server):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.5)
            try:
                sock.sendto(data, (server, 53))
                resp, _ = sock.recvfrom(2048)
                with lock:
                    if not stop_event.is_set():
                        results.append(resp)
                        stop_event.set()
            except:
                pass
            finally:
                sock.close()

        threads = []
        for s in dnsservers:
            t = threading.Thread(target=worker, args=(s,), daemon=True)
            threads.append(t)
            t.start()
        
        # Wait up to 2.5 seconds for the first winner
        stop_event.wait(2.5)
        return results[0] if results else None

    def _sync_voucher_to_new_identity(self, source_v, new_mac, ip):
        """Copies authorization from an old identity to a new one (MAC Randomization sync)."""
        new_mac = new_mac.upper()
        vouchers = get_vouchers()
        
        # Avoid duplicate syncs
        if any(v["mac"].upper() == new_mac and v["status"] == "active" for v in vouchers):
            return

        logger.info(f"🧬 [IDENTITY SYNC] Mirroring session {source_v['id']} to new MAC {new_mac}")
        
        new_v = source_v.copy()
        new_v["id"] = str(uuid.uuid4())[:8]
        new_v["mac"] = new_mac
        new_v["reference"] = f"SYNC-{source_v['id']}"
        
        vouchers.append(new_v)
        save_vouchers(vouchers)
        
        # Instantly unblock on router
        if MAIN_LOOP:
            asyncio.run_coroutine_threadsafe(unblock_device(new_mac), MAIN_LOOP)
            
        # Update device store status
        devices_store = get_devices_store()
        updated = False
        for ds in devices_store:
            if ds.get("mac", "").upper() == new_mac:
                ds["status"] = "active"
                ds["voucher_id"] = new_v["id"]
                ds["expires"] = new_v["expires"]
                updated = True
                break
        if not updated:
            devices_store.append({
                "mac": new_mac,
                "hostname": "Randomized Device",
                "ip": ip,
                "status": "active",
                "voucher_id": new_v["id"],
                "expires": new_v["expires"]
            })
        save_devices_store(devices_store)
        
        # Notify UI
        asyncio.run_coroutine_threadsafe(
            ws_manager.broadcast({"type": "device_unblocked", "mac": new_mac, "is_sync": True}), 
            MAIN_LOOP
        )

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Catch-all hijacked route (MUST BE LAST)
# ---------------------------------------------------------------------------

@app.api_route("/{path_name:path}", methods=["GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"])
async def catch_all(request: Request, path_name: str):
    # If it's an API call or internal path, don't hijack
    if path_name.startswith(("api/", "static/", "ws", "admin")):
        # We don't want to redirect valid internal API / websocket / admin requests
        raise HTTPException(status_code=404)
    
    # Check if authorized - if so, this shouldn't have hit our server (dns would proxied it)
    # But if it did, redirect to a useful starting point
    logger.info(f"🚩 Global Hijack: Redirecting {request.client.host if request.client else 'unknown'} path '{path_name}' to portal.")
    config = get_config()
    server_ip = config.get("serverIp", "192.168.1.162")
    return RedirectResponse(url=f"http://{server_ip}/", status_code=302)


if __name__ == "__main__":
    import uvicorn
    import signal
    import os
    import time
    import webbrowser
    import threading
    
    # 1. Force-kill on Ctrl+C so the process never hangs
    def _force_exit(sig, frame):
        print("\n🛑 Server stopping...")
        os._exit(0)
    signal.signal(signal.SIGINT, _force_exit)
    signal.signal(signal.SIGTERM, _force_exit)

    # 2. Auto-launch the Admin Portal locally when the server starts
    def _open_admin(port):
        time.sleep(2.0)
        url = f"http://127.0.0.1:{port}/admin" if port != 80 else "http://127.0.0.1/admin"
        logger.info(f"🌐 Opening admin: {url}")
        webbrowser.open(url)

    # 3. Start Web Portal (HTTP-only) on Port 80
    logger.info("🚀 Starting Web Portal...")
    start_dummy_https_server()
    try:
        threading.Thread(target=_open_admin, args=(80,), daemon=True).start()
        uvicorn.run(app, host="0.0.0.0", port=80, log_level="info", reload=False)
    except Exception as e:
        logger.error(f"Failed to start on Port 80: {e}")
        logger.info("Retrying on 8000...")
        threading.Thread(target=_open_admin, args=(8000,), daemon=True).start()
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info", reload=False)