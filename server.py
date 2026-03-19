"""
server.py — FastAPI WiFi Hotspot Voucher Server
Core flow:
  Customer connects → scans QR → enters phone → pays via Snippe USSD →
  webhook confirms → Playwright unblocks MAC → customer gets internet →
  expiry timer re-blocks MAC automatically.
"""

import asyncio
from contextlib import asynccontextmanager
import hashlib
import hmac
import io
import json
import logging
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import qrcode
from qrcode.image.styledpil import StyledPilImage

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from router_scraper import scrape_devices, block_device, unblock_device, sync_whitelist_to_router, cleanup as pw_cleanup

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("hotzone")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE = Path(__file__).parent
CONFIG_PATH = BASE / "config.json"
WHITELIST_PATH = BASE / "whitelist.json"
VOUCHERS_PATH = BASE / "vouchers.json"
DEVICES_PATH = BASE / "devices.json"
STATIC_DIR = BASE / "static"

# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> Any:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        if path in (WHITELIST_PATH, VOUCHERS_PATH, DEVICES_PATH):
            return []
        return {}


def _write_json(path: Path, data: Any):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def get_config() -> dict:
    return _read_json(CONFIG_PATH)


def get_whitelist() -> list:
    return _read_json(WHITELIST_PATH)


def get_vouchers() -> list:
    return _read_json(VOUCHERS_PATH)


def save_vouchers(vouchers: list):
    _write_json(VOUCHERS_PATH, vouchers)


def get_devices_store() -> list:
    return _read_json(DEVICES_PATH)


def save_devices_store(devices: list):
    _write_json(DEVICES_PATH, devices)

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🔥 HotZone WiFi Voucher Server starting...")
    
    # Sync whitelist to router at startup (sequential, one session)
    whitelist = get_whitelist()
    if whitelist:
        logger.info(f"Syncing {len(whitelist)} whitelisted devices to router...")
        asyncio.create_task(sync_whitelist_to_router(whitelist))

    monitor_task = asyncio.create_task(device_monitor())
    yield
    logger.info("Shutting down — cleaning up Playwright...")
    monitor_task.cancel()
    await pw_cleanup()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="HotZone WiFi Voucher System", lifespan=lifespan)

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
    playwrightEnabled: bool | None = None
    serverIp: str | None = None
    dailyMode: str | None = None
    dailyCutoffTime: str | None = None
    wifiSSID: str | None = None
    wifiPassword: str | None = None
    wifiSecurity: str | None = None
    adminPin: str | None = None

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
    return HTMLResponse("<h1>Customer page not found</h1>", status_code=404)


@app.get("/admin", response_class=HTMLResponse)
async def serve_admin_page():
    admin = BASE / "hotzone-admin.html"
    if admin.exists():
        return FileResponse(str(admin))
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
        
    devices = get_devices_store()
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

@app.get("/api/devices")
async def list_devices():
    try:
        router_devices = await scrape_devices()
    except Exception as e:
        logger.error(f"Scrape failed: {e}")
        router_devices = []

    whitelist = get_whitelist()
    vouchers = get_vouchers()
    wl_macs = {w["mac"].upper() for w in whitelist}

    now = datetime.now()
    enriched = []
    for d in router_devices:
        mac = d["mac"].upper()
        entry = {**d, "mac": mac}

        if mac in wl_macs:
            entry["status"] = "whitelisted"
        else:
            # Check voucher
            voucher = None
            for v in vouchers:
                if v["mac"].upper() == mac and v["status"] == "active":
                    voucher = v
                    break

            if voucher:
                exp = datetime.fromisoformat(voucher["expires"])
                if exp > now:
                    entry["status"] = "active"
                    entry["expires"] = voucher["expires"]
                    entry["voucher_id"] = voucher["id"]
                    remaining = (exp - now).total_seconds()
                    entry["time_remaining"] = int(remaining)
                else:
                    entry["status"] = "expired"
                    entry["voucher_id"] = voucher["id"]
            else:
                entry["status"] = "unknown"

        enriched.append(entry)

    return enriched


@app.post("/api/devices/{mac}/block")
async def block_device_route(mac: str):
    whitelist = get_whitelist()
    if any(w["mac"].upper() == mac.upper() for w in whitelist):
        raise HTTPException(status_code=403, detail="Cannot block whitelisted device")

    success = await block_device(mac)

    # Update devices store
    devices_store = get_devices_store()
    for ds in devices_store:
        if ds.get("mac", "").upper() == mac.upper():
            ds["status"] = "blocked"
            break
    save_devices_store(devices_store)

    await ws_manager.broadcast({"type": "device_blocked", "mac": mac})
    return {"success": success, "mac": mac}


@app.post("/api/devices/{mac}/unblock")
async def unblock_device_route(mac: str):
    success = await unblock_device(mac)

    devices_store = get_devices_store()
    for ds in devices_store:
        if ds.get("mac", "").upper() == mac.upper():
            ds["status"] = "active"
            break
    save_devices_store(devices_store)

    await ws_manager.broadcast({"type": "device_unblocked", "mac": mac})
    return {"success": success, "mac": mac}

# ---------------------------------------------------------------------------
# Routes — Whitelist
# ---------------------------------------------------------------------------

@app.get("/api/whitelist")
async def get_whitelist_route():
    return get_whitelist()


@app.post("/api/whitelist")
async def add_whitelist(entry: WhitelistEntry):
    wl = get_whitelist()
    
    # Actively unblock on the router
    # Run synchronously to not block the request for too long, or asyncio.create_task
    # Actually, Playwright calls can take 10-15s, let's run it in the background
    asyncio.create_task(unblock_device(entry.mac))

    # Check if already present
    for w in wl:
        if w["mac"].upper() == entry.mac.upper():
            w["hostname"] = entry.hostname
            w["label"] = entry.label
            _write_json(WHITELIST_PATH, wl)
            return {"status": "updated", "entry": w}

    new_entry = {"mac": entry.mac.upper(), "hostname": entry.hostname, "label": entry.label}
    wl.append(new_entry)
    _write_json(WHITELIST_PATH, wl)
    await ws_manager.broadcast({"type": "whitelist_updated", "whitelist": wl})
    return {"status": "added", "entry": new_entry}


@app.delete("/api/whitelist/{mac}")
async def remove_whitelist(mac: str):
    wl = get_whitelist()
    wl = [w for w in wl if w["mac"].upper() != mac.upper()]
    _write_json(WHITELIST_PATH, wl)
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
    return safe


@app.post("/api/config")
async def update_config(update: ConfigUpdate):
    config = get_config()
    for key, val in update.dict(exclude_none=True).items():
        config[key] = val
    _write_json(CONFIG_PATH, config)
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

    total_all = sum(v.get("amount", 0) for v in vouchers if v.get("status") in ("active", "expired"))
    total_today = sum(
        v.get("amount", 0) for v in vouchers
        if v.get("status") in ("active", "expired")
        and datetime.fromisoformat(v["created"]) >= today_start
    )

    return {
        "today": total_today,
        "all_time": total_all,
        "currency": "TZS",
        "voucher_count": len(vouchers),
        "active_count": sum(1 for v in vouchers if v.get("status") == "active")
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

VOUCHER_CODES_PATH = BASE / "voucher_codes.json"

def get_voucher_codes() -> list:
    return _read_json(VOUCHER_CODES_PATH)

def save_voucher_codes(codes: list):
    _write_json(VOUCHER_CODES_PATH, codes)


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
        raise HTTPException(status_code=400, detail="This voucher code has already been used.")

    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "unknown"

    router_devices = await scrape_devices()
    device = next((d for d in router_devices if d.get("ip") == client_ip), None)
    
    mac = None
    hostname = "unknown"
    
    if device:
        mac = device["mac"].upper()
        hostname = device.get("host", "unknown")
    else:
        # Fallback to persistent local storage if live scrape returned 0
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
    expires = now + timedelta(hours=target_code.get("duration_hours", 24))

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

    if not device:
        device = {"mac": mac, "host": hostname, "ip": client_ip}
        
    await ws_manager.broadcast({
        "type": "device_unblocked",
        "voucher": session_voucher,
        "device": device
    })
    
    await ws_manager.broadcast({"type": "voucher_codes_updated"})

    logger.info(f"Voucher code {code_str} redeemed successfully by MAC {mac}")
    return {"status": "success", "voucher": session_voucher}

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

async def device_monitor():
    """Run every 10 seconds: scrape devices, enforce blocks, detect spoofs."""
    await asyncio.sleep(5)  # Initial delay
    while True:
        try:
            config = get_config()
            if not config.get("playwrightEnabled", True):
                await asyncio.sleep(10)
                continue

            router_devices = await scrape_devices()
            whitelist = get_whitelist()
            vouchers = get_vouchers()
            devices_store = get_devices_store()

            wl_macs = {w["mac"].upper() for w in whitelist}
            now = datetime.now()
            changed = False

            for rd in router_devices:
                mac = rd["mac"].upper()
                hostname = rd.get("host", "unknown")
                ip = rd.get("ip", "")

                # Skip whitelisted
                if mac in wl_macs:
                    continue

                # Check for active voucher
                active_voucher = None
                for v in vouchers:
                    if v["mac"].upper() == mac and v["status"] == "active":
                        active_voucher = v
                        break

                # Check for spoofing
                existing = None
                for ds in devices_store:
                    if ds.get("mac", "").upper() == mac:
                        existing = ds
                        break

                if existing:
                    # MAC matches but hostname changed
                    if existing.get("hostname") and existing["hostname"] != hostname:
                        logger.warning(f"Hostname changed: {existing['hostname']} → {hostname} for MAC {mac}")
                        existing["hostname"] = hostname
                        existing["hostname_changed"] = True
                        changed = True

                # Check hostname spoofing (same hostname, different MAC)
                for ds in devices_store:
                    if (ds.get("hostname") == hostname
                            and ds.get("mac", "").upper() != mac
                            and hostname not in ("unknown", "", "*")):
                        logger.warning(f"SPOOF? Hostname '{hostname}' seen with MAC {mac}, previously {ds['mac']}")
                        await ws_manager.broadcast({
                            "type": "device_spoofed",
                            "hostname": hostname,
                            "new_mac": mac,
                            "old_mac": ds["mac"],
                            "ip": ip
                        })
                        # Block the spoofed device
                        await block_device(mac)
                        if existing:
                            existing["status"] = "suspected_spoof"
                        else:
                            devices_store.append({
                                "mac": mac,
                                "hostname": hostname,
                                "ip": ip,
                                "status": "suspected_spoof",
                                "first_seen": now.isoformat()
                            })
                        changed = True
                        break

                # Expired voucher → block
                if active_voucher:
                    exp = datetime.fromisoformat(active_voucher["expires"])
                    if exp <= now:
                        logger.info(f"Voucher expired for {mac} — blocking")
                        active_voucher["status"] = "expired"
                        await block_device(mac)
                        if existing:
                            existing["status"] = "expired"
                        await ws_manager.broadcast({
                            "type": "device_blocked",
                            "mac": mac,
                            "reason": "expired"
                        })
                        changed = True
                else:
                    # Unknown device (no voucher, not whitelisted)
                    if not existing or existing.get("status") not in ("blocked", "suspected_spoof"):
                        logger.info(f"Unknown device {mac} connected — blocking by default")
                        await block_device(mac)
                        
                        if existing:
                            existing["status"] = "blocked"
                        else:
                            devices_store.append({
                                "mac": mac,
                                "hostname": hostname,
                                "ip": ip,
                                "status": "blocked",
                                "first_seen": now.isoformat()
                            })
                        
                        changed = True
                        
                        if not existing:
                            await ws_manager.broadcast({
                                "type": "new_device",
                                "mac": mac,
                                "hostname": hostname,
                                "ip": ip
                            })
                            
                        await ws_manager.broadcast({
                            "type": "device_blocked",
                            "mac": mac,
                            "reason": "unknown (no voucher)"
                        })

                # Update existing entry
                if existing:
                    existing["ip"] = ip
                    existing["last_seen"] = now.isoformat()
                    changed = True

            if changed:
                save_vouchers(vouchers)
                save_devices_store(devices_store)

            # Broadcast devices update
            await ws_manager.broadcast({
                "type": "devices_update",
                "devices": router_devices,
                "timestamp": now.isoformat()
            })

        except Exception as e:
            logger.error(f"Device monitor error: {e}", exc_info=True)

        await asyncio.sleep(10)



# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    config = get_config()
    server_ip = config.get("serverIp", "0.0.0.0")
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
