import httpx
import hashlib
import json
import logging
import asyncio
import os
from pathlib import Path

logger = logging.getLogger("router_scraper")

# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    import sys, sqlite3, platform
    if getattr(sys, 'frozen', False):
        if platform.system() == "Windows":
            data_dir = Path(os.environ.get("APPDATA", os.path.expanduser("~"))) / "HotZonePro"
        else:
            data_dir = Path(os.path.expanduser("~")) / ".HotZonePro"
        db_path = data_dir / "hotzone.db"
    else:
        db_path = Path(__file__).parent / "hotzone.db"
    try:
        with sqlite3.connect(db_path, timeout=5.0) as conn:
            rows = conn.execute("SELECT key, value FROM config").fetchall()
            if rows:
                return {r[0]: r[1] for r in rows}
    except Exception as e:
        logger.error(f"Config load error: {e}")
    return {}

# ---------------------------------------------------------------------------
# TYPE_B (ubus) — ZTE 5G CPE at 192.168.0.1
# Login: password only (no username), double SHA256
# Block: zwrt_wlan.set with denymaclist
# ---------------------------------------------------------------------------

_ubus_session = None
_client = None
_lock = asyncio.Lock()

NULL_SESSION = "00000000000000000000000000000000"

def _get_router_ip() -> str:
    return _load_config().get("routerIp", "192.168.0.1")

def _headers(router_ip: str) -> dict:
    return {
        "Content-Type": "application/json",
        "Origin":  f"https://{router_ip}",
        "Referer": f"https://{router_ip}/",
    }

def _get_client(router_ip: str):
    global _client
    if _client is None or str(_client.base_url) != f"https://{router_ip}":
        if _client:
            asyncio.get_event_loop().run_until_complete(_client.aclose())
        _client = httpx.AsyncClient(
            base_url=f"https://{router_ip}", verify=False, timeout=10.0,
            follow_redirects=True)
    return _client

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest().upper()

async def _ubus_call(client, router_ip, session, service, method, params=None):
    """Single JSON-RPC call. Returns (error_code, data).
    Success: code == [0] or 0
    Bad session: code == []
    """
    headers = _headers(router_ip)
    body = {"jsonrpc": "2.0", "id": 1, "method": "call",
            "params": [session, service, method, params or {}]}
    r = await client.post("/ubus/", headers=headers, json=body)
    result = r.json().get("result", [])
    if isinstance(result, list) and len(result) > 1:
        return result[0], result[1]
    return result, {}

def _is_success(code) -> bool:
    return code == 0 or code == [0]

async def _login(client, router_ip, config):
    global _ubus_session
    password = config.get("routerPass", "")

    code, data = await _ubus_call(client, router_ip, NULL_SESSION,
                                   "zwrt_web", "web_login_info")
    sault = data.get("zte_web_sault", "")
    if not sault:
        raise Exception(f"Login failed: no sault (code={code}, data={data})")

    hashed = sha256(sha256(password) + sault)
    code, data = await _ubus_call(client, router_ip, NULL_SESSION,
                                   "zwrt_web", "web_login", {"password": hashed})
    session = data.get("ubus_rpc_session", "")
    if not session:
        raise Exception(f"Login rejected: code={code}, data={data}")
    _ubus_session = session
    logger.info(f"ZTE ubus login OK - session {session[:12]}...")
    return session

async def _ensure_logged_in(client, router_ip, config):
    global _ubus_session
    if not _ubus_session:
        await _login(client, router_ip, config)
        return _ubus_session

    # Verify session still valid (cheap call)
    code, _ = await _ubus_call(client, router_ip, _ubus_session,
                               "zwrt_router.api", "router_get_user_list_num")
    if code == [] or code == 1:
        logger.info("Session expired — re-logging in")
        _ubus_session = None
        await _login(client, router_ip, config)
    return _ubus_session

def _get_deny_list(data) -> list:
    """denymaclist can be None when empty — always return a list."""
    deny = data.get("denymaclist")
    return deny if isinstance(deny, list) else []

# ---------------------------------------------------------------------------
# scrape_devices
# ---------------------------------------------------------------------------

async def scrape_devices(acquire_lock: bool = True) -> list[dict]:
    global _ubus_session
    config = _load_config()
    router_ip = _get_router_ip()

    async def _do_scrape():
        try:
            client = _get_client(router_ip)
            session = await _ensure_logged_in(client, router_ip, config)

            devices = []

            # WiFi clients
            _, cnt = await _ubus_call(client, router_ip, session,
                "zwrt_router.api", "router_get_user_list_num")
            total = int(cnt.get("wireless_num", 0) or 0)

            if total > 0:
                _, wdata = await _ubus_call(client, router_ip, session,
                    "zwrt_router.api", "router_wireless_access_list",
                    {"start_id": 1, "end_id": max(total, 64)})
                for d in wdata.get("wireless_access_list_info", []):
                    mac = (d.get("mac_address") or "").upper()
                    if mac:
                        devices.append({
                            "mac": mac,
                            "hostname": d.get("hostname", "unknown"),
                            "ip": d.get("ip_address", ""),
                        })

            # LAN / Ethernet clients
            _, ldata = await _ubus_call(client, router_ip, session,
                "zwrt_router.api", "router_lan_access_list")
            for d in ldata.get("lan_access_list_info", []):
                mac = (d.get("mac_address") or "").upper()
                if mac and not any(x["mac"] == mac for x in devices):
                    devices.append({
                        "mac": mac,
                        "hostname": d.get("hostname", "unknown"),
                        "ip": d.get("ip_address", ""),
                    })

            # ARP table — extra IP→MAC mapping (key is 'mac')
            _, arpdata = await _ubus_call(client, router_ip, session,
                "zwrt_router.api", "router_get_arptable")
            for entry in arpdata.get("arptable", []):
                mac = (entry.get("mac") or "").upper()
                ip = entry.get("ip", "")
                if mac:
                    existing = next((d for d in devices if d["mac"] == mac), None)
                    if existing:
                        if not existing["ip"]:
                            existing["ip"] = ip
                    else:
                        devices.append({
                            "mac": mac, "hostname": "unknown", "ip": ip,
                        })

            logger.info(f"Scraped {len(devices)} devices from router")
            return devices

        except Exception as e:
            logger.error(f"scrape_devices failed: {e}")
            _ubus_session = None
            return []

    if acquire_lock:
        async with _lock:
            return await _do_scrape()
    return await _do_scrape()

# ---------------------------------------------------------------------------
# Deny-list helpers (the block/unblock mechanism)
# ---------------------------------------------------------------------------

async def _apply_deny_list(deny_list: list):
    """Set the WiFi deny list on both 2.4G and 5G. Empty list = allow all."""
    config = _load_config()
    router_ip = _get_router_ip()
    client = _get_client(router_ip)
    session = await _ensure_logged_in(client, router_ip, config)

    macfilter = "deny" if deny_list else "disable"
    payload = {
        "main_2g": {"macfilter": macfilter, "denymaclist": deny_list},
        "main_5g": {"macfilter": macfilter, "denymaclist": deny_list},
    }
    code, data = await _ubus_call(client, router_ip, session,
                                  "zwrt_wlan", "set", payload)
    if _is_success(code):
        logger.info(f"WiFi deny list updated: {len(deny_list)} blocked")
        return True
    logger.error(f"zwrt_wlan.set failed: code={code} data={data}")
    return False

async def _get_current_deny() -> list:
    config = _load_config()
    router_ip = _get_router_ip()
    client = _get_client(router_ip)
    session = await _ensure_logged_in(client, router_ip, config)

    _, data = await _ubus_call(client, router_ip, session,
                               "uci", "get", {"config": "wireless", "section": "main_2g"})
    return _get_deny_list(data.get("values", {}))

# ---------------------------------------------------------------------------
# Public API: block / unblock (used by voucher redemption + expiry)
# ---------------------------------------------------------------------------

_pending_adds    = set()   # MACs to allow (voucher redeemed)
_pending_deletes = set()   # MACs to block (voucher expired)
_queue_task  = None
_queue_event = asyncio.Event()

def _start_queue_worker():
    global _queue_task
    if _queue_task is None or _queue_task.done():
        _queue_task = asyncio.create_task(_queue_worker())

async def block_device(mac: str) -> bool:
    """Block a device (voucher expired)."""
    _pending_deletes.add(mac.upper())
    _start_queue_worker()
    _queue_event.set()
    logger.info(f"Queued block for {mac}")
    return True

async def unblock_device(mac: str) -> bool:
    """Unblock a device (voucher redeemed)."""
    _pending_adds.add(mac.upper())
    _start_queue_worker()
    _queue_event.set()
    logger.info(f"Queued unblock for {mac}")
    return True

async def _queue_worker():
    global _pending_adds, _pending_deletes, _ubus_session
    while True:
        await _queue_event.wait()
        _queue_event.clear()
        await asyncio.sleep(0.5)

        adds    = list(_pending_adds);    _pending_adds.clear()
        deletes = list(_pending_deletes); _pending_deletes.clear()
        if not adds and not deletes:
            continue

        for attempt in range(1, 4):
            try:
                async with _lock:
                    current = await _get_current_deny()
                    deny_set = {m.upper() for m in current}

                    for mac in deletes:   # expired → block
                        deny_set.add(mac.upper())
                    for mac in adds:      # redeemed → allow
                        deny_set.discard(mac.upper())

                    ok = await _apply_deny_list(list(deny_set))
                    if ok:
                        break
                    raise Exception("zwrt_wlan.set failed")
            except Exception as e:
                logger.error(f"Queue worker attempt {attempt}/3: {e}")
                _ubus_session = None
                if attempt < 3:
                    await asyncio.sleep(2 * attempt)
                else:
                    _pending_adds.update(adds)
                    _pending_deletes.update(deletes)
                    async def _retry():
                        await asyncio.sleep(15)
                        _queue_event.set()
                    asyncio.create_task(_retry())

# ---------------------------------------------------------------------------
# sync_whitelist_to_router — Washa System
# ---------------------------------------------------------------------------

async def sync_whitelist_to_router(whitelist: list[dict]) -> bool:
    """Ensure whitelisted MACs are NOT in the deny list. Others stay blocked."""
    global _ubus_session
    if not whitelist:
        logger.warning("sync_whitelist_to_router: empty whitelist — skipping")
        return False

    try:
        async with _lock:
            current = await _get_current_deny()
            allowed_upper = {e.get("mac", "").upper() for e in whitelist}
            new_deny = [m for m in current if m.upper() not in allowed_upper]
            ok = await _apply_deny_list(new_deny)
            logger.info(f"Whitelist synced: {len(new_deny)} blocked, {len(allowed_upper)} allowed")
            return ok
    except Exception as e:
        logger.error(f"sync_whitelist_to_router failed: {e}")
        _ubus_session = None
        return False

# ---------------------------------------------------------------------------
# purge_unauthorized_macs — block all currently connected non-whitelisted
# ---------------------------------------------------------------------------

async def purge_unauthorized_macs(allowed_macs: set) -> bool:
    global _ubus_session
    try:
        async with _lock:
            devices = await scrape_devices(acquire_lock=False)
            allowed_upper = {m.upper() for m in allowed_macs}
            deny_list = []
            for d in devices:
                mac = d.get("mac", "").upper()
                if mac and mac not in allowed_upper:
                    deny_list.append(mac)
            ok = await _apply_deny_list(deny_list)
            logger.info(f"Purged unauthorized: {len(deny_list)} devices blocked")
            return ok
    except Exception as e:
        logger.error(f"purge_unauthorized_macs failed: {e}")
        return False

# ---------------------------------------------------------------------------
# disable_whitelist_mode — Zima System (open everything)
# ---------------------------------------------------------------------------

async def disable_whitelist_mode() -> bool:
    global _ubus_session
    try:
        async with _lock:
            ok = await _apply_deny_list([])
            logger.info("WiFi filter cleared - all devices allowed")
            return ok
    except Exception as e:
        logger.debug(f"disable_whitelist_mode failed (router offline?): {e}")
        return False

# ---------------------------------------------------------------------------
# set_dhcp_dns — not possible on this router via API (access denied)
# DNS Blocker + ARP spoofing handle interception instead
# ---------------------------------------------------------------------------

async def set_dhcp_dns(dns_ip: str) -> bool:
    logger.info("DHCP DNS not settable via API on this router — using DNS Blocker + ARP")
    return True

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

async def cleanup():
    global _client
    if _client:
        await _client.aclose()
        _client = None

async def shutdown_scraper():
    await cleanup()
