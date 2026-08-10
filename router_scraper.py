import httpx
import hashlib
import json
import logging
import asyncio
import uuid
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
# Router type detection
# TYPE_A = old ZTE CPE: /cgi-bin/http.cgi with CMD-based JSON API
# TYPE_B = new ZTE:     /ubus/ with JSON-RPC 2.0 (zwrt_web / zwrt_router.api)
# ---------------------------------------------------------------------------

_router_type = None   # "A" | "B" | None (undetected)
_session_id  = None   # TYPE_A session ID
_ubus_session = None  # TYPE_B ubus_rpc_session
_client = None
_lock = asyncio.Lock()

_UBUS_HEADERS = {
    "Content-Type": "application/json",
    "Origin": "https://",        # filled dynamically
    "Referer": "https:///"       # filled dynamically
}

NULL_SESSION = "00000000000000000000000000000000"

def _get_client(router_ip: str, https: bool = False):
    global _client
    scheme = "https" if https else "http"
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=f"{scheme}://{router_ip}",
            timeout=10.0,
            verify=False
        )
    return _client

def _ubus_headers(router_ip: str):
    return {
        "Content-Type": "application/json",
        "Origin":  f"https://{router_ip}",
        "Referer": f"https://{router_ip}/",
    }

# ---------------------------------------------------------------------------
# TYPE_A helpers  (original ZTE CPE — /cgi-bin/http.cgi)
# ---------------------------------------------------------------------------

async def _login_typeA(client, config):
    global _session_id
    password = config.get("routerPass", "")
    username = config.get("routerUser", "admin")

    res = await client.post("/cgi-bin/http.cgi",
        json={"cmd": 232, "method": "GET", "sessionId": "", "language": "en"})
    token = res.json().get("token", "")
    if not token:
        raise Exception(f"TYPE_A: no token — {res.text[:80]}")

    hashed_pw = hashlib.sha256((token + password).encode()).hexdigest()
    def md5(s): return hashlib.md5(s.encode()).hexdigest()
    setup_session = md5(str(uuid.uuid4())) + md5(str(uuid.uuid4()))

    login_res = await client.post("/cgi-bin/http.cgi", json={
        "cmd": 100, "method": "POST", "sessionId": setup_session,
        "username": username, "passwd": hashed_pw,
        "isAutoUpgrade": "0", "language": "en"
    })
    data = login_res.json()
    if "AUTH" not in data or data.get("success") is False:
        raise Exception(f"TYPE_A login rejected: {data}")
    _session_id = data.get("sessionId")
    logger.info("✅ Router TYPE_A session established")

async def _ensure_typeA(client, config):
    global _session_id
    if not _session_id:
        await _login_typeA(client, config)

# ---------------------------------------------------------------------------
# TYPE_B helpers  (new ZTE — /ubus/ JSON-RPC)
# ---------------------------------------------------------------------------

async def _ubus_call(client, router_ip, session, service, method, params=None):
    """Single JSON-RPC call on /ubus/ endpoint."""
    headers = _ubus_headers(router_ip)
    body = {"jsonrpc": "2.0", "id": 1, "method": "call",
            "params": [session, service, method, params or {}]}
    r = await client.post("/ubus/", headers=headers, json=body)
    result = r.json().get("result", [])
    if isinstance(result, list) and len(result) > 1:
        return result[0], result[1]
    return result, {}

async def _login_typeB(client, router_ip, config):
    global _ubus_session
    password = config.get("routerPass", "")

    code, data = await _ubus_call(client, router_ip, NULL_SESSION,
                                   "zwrt_web", "web_login_info")
    sault = data.get("zte_web_sault", "")
    if not sault:
        raise Exception(f"TYPE_B: no sault — data={data}")

    def sha256(s): return hashlib.sha256(s.encode()).hexdigest().upper()
    hashed = sha256(sha256(password) + sault)

    code, data = await _ubus_call(client, router_ip, NULL_SESSION,
                                   "zwrt_web", "web_login", {"password": hashed})
    session = data.get("ubus_rpc_session", "")
    if not session:
        raise Exception(f"TYPE_B login failed: code={code} data={data}")
    _ubus_session = session
    logger.info("✅ Router TYPE_B (ubus) session established")

async def _ensure_typeB(client, router_ip, config):
    global _ubus_session
    if not _ubus_session:
        await _login_typeB(client, router_ip, config)

# ---------------------------------------------------------------------------
# Auto-detect router type
# ---------------------------------------------------------------------------

async def _detect_router_type(router_ip: str, config: dict):
    """
    Try TYPE_B (new ubus) first — if /ubus/ responds with sault, it's TYPE_B.
    Otherwise fall back to TYPE_A (old /cgi-bin/http.cgi CMD API).
    """
    global _router_type, _client

    # Try TYPE_B: HTTPS + ubus
    try:
        https_client = httpx.AsyncClient(
            base_url=f"https://{router_ip}", timeout=6.0, verify=False)
        headers = _ubus_headers(router_ip)
        r = await https_client.post("/ubus/", headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": "call",
            "params": [NULL_SESSION, "zwrt_web", "web_login_info", {}]
        })
        result = r.json().get("result", [])
        if isinstance(result, list) and len(result) > 1:
            if result[1].get("zte_web_sault"):
                _router_type = "B"
                _client = https_client
                logger.info("🔍 Detected Router TYPE_B (ubus/HTTPS)")
                return "B"
        await https_client.aclose()
    except Exception as e:
        logger.debug(f"TYPE_B detection failed: {e}")

    # Fall back to TYPE_A: HTTP + /cgi-bin/http.cgi
    try:
        http_client = httpx.AsyncClient(
            base_url=f"http://{router_ip}", timeout=6.0)
        r = await http_client.post("/cgi-bin/http.cgi", json={
            "cmd": 232, "method": "GET", "sessionId": "", "language": "en"
        })
        if r.json().get("token"):
            _router_type = "A"
            _client = http_client
            logger.info("🔍 Detected Router TYPE_A (cgi-bin/http.cgi)")
            return "A"
        await http_client.aclose()
    except Exception as e:
        logger.debug(f"TYPE_A detection failed: {e}")

    logger.error(f"❌ Could not detect router type at {router_ip}")
    return None

async def _get_router(config):
    """Return (client, router_ip, router_type) — detecting if needed."""
    global _router_type, _client
    router_ip = config.get("routerIp", "192.168.1.1")
    if _router_type is None or _client is None:
        _client = None
        await _detect_router_type(router_ip, config)
    return _client, router_ip, _router_type

# ---------------------------------------------------------------------------
# scrape_devices — unified API
# ---------------------------------------------------------------------------

async def scrape_devices() -> list[dict]:
    global _session_id, _ubus_session
    config = _load_config()

    async with _lock:
        client, router_ip, rtype = await _get_router(config)
        if not client:
            return []

        try:
            # ── TYPE_A ──────────────────────────────────────────────
            if rtype == "A":
                await _ensure_typeA(client, config)
                res = await client.post("/cgi-bin/http.cgi",
                    json={"cmd": 223, "method": "GET",
                          "language": "en", "sessionId": _session_id})
                data = res.json()
                if data.get("message") == "NO_AUTH":
                    raise Exception("NO_AUTH")
                dhcp_list = data.get("dhcp_list_info", [])

                mac_res = await client.post("/cgi-bin/http.cgi",
                    json={"cmd": 23, "method": "GET",
                          "language": "en", "sessionId": _session_id})
                allowed_macs = {r.get("mac","").upper()
                                for r in mac_res.json().get("datas", [])
                                if r.get("enableRule")}

                devices = []
                for item in dhcp_list:
                    mac = item.get("mac", "").upper()
                    if not mac or len(mac) != 17:
                        continue
                    devices.append({
                        "mac": mac,
                        "hostname": item.get("hostname", item.get("user", "unknown")),
                        "ip": item.get("ip", ""),
                        "router_allowed": mac in allowed_macs
                    })
                logger.info(f"TYPE_A scrape: {len(devices)} devices")
                return devices

            # ── TYPE_B ──────────────────────────────────────────────
            elif rtype == "B":
                await _ensure_typeB(client, router_ip, config)

                devices = []

                # Wireless clients (paginated)
                _, cnt_data = await _ubus_call(client, router_ip, _ubus_session,
                    "zwrt_router.api", "router_get_user_list_num")
                total = cnt_data.get("wireless_num", 0) + cnt_data.get("lan_num", 0)

                if total > 0:
                    _, w_data = await _ubus_call(client, router_ip, _ubus_session,
                        "zwrt_router.api", "router_wireless_access_list",
                        {"start_id": 1, "end_id": max(total, 64)})
                    for d in w_data.get("wireless_access_list_info", []):
                        devices.append({
                            "mac": d.get("mac_address","").upper(),
                            "hostname": d.get("hostname", "unknown"),
                            "ip": d.get("ip_address", ""),
                            "router_allowed": True
                        })

                # LAN/Ethernet clients
                _, l_data = await _ubus_call(client, router_ip, _ubus_session,
                    "zwrt_router.api", "router_lan_access_list")
                for d in l_data.get("lan_access_list_info", []):
                    mac = d.get("mac_address", "").upper()
                    if not any(x["mac"] == mac for x in devices):
                        devices.append({
                            "mac": mac,
                            "hostname": d.get("hostname", "unknown"),
                            "ip": d.get("ip_address", ""),
                            "router_allowed": True
                        })

                # ARP table (extra IP→MAC mapping)
                _, arp_data = await _ubus_call(client, router_ip, _ubus_session,
                    "zwrt_router.api", "router_get_arptable")
                for entry in arp_data.get("arptable", []):
                    mac = entry.get("mac", "").upper()
                    ip  = entry.get("ip", "")
                    existing = next((d for d in devices if d["mac"] == mac), None)
                    if existing:
                        if not existing["ip"]:
                            existing["ip"] = ip
                    else:
                        devices.append({
                            "mac": mac, "hostname": "unknown",
                            "ip": ip, "router_allowed": False
                        })

                logger.info(f"TYPE_B scrape: {len(devices)} devices")
                return devices

        except Exception as e:
            logger.error(f"scrape_devices failed: {e}")
            _session_id = None
            _ubus_session = None
            _router_type = None
            return []

    return []

# ---------------------------------------------------------------------------
# Background batch worker (block / unblock)
# ---------------------------------------------------------------------------

_pending_adds    = set()
_pending_deletes = set()
_queue_task  = None
_queue_event = asyncio.Event()

def _start_queue_worker():
    global _queue_task
    if _queue_task is None or _queue_task.done():
        _queue_task = asyncio.create_task(_queue_worker())

async def shutdown_scraper():
    global _queue_task, _client
    if _queue_task and not _queue_task.done():
        _queue_task.cancel()
    if _client:
        await _client.aclose()
        _client = None

async def _queue_worker():
    while True:
        await _queue_event.wait()
        _queue_event.clear()
        await asyncio.sleep(0.5)

        global _pending_adds, _pending_deletes, _session_id, _ubus_session
        adds    = list(_pending_adds);    _pending_adds.clear()
        deletes = list(_pending_deletes); _pending_deletes.clear()
        if not adds and not deletes:
            continue

        config    = _load_config()
        for attempt in range(1, 4):
            try:
                async with _lock:
                    client, router_ip, rtype = await _get_router(config)
                    if not client:
                        raise Exception("No router connection")

                    # ── TYPE_A ──────────────────────────────────────
                    if rtype == "A":
                        await _ensure_typeA(client, config)
                        get_res  = await client.post("/cgi-bin/http.cgi",
                            json={"cmd": 23, "method": "GET",
                                  "language": "en", "sessionId": _session_id})
                        get_data = get_res.json()
                        if get_data.get("message") == "NO_AUTH":
                            raise Exception("NO_AUTH")
                        token = get_data.get("token")
                        rules = get_data.get("datas", [])
                        changed = False

                        for mac in deletes:
                            before = len(rules)
                            rules = [r for r in rules
                                     if r.get("mac","").upper() != mac.upper()]
                            if len(rules) < before:
                                changed = True
                                logger.info(f"TYPE_A removed {mac}")

                        existing = {r.get("mac","").upper() for r in rules}
                        for mac in adds:
                            mu = mac.upper()
                            if mu not in existing:
                                rules.append({"mac": mu, "enableRule": True,
                                              "ippro": "ALL", "remark": "",
                                              "enableLink": True})
                                existing.add(mu); changed = True
                                logger.info(f"TYPE_A added {mac}")

                        if changed:
                            await client.post("/cgi-bin/http.cgi",
                                json={"cmd": 23, "method": "POST",
                                      "language": "en",
                                      "sessionId": _session_id,
                                      "datas": rules, "token": token})
                            await client.post("/cgi-bin/http.cgi",
                                json={"cmd": 20, "method": "POST",
                                      "language": "en",
                                      "sessionId": _session_id, "token": token})
                            logger.info("TYPE_A batch applied ✅")

                    # ── TYPE_B ──────────────────────────────────────
                    elif rtype == "B":
                        await _ensure_typeB(client, router_ip, config)

                        # Unblock (delete parental control for that MAC)
                        for mac in deletes:
                            c, d = await _ubus_call(client, router_ip, _ubus_session,
                                "zwrt_router.api", "router_delete_pctrl_by_mac",
                                {"src_mac": mac.upper()})
                            logger.info(f"TYPE_B unblocked {mac}: code={c}")

                        # Block = add parental control that blocks all day all week
                        for mac in adds:
                            c, d = await _ubus_call(client, router_ip, _ubus_session,
                                "zwrt_router.api", "router_set_pctrl", {
                                    "src_mac": mac.upper(),
                                    "weekdays": "1234567",
                                    "start_time": "0000",
                                    "stop_time": "2359",
                                    "enabled": 1,
                                    "action": "add"
                                })
                            logger.info(f"TYPE_B blocked {mac}: code={c}")

                break  # success
            except Exception as e:
                logger.error(f"Queue worker attempt {attempt}/3: {e}")
                _session_id   = None
                _ubus_session = None
                _router_type  = None
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
# Public block / unblock API
# ---------------------------------------------------------------------------

async def block_device(mac: str) -> bool:
    _pending_deletes.add(mac)   # "delete from allowed" = block
    _start_queue_worker()
    _queue_event.set()
    logger.info(f"Queued block for {mac}")
    return True

async def unblock_device(mac: str) -> bool:
    _pending_adds.add(mac)      # "add to allowed" = unblock
    _start_queue_worker()
    _queue_event.set()
    logger.info(f"Queued unblock for {mac}")
    return True

# ---------------------------------------------------------------------------
# sync_whitelist_to_router — called by Washa System
# ---------------------------------------------------------------------------

async def sync_whitelist_to_router(whitelist: list[dict]) -> bool:
    global _session_id, _ubus_session
    config = _load_config()

    if not whitelist:
        logger.warning("sync_whitelist_to_router: empty list — skipping to prevent lockout")
        return False

    async with _lock:
        try:
            client, router_ip, rtype = await _get_router(config)
            if not client:
                return False

            # ── TYPE_A ──────────────────────────────────────────────
            if rtype == "A":
                await _ensure_typeA(client, config)

                get_res  = await client.post("/cgi-bin/http.cgi",
                    json={"cmd": 23, "method": "GET",
                          "language": "en", "sessionId": _session_id})
                get_data = get_res.json()
                if get_data.get("message") == "NO_AUTH":
                    _session_id = None
                    await _ensure_typeA(client, config)
                    get_res  = await client.post("/cgi-bin/http.cgi",
                        json={"cmd": 23, "method": "GET",
                              "language": "en", "sessionId": _session_id})
                    get_data = get_res.json()

                token = get_data.get("token")
                rules = get_data.get("datas", [])

                # Enable whitelist mode (CMD 28, 30)
                for mode_cmd in [28, 30]:
                    mode_res  = await client.post("/cgi-bin/http.cgi",
                        json={"cmd": mode_cmd, "method": "GET",
                              "language": "en", "sessionId": _session_id})
                    mode_data = mode_res.json()
                    if "datas" in mode_data:
                        mt = mode_data.get("token")
                        mr = mode_data["datas"]
                        ch = False
                        for r in mr:
                            if r.get("acceptAll") is not False:
                                r["acceptAll"] = False; ch = True
                        if ch:
                            await client.post("/cgi-bin/http.cgi",
                                json={"cmd": mode_cmd, "method": "POST",
                                      "language": "en", "sessionId": _session_id,
                                      "datas": mr, "token": mt})
                            logger.info(f"TYPE_A whitelist mode CMD {mode_cmd} ✅")

                existing = {r.get("mac","").upper() for r in rules}
                changed  = False
                for entry in whitelist:
                    mu = entry.get("mac","").upper()
                    if mu not in existing:
                        rules.append({"mac": mu, "enableRule": True,
                                      "ippro": "ALL", "remark": "",
                                      "enableLink": True})
                        existing.add(mu); changed = True
                        logger.info(f"TYPE_A sync added {mu}")

                if changed:
                    await client.post("/cgi-bin/http.cgi",
                        json={"cmd": 23, "method": "POST", "language": "en",
                              "sessionId": _session_id,
                              "datas": rules, "token": token})

                await client.post("/cgi-bin/http.cgi",
                    json={"cmd": 20, "method": "POST", "language": "en",
                          "sessionId": _session_id, "token": token})
                logger.info("TYPE_A sync whitelist done ✅")
                return True

            # ── TYPE_B ──────────────────────────────────────────────
            elif rtype == "B":
                await _ensure_typeB(client, router_ip, config)

                # For TYPE_B: block unauthorized devices using per-device parental control
                # NEVER use macipport_filter_switch DROP — it bricks the router
                # Only unblock whitelisted MACs (remove their pctrl block if any)
                for entry in whitelist:
                    mac = entry.get("mac", "").upper()
                    await _ubus_call(client, router_ip, _ubus_session,
                        "zwrt_router.api", "router_delete_pctrl_by_mac",
                        {"src_mac": mac})
                    logger.info(f"TYPE_B unblocked (whitelisted) {mac}")

                logger.info("TYPE_B sync done — DNS Blocker handles unauthorized devices ✅")
                return True

        except Exception as e:
            logger.error(f"sync_whitelist_to_router failed: {e}")
            _session_id   = None
            _ubus_session = None
            _router_type  = None
            return False

    return False

# ---------------------------------------------------------------------------
# purge_unauthorized_macs — remove non-whitelisted MACs from router
# ---------------------------------------------------------------------------

async def purge_unauthorized_macs(allowed_macs: set) -> bool:
    global _session_id, _ubus_session
    config = _load_config()

    async with _lock:
        try:
            client, router_ip, rtype = await _get_router(config)
            if not client:
                return False

            if rtype == "A":
                await _ensure_typeA(client, config)
                get_res  = await client.post("/cgi-bin/http.cgi",
                    json={"cmd": 23, "method": "GET",
                          "language": "en", "sessionId": _session_id})
                get_data = get_res.json()
                token    = get_data.get("token")
                rules    = get_data.get("datas", [])
                allowed_upper = {m.upper() for m in allowed_macs}
                new_rules = [r for r in rules
                             if r.get("mac","").upper() in allowed_upper]
                if len(new_rules) < len(rules):
                    await client.post("/cgi-bin/http.cgi",
                        json={"cmd": 23, "method": "POST", "language": "en",
                              "sessionId": _session_id,
                              "datas": new_rules, "token": token})
                    await client.post("/cgi-bin/http.cgi",
                        json={"cmd": 20, "method": "POST", "language": "en",
                              "sessionId": _session_id, "token": token})
                    logger.info("TYPE_A purged unauthorized MACs ✅")

            elif rtype == "B":
                await _ensure_typeB(client, router_ip, config)
                # For TYPE_B: block every device NOT in allowed set via pctrl
                _, arp_data = await _ubus_call(client, router_ip, _ubus_session,
                    "zwrt_router.api", "router_get_arptable")
                allowed_upper = {m.upper() for m in allowed_macs}
                for entry in arp_data.get("arptable", []):
                    mac = entry.get("mac","").upper()
                    if mac and mac not in allowed_upper:
                        await _ubus_call(client, router_ip, _ubus_session,
                            "zwrt_router.api", "router_set_pctrl", {
                                "src_mac": mac,
                                "weekdays": "1234567",
                                "start_time": "0000",
                                "stop_time": "2359",
                                "enabled": 1,
                                "action": "add"
                            })
                logger.info("TYPE_B purged unauthorized MACs via pctrl ✅")

            return True
        except Exception as e:
            logger.error(f"purge_unauthorized_macs failed: {e}")
            return False

# ---------------------------------------------------------------------------
# disable_whitelist_mode — called by Zima System
# ---------------------------------------------------------------------------

async def disable_whitelist_mode() -> bool:
    global _session_id, _ubus_session
    config = _load_config()

    async with _lock:
        try:
            client, router_ip, rtype = await _get_router(config)
            if not client:
                return False

            if rtype == "A":
                await _ensure_typeA(client, config)
                for mode_cmd in [28, 30]:
                    mode_res  = await client.post("/cgi-bin/http.cgi",
                        json={"cmd": mode_cmd, "method": "GET",
                              "language": "en", "sessionId": _session_id})
                    mode_data = mode_res.json()
                    if "datas" in mode_data:
                        mt = mode_data.get("token")
                        mr = mode_data["datas"]
                        ch = False
                        for r in mr:
                            if r.get("acceptAll") is not True:
                                r["acceptAll"] = True; ch = True
                        if ch:
                            await client.post("/cgi-bin/http.cgi",
                                json={"cmd": mode_cmd, "method": "POST",
                                      "language": "en", "sessionId": _session_id,
                                      "datas": mr, "token": mt})
                            logger.info(f"TYPE_A allow-all CMD {mode_cmd} ✅")
                get_res = await client.post("/cgi-bin/http.cgi",
                    json={"cmd": 23, "method": "GET",
                          "language": "en", "sessionId": _session_id})
                token = get_res.json().get("token")
                await client.post("/cgi-bin/http.cgi",
                    json={"cmd": 20, "method": "POST", "language": "en",
                          "sessionId": _session_id, "token": token})
                logger.info("TYPE_A allow-all applied ✅")

            elif rtype == "B":
                await _ensure_typeB(client, router_ip, config)
                # Only clear pctrl blocks — never touch macipport_filter_switch
                _, macs_data = await _ubus_call(client, router_ip, _ubus_session,
                    "zwrt_router.api", "router_get_macs_setted_pctrl")
                for mac in macs_data.get("macs", []):
                    await _ubus_call(client, router_ip, _ubus_session,
                        "zwrt_router.api", "router_delete_pctrl_by_mac",
                        {"src_mac": mac})
                logger.info("TYPE_B all pctrl blocks cleared ✅")

            return True
        except Exception as e:
            logger.debug(f"disable_whitelist_mode failed (router may be offline): {e}")
            return False

# ---------------------------------------------------------------------------
# set_dhcp_dns — point clients to our DNS blocker
# ---------------------------------------------------------------------------

async def set_dhcp_dns(dns_ip: str) -> bool:
    global _session_id, _ubus_session
    config = _load_config()

    async with _lock:
        try:
            client, router_ip, rtype = await _get_router(config)
            if not client:
                return False

            if rtype == "A":
                await _ensure_typeA(client, config)
                # Try CMD 1
                res = await client.post("/cgi-bin/http.cgi",
                    json={"cmd": 1, "method": "GET",
                          "language": "en", "sessionId": _session_id})
                data  = res.json()
                token = data.get("token")
                datas = data.get("datas", [])
                changed = False; dns_found = False
                for entry in datas:
                    for k in ("dnsPrimary", "dns1", "primaryDns"):
                        if k in entry:
                            dns_found = True
                            if entry[k] != dns_ip:
                                entry[k] = dns_ip; changed = True
                    for k in ("dnsSecondary", "dns2", "secondaryDns"):
                        if k in entry and entry[k] not in ("0.0.0.0", "", dns_ip):
                            entry[k] = ""; changed = True
                if not dns_found:
                    raise Exception("No DNS key in CMD 1")
                if changed:
                    await client.post("/cgi-bin/http.cgi",
                        json={"cmd": 1, "method": "POST", "language": "en",
                              "sessionId": _session_id,
                              "datas": datas, "token": token})
                    logger.info(f"TYPE_A DHCP DNS → {dns_ip} ✅")
                else:
                    logger.info("TYPE_A DHCP DNS already set correctly")
                return True

            elif rtype == "B":
                # TYPE_B: router DHCP DNS cannot be set via web API (access denied)
                # The DNS Blocker + ARP spoof handle interception instead
                logger.info("TYPE_B: DHCP DNS not settable via API — relying on DNS Blocker + ARP spoofing")
                return True

        except Exception as e:
            logger.warning(f"set_dhcp_dns failed: {e}")
            # Try CMD 219 fallback for TYPE_A
            try:
                res = await client.post("/cgi-bin/http.cgi",
                    json={"cmd": 219, "method": "GET",
                          "language": "en", "sessionId": _session_id})
                data  = res.json()
                token = data.get("token")
                datas = data.get("datas", [])
                changed = False
                for entry in datas:
                    for k in ("dnsPrimary", "dns1"):
                        if k in entry and entry[k] != dns_ip:
                            entry[k] = dns_ip; changed = True
                if changed:
                    await client.post("/cgi-bin/http.cgi",
                        json={"cmd": 219, "method": "POST", "language": "en",
                              "sessionId": _session_id,
                              "datas": datas, "token": token})
                    logger.info(f"TYPE_A CMD 219 DHCP DNS → {dns_ip} ✅")
                return True
            except Exception as e2:
                logger.warning(f"set_dhcp_dns CMD 219 also failed: {e2}")
                return False

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

async def cleanup():
    global _client
    if _client:
        await _client.aclose()
        _client = None
