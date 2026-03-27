import httpx
import hashlib
import json
import logging
import asyncio
import uuid
import os
from pathlib import Path

logger = logging.getLogger("router_scraper")

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
        pass
    return {}

_session_id = None
_client = None
_lock = asyncio.Lock()

def get_client(router_ip):
    global _client
    if _client is None:
        _client = httpx.AsyncClient(base_url=f"http://{router_ip}", timeout=10.0)
    return _client

async def _login(client, config):
    global _session_id
    username = config.get("routerUser", "admin")
    password = config.get("routerPass", "")
    
    # 1. Get Token
    try:
        res = await client.post("/cgi-bin/http.cgi", json={"cmd": 232, "method": "GET", "sessionId": "", "language": "en"})
        token = res.json().get("token", "")
        if not token:
            raise Exception(f"No token received. Response: {res.text}")
    except Exception as e:
        logger.error(f"Failed to get login token: {e}")
        raise

    # 2. Hash Password (sha256(token + password))
    hashed_pw = hashlib.sha256((token + password).encode()).hexdigest()
    
    # Generate arbitrary setup sessionId
    def md5(s): return hashlib.md5(s.encode()).hexdigest()
    setup_session = md5(str(uuid.uuid4())) + md5(str(uuid.uuid4()))

    # 3. Post Login
    try:
        login_res = await client.post("/cgi-bin/http.cgi", json={
            "cmd": 100,
            "method": "POST",
            "sessionId": setup_session,
            "username": username,
            "passwd": hashed_pw,
            "isAutoUpgrade": "0",
            "language": "en"
        })
        data = login_res.json()
        if "AUTH" not in data or data.get("success") == False:
            raise Exception(f"Login rejected: {data}")
            
        _session_id = data.get("sessionId")
        logger.info("Successfully established lightning fast API session with router.")
    except Exception as e:
        _session_id = None
        logger.error(f"API Login failed: {e}")
        raise

async def _ensure_logged_in(client, config):
    global _session_id
    if not _session_id:
        await _login(client, config)
        return
        
    # Verify session is still valid
    try:
        res = await client.post("/cgi-bin/http.cgi", json={"cmd": 269, "method": "GET", "sessionId": _session_id, "language": "en"})
        data = res.json()
        if data.get("message") == "NO_AUTH" or not data.get("success"):
            logger.info("API Session expired. Re-authenticating...")
            await _login(client, config)
    except Exception:
        await _login(client, config)


async def scrape_devices() -> list[dict]:
    global _session_id
    config = _load_config()

    router_ip = config.get("routerIp", "192.168.1.1")
    client = get_client(router_ip)

    async with _lock:
        try:
            await _ensure_logged_in(client, config)

            # 1. Scrape DHCP (CMD 223)
            dhcp_res = await client.post("/cgi-bin/http.cgi", json={"cmd": 223, "method": "GET", "language": "en", "sessionId": _session_id})
            dhcp_data = dhcp_res.json()
            
            # fallback to connected_devices (CMD 394 or similar) if needed, but 223 is usually standard
            dhcp_list = dhcp_data.get("dhcp_list_info", [])
            
            # 2. Scrape MAC Filter definitions (CMD 23)
            mac_filter_res = await client.post("/cgi-bin/http.cgi", json={"cmd": 23, "method": "GET", "language": "en", "sessionId": _session_id})
            mac_data = mac_filter_res.json()
            allowed_rules = mac_data.get("datas", [])
            
            allowed_macs = set()
            for rule in allowed_rules:
                if rule.get("enableRule"):
                    allowed_macs.add(rule.get("mac", "").upper())

            devices = []
            dhcp_macs = set()

            for item in dhcp_list:
                mac = item.get("mac", "").upper()
                if not mac or len(mac) != 17:
                    continue
                
                host = item.get("hostname", "unknown")
                if host == "unknown" and item.get("user"):
                    host = item.get("user")
                    
                ip = item.get("ip", "")

                dhcp_macs.add(mac)
                devices.append({
                    "mac": mac,
                    "host": host,
                    "ip": ip,
                    "router_allowed": mac in allowed_macs
                })
                
            # Add allowed devices that are NOT currently in DHCP
            for mac in allowed_macs:
                if mac not in dhcp_macs:
                    devices.append({
                        "host": "—",
                        "mac": mac,
                        "ip": "—",
                        "router_allowed": True
                    })

            logger.debug(f"🛰️ [HARDWARE STATUS] {len(allowed_macs)} devices physically whitelisted on router hardware.")
            return devices

        except Exception as e:
            logger.error(f"API Scraper failed: {e}")
            _session_id = None
            return []


# Background Batch Worker (Simplified via API arrays!)
_pending_adds = set()
_pending_deletes = set()
_queue_task = None
_queue_event = asyncio.Event()

def _start_queue_worker():
    global _queue_task
    if _queue_task is None or _queue_task.done():
        _queue_task = asyncio.create_task(_queue_worker())

async def shutdown_scraper():
    global _queue_task, _client
    if _queue_task and not _queue_task.done():
        _queue_task.cancel()
    if _client is not None:
        await _client.aclose()
        _client = None

async def _queue_worker():
    while True:
        await _queue_event.wait()
        _queue_event.clear()

        # Batch window
        await asyncio.sleep(0.5)

        global _pending_adds, _pending_deletes, _session_id
        adds = list(_pending_adds)
        deletes = list(_pending_deletes)
        _pending_adds.clear()
        _pending_deletes.clear()

        if not adds and not deletes:
            continue

        config = _load_config()

        router_ip = config.get("routerIp", "192.168.1.1")
        client = get_client(router_ip)

        for attempt in range(1, 4):
            try:
                async with _lock:
                    await _ensure_logged_in(client, config)

                    # 1. Get current MAC Filter list & token
                    get_res = await client.post("/cgi-bin/http.cgi", json={"cmd": 23, "method": "GET", "language": "en", "sessionId": _session_id})
                    get_data = get_res.json()
                    logger.debug(f"CMD 23 GET response keys: {list(get_data.keys())}")
                    
                    # Check for auth failure
                    if get_data.get("message") == "NO_AUTH":
                        raise Exception("Session expired (NO_AUTH)")
                    
                    # Validate we got the expected data structure
                    token = get_data.get("token")
                    if "datas" not in get_data or not token:
                        raise Exception(f"Unexpected MAC filter response (keys: {list(get_data.keys())})")
                        
                    rules = get_data.get("datas", [])

                    changed = False
                    
                    # 2. Process Deletes
                    for mac in deletes:
                        mac_upper = mac.upper()
                        # Find and remove
                        original_len = len(rules)
                        rules = [r for r in rules if r.get("mac", "").upper() != mac_upper]
                        if len(rules) < original_len:
                            changed = True
                            logger.info(f"API batch removed {mac_upper} from rules")

                    # 3. Process Adds
                    existing = {r.get("mac", "").upper() for r in rules}
                    for mac in adds:
                        mac_upper = mac.upper()
                        if mac_upper not in existing:
                            rules.append({
                                "mac": mac_upper,
                                "enableRule": True,
                                "ippro": "ALL",
                                "remark": "",
                                "enableLink": True
                            })
                            existing.add(mac_upper)
                            changed = True
                            logger.info(f"API batch added {mac_upper} to rules")

                    if changed:
                        # 4. Save changed Rules
                        save_res = await client.post("/cgi-bin/http.cgi", json={
                            "cmd": 23,
                            "method": "POST",
                            "language": "en",
                            "sessionId": _session_id,
                            "datas": rules,
                            "token": token
                        })
                        save_data = save_res.json()
                        logger.debug(f"CMD 23 POST response: {save_data}")
                        if save_data.get("message") == "NO_AUTH":
                            raise Exception("Session expired on save (NO_AUTH)")
                        if save_data.get("success") == False:
                            raise Exception(f"Router rejected the saved rules: {save_data}")

                        # 5. Apply Filter to enforce changes
                        apply_res = await client.post("/cgi-bin/http.cgi", json={
                            "cmd": 20,
                            "method": "POST",
                            "language": "en",
                            "sessionId": _session_id,
                            "token": token
                        })
                        apply_data = apply_res.json()
                        logger.debug(f"CMD 20 POST response: {apply_data}")
                        if apply_data.get("success") == False:
                            logger.warning(f"Router save succeeded, but APPLY rule call indicated failure: {apply_data}")
                            
                        logger.info("API batch applied routing rules instantly ✅")

                break  # Complete success

            except Exception as e:
                logger.error(f"Batch API attempt {attempt}/3 failed: {e}")
                _session_id = None
                if attempt < 3:
                    await asyncio.sleep(2 * attempt)
                else:
                    # After giving up, we put them back and set the event so they get retried eventually.
                    _pending_adds.update(adds)
                    _pending_deletes.update(deletes)
                    logger.error(f"Batch API gave up after 3 attempts. Adds:{adds} Deletes:{deletes}")


async def block_device(mac: str) -> bool:
    _pending_deletes.add(mac)
    _start_queue_worker()
    _queue_event.set()
    logger.info(f"Queued API block block for {mac}")
    return True

async def unblock_device(mac: str) -> bool:
    _pending_adds.add(mac)
    _start_queue_worker()
    _queue_event.set()
    logger.info(f"Queued API unblock for {mac}")
    return True


async def sync_whitelist_to_router(whitelist: list[dict]) -> bool:
    global _session_id
    config = _load_config()

    router_ip = config.get("routerIp", "192.168.1.1")
    client = get_client(router_ip)

    async with _lock:
        try:
            await _ensure_logged_in(client, config)

            get_res = await client.post("/cgi-bin/http.cgi", json={"cmd": 23, "method": "GET", "language": "en", "sessionId": _session_id})
            get_data = get_res.json()
            token = get_data.get("token")
            rules = get_data.get("datas", [])

            # --- API REQUEST TO CHANGE DEFAULT RULE TO WHITELIST ---
            # CMD 28 and 30 handle the default accept/deny policies (Whitelist vs Blacklist)
            # acceptAll: false implies "Whitelist mode" (deny all except what is defined)
            for mode_cmd in [28, 30]:
                mode_res = await client.post("/cgi-bin/http.cgi", json={"cmd": mode_cmd, "method": "GET", "language": "en", "sessionId": _session_id})
                mode_data = mode_res.json()
                if "datas" in mode_data:
                    mode_token = mode_data.get("token")
                    mode_rules = mode_data["datas"]
                    mode_changed = False
                    
                    for r in mode_rules:
                        if r.get("acceptAll") is not False: # Ensure Whitelist mode!
                            r["acceptAll"] = False
                            mode_changed = True
                            
                    if mode_changed:
                        await client.post("/cgi-bin/http.cgi", json={
                            "cmd": mode_cmd, "method": "POST", "language": "en", 
                            "sessionId": _session_id, "datas": mode_rules, "token": mode_token
                        })
                        logger.info(f"API sync enforced Whitelist mode for CMD {mode_cmd} ✅")
            # -------------------------------------------------------------

            existing = {r.get("mac", "").upper() for r in rules}
            changed = False

            for authorized in whitelist:
                mac_upper = authorized.get("mac", "").upper()
                if mac_upper not in existing:
                    rules.append({
                        "mac": mac_upper,
                        "enableRule": True,
                        "ippro": "ALL",
                        "remark": "",
                        "enableLink": True
                    })
                    existing.add(mac_upper)
                    changed = True
                    logger.info(f"API sync added {mac_upper}")

            if changed:
                await client.post("/cgi-bin/http.cgi", json={"cmd": 23, "method": "POST", "language": "en", "sessionId": _session_id, "datas": rules, "token": token})
                await client.post("/cgi-bin/http.cgi", json={"cmd": 20, "method": "POST", "language": "en", "sessionId": _session_id, "token": token})
                logger.info("API sync completed whitelist enforcement ✅")
                
            return True

        except Exception as e:
            logger.error(f"API sync failed: {e}")
            _session_id = None
            return False

async def purge_unauthorized_macs(allowed_macs: set) -> bool:
    global _session_id
    config = _load_config()

    router_ip = config.get("routerIp", "192.168.1.1")
    client = get_client(router_ip)

    async with _lock:
        try:
            await _ensure_logged_in(client, config)

            get_res = await client.post("/cgi-bin/http.cgi", json={"cmd": 23, "method": "GET", "language": "en", "sessionId": _session_id})
            get_data = get_res.json()
            token = get_data.get("token")
            rules = get_data.get("datas", [])

            original_len = len(rules)
            allowed_macs_upper = {m.upper() for m in allowed_macs}
            
            # Keep only rules that are in the allowed_macs set
            rules = [r for r in rules if r.get("mac", "").upper() in allowed_macs_upper]

            if len(rules) < original_len:
                await client.post("/cgi-bin/http.cgi", json={"cmd": 23, "method": "POST", "language": "en", "sessionId": _session_id, "datas": rules, "token": token})
                await client.post("/cgi-bin/http.cgi", json={"cmd": 20, "method": "POST", "language": "en", "sessionId": _session_id, "token": token})
                logger.info("API sync purged unauthorized MACs ✅")
                
            return True

        except Exception as e:
            logger.error(f"API purge failed: {e}")
            _session_id = None
            return False

async def cleanup():
    # No playwright browser to cleanup anymore!
    global _client
    if _client:
        await _client.aclose()
        _client = None
