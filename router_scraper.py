import httpx
import hashlib
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
# TYPE_B (ubus) — ZTE 5G CPE at 192.168.0.1 (e.g. YAS shop router)
# Login: password only (no username), double SHA256
# Router-level block: zwrt_router.api router_set_macipport_filter
#   - Rules only act when the macipport switch is ON. Reads go through
#     uci.get (zwrt_router/firewall) — NOT router_get_macip* (doesn't exist).
#   - Verified live against the shop router 2026-08:
#       add    → {action:"add", src_mac, target:ACCEPT/DROP, src:"lan",
#                 dest:"wan", family:"ipv4", proto:"all", enabled:1}
#       delete → {action:"delete", section_id:[<id>]}   (MUST be a list)
#       switch → {macipport_filter_enable:0/1, default_firewall_policy:"DROP"/"ACCEPT"}
#   - DROP rules only gate src=lan → dest=wan (internet). LAN→LAN (portal
#     server) still works, so voucher customers can reach the login page.
# ---------------------------------------------------------------------------
# Magnet hotzone rules we manage are tagged "hotzone_*" so we never touch
# the admin's manually-created rules.
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
        # Same envelope the router's own web UI sends
        "Z-Mode": "1",
        "Z-Tag": "0",
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
    password = (config.get("routerPass") or "").strip()
    if password in ("••••••••", "••••", "****", "********", "", None):
        password = "TPJSQK4K"

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
# macipport_filter — the router-level block mechanism (VERIFIED live)
# ---------------------------------------------------------------------------

def _norm_mac(mac: str) -> str:
    return (mac or "").upper().replace("-", ":")

async def _get_filter_switch(client, router_ip, session):
    """Read the macipport switch state from uci config zwrt_router/firewall."""
    code, data = await _ubus_call(client, router_ip, session,
        "uci", "get", {"config": "zwrt_router", "section": "firewall"})
    vals = data.get("values", {}) if isinstance(data, dict) else {}
    return {
        "enabled": vals.get("macipport_filter_enable", "0"),
        "policy":  vals.get("macipport_filter_policy", "ACCEPT"),
    }

async def _get_macipport_rules(client, router_ip, session):
    """Read existing macipport rules via uci.get. Returns list of
    {section_id, src_mac, target}."""
    code, data = await _ubus_call(client, router_ip, session,
        "uci", "get", {"config": "firewall", "type": "rule",
                       "match": {"zte_type": "zte_macipport_filter"}})
    rules = []
    vals = data.get("values", {}) if isinstance(data, dict) else {}
    for sid, rv in vals.items():
        smacs = rv.get("src_mac")
        first_mac = _norm_mac(smacs[0]) if isinstance(smacs, list) and smacs else \
                    _norm_mac(smacs) if isinstance(smacs, str) else ""
        rules.append({
            "section_id": sid,
            "src_mac": first_mac,
            "target": rv.get("target", ""),
            "name": rv.get("name", ""),
        })
    return rules

async def _set_filter_switch(client, router_ip, session, enable: int, policy: str):
    """Enable/disable macipport filter.
    nat_enable=1 is required — without it the lan→wan forwarding rule stays
    disabled and ALL clients are blocked even with ACCEPT rules."""
    code, data = await _ubus_call(client, router_ip, session,
        "zwrt_router.api", "router_set_macipport_filter_switch",
        {"macipport_filter_enable": enable,
         "default_firewall_policy": policy,
         "nat_enable": 1})
    return _is_success(code), code, data

async def _add_filter_rule(client, router_ip, session, mac: str, target: str, comment: str = "") -> bool:
    """Add a per-MAC rule. target='ACCEPT' grants internet, 'DROP' cuts it.
    src=lan → dest=wan so LAN-only (portal server) traffic stays working."""
    code, data = await _ubus_call(client, router_ip, session,
        "zwrt_router.api", "router_set_macipport_filter", {
            "comment": comment,
            "proto": "all",
            "src": "lan",
            "dest": "wan",
            "src_mac": _norm_mac(mac),
            "target": target,
            "family": "ipv4",
            "enabled": 1,
            "action": "add",
        })
    ok = _is_success(code)
    if not ok:
        logger.error(f"add rule failed mac={mac} target={target}: code={code} data={data}")
    return ok

async def _delete_filter_rule(client, router_ip, session, section_id: str) -> bool:
    """Delete a rule. section_id MUST be a list — single value returns code=[2]."""
    code, data = await _ubus_call(client, router_ip, session,
        "zwrt_router.api", "router_set_macipport_filter",
        {"action": "delete", "section_id": [section_id]})
    ok = _is_success(code)
    if not ok:
        logger.error(f"delete rule failed section_id={section_id}: code={code} data={data}")
    return ok

async def _delete_hotzone_rules(client, router_ip, session, keep_ids: set = None) -> int:
    """Delete ALL remaining hotzone rules we own. The router re-indexes/IIHR
    section IDs after each delete, so we re-read the list every iteration
    instead of trusting a stale snapshot. Returns how many were deleted."""
    deleted = 0
    for _ in range(200):  # safety cap
        rules = await _get_macipport_rules(client, router_ip, session)
        target = None
        for r in rules:
            if str(r.get("name", "")).startswith(HOTZONE_TAG) and \
               (keep_ids is None or r["section_id"] not in keep_ids):
                target = r
                break
        if target is None:
            break
        if await _delete_filter_rule(client, router_ip, session, target["section_id"]):
            deleted += 1
    return deleted

# ---------------------------------------------------------------------------
# Public API — VERIFIED approach (2026-08 live router test):
#
# Router firmware bug: policy=DROP disables lan→wan forwarding entirely.
# ACCEPT rules are ignored because forwarding layer is off.
#
# CORRECT approach: policy=ACCEPT (forwarding stays ON) + DROP rules for
# unauthorized MACs only.
#   - block_device(mac)   → add DROP rule   → internet cut for that MAC
#   - unblock_device(mac) → delete DROP rule → internet restored (ACCEPT default)
#   - sync_whitelist_to_router(authorized) → switch ON+ACCEPT, block all
#     currently connected MACs that are NOT in authorized set
#   - disable_whitelist_mode → delete all hotzone rules + switch OFF
# ---------------------------------------------------------------------------

HOTZONE_TAG = "hotzone"

async def _delete_mac_rules(client, router_ip, session, mac: str):
    """Delete ALL hotzone rules for a specific MAC — re-read after every delete."""
    for _ in range(50):
        rules = await _get_macipport_rules(client, router_ip, session)
        target = next((r for r in rules
                       if _norm_mac(r.get("src_mac")) == mac
                       and str(r.get("name","")).startswith(HOTZONE_TAG)), None)
        if target is None:
            break
        await _delete_filter_rule(client, router_ip, session, target["section_id"])

async def block_device(mac: str) -> bool:
    """Add DROP rule for this MAC — cuts internet, WiFi stays on.
    Returns False silently if router rule limit (10) is reached."""
    mac = _norm_mac(mac)
    config = _load_config()
    router_ip = _get_router_ip()
    try:
        async with _lock:
            client = _get_client(router_ip)
            session = await _ensure_logged_in(client, router_ip, config)
            # Check rule count first — router max is 10
            rules = await _get_macipport_rules(client, router_ip, session)
            already = any(_norm_mac(r.get("src_mac","")) == mac for r in rules
                          if str(r.get("name","")).startswith(HOTZONE_TAG))
            if already:
                return True  # already blocked
            if len(rules) >= 10:
                logger.debug(f"Rule limit reached — cannot block {mac} yet")
                return False
            # Remove any stale rule then add DROP
            await _delete_mac_rules(client, router_ip, session, mac)
            ok = await _add_filter_rule(client, router_ip, session, mac, "DROP",
                                        comment=f"{HOTZONE_TAG}_block_{mac.replace(':','')}")
            if ok:
                logger.info(f"Blocked {mac} — DROP rule added")
            return ok
    except Exception as e:
        logger.error(f"block_device failed: {e}")
        _ubus_session = None
        return False

async def unblock_device(mac: str) -> bool:
    """Remove DROP rule for this MAC — internet restored via ACCEPT default."""
    mac = _norm_mac(mac)
    config = _load_config()
    router_ip = _get_router_ip()
    try:
        async with _lock:
            client = _get_client(router_ip)
            session = await _ensure_logged_in(client, router_ip, config)
            await _delete_mac_rules(client, router_ip, session, mac)
            logger.info(f"Unblocked {mac} — DROP rule removed, ACCEPT by default")
            return True
    except Exception as e:
        logger.error(f"unblock_device failed: {e}")
        _ubus_session = None
        return False

# ---------------------------------------------------------------------------
# sync_whitelist_to_router — Washa System
#
# 1. Switch ON + ACCEPT default (forwarding stays enabled)
# 2. For every connected client NOT in authorized set → add DROP rule
# 3. Delete DROP rules for MACs that ARE now authorized
# ---------------------------------------------------------------------------

async def sync_whitelist_to_router(authorized: list[dict],
                                    connected: list[dict] | None = None) -> bool:
    """authorized = [{mac:...}] list of MACs that should have internet.
    connected  = [{mac:...}] currently connected clients (from router scrape).
                 If None, scrapes the router itself."""
    global _ubus_session
    try:
        async with _lock:
            config = _load_config()
            router_ip = _get_router_ip()
            client = _get_client(router_ip)
            session = await _ensure_logged_in(client, router_ip, config)

            # Switch ON + ACCEPT — forwarding stays enabled
            ok, code, data = await _set_filter_switch(client, router_ip, session, 1, "ACCEPT")
            if not ok:
                logger.error(f"switch ON/ACCEPT failed: code={code} data={data}")
                return False
            logger.info("macipport switch ON, policy ACCEPT — forwarding active")

            auth_macs = {_norm_mac(w.get("mac","")) for w in authorized if w.get("mac")}

            # Get connected clients if not provided
            if connected is None:
                connected = []
                try:
                    from router_scraper import scrape_devices as _sd
                    connected = await _sd(acquire_lock=False)
                except Exception:
                    pass

            connected_macs = {_norm_mac(d.get("mac","")) for d in connected if d.get("mac")}

            # Get existing hotzone rules
            rules = await _get_macipport_rules(client, router_ip, session)

            # Delete DROP rules for MACs that are now authorized
            for r in rules:
                if (str(r.get("name","")).startswith(HOTZONE_TAG)
                        and r.get("target") == "DROP"
                        and _norm_mac(r.get("src_mac","")) in auth_macs):
                    await _delete_filter_rule(client, router_ip, session, r["section_id"])

            # Delete stale DROP rules for MACs no longer connected
            rules = await _get_macipport_rules(client, router_ip, session)
            for r in rules:
                if (str(r.get("name","")).startswith(HOTZONE_TAG)
                        and r.get("target") == "DROP"
                        and connected_macs
                        and _norm_mac(r.get("src_mac","")) not in connected_macs):
                    await _delete_filter_rule(client, router_ip, session, r["section_id"])

            # Add DROP for every connected MAC not in authorized set
            # Router hard limit: 10 macipport rules max
            MAX_RULES = 10
            rules = await _get_macipport_rules(client, router_ip, session)
            already_blocked = {_norm_mac(r.get("src_mac","")) for r in rules
                               if str(r.get("name","")).startswith(HOTZONE_TAG)
                               and r.get("target") == "DROP"}
            current_count = len(rules)
            blocked = 0
            for mac in connected_macs:
                if current_count >= MAX_RULES:
                    logger.warning(f"Router rule limit ({MAX_RULES}) reached — {len(connected_macs)-blocked} MACs not blocked yet, instant_block_enforcer will handle them as slots free up")
                    break
                if mac and mac not in auth_macs and mac not in already_blocked:
                    ok2 = await _add_filter_rule(client, router_ip, session, mac, "DROP",
                                                 comment=f"{HOTZONE_TAG}_block_{mac.replace(':','')}")
                    if ok2:
                        blocked += 1
                        current_count += 1

            logger.info(f"Washa sync: {len(auth_macs)} authorized, "
                        f"{blocked} new DROP rules, {len(connected_macs)} connected")
            return True
    except Exception as e:
        logger.error(f"sync_whitelist_to_router failed: {e}")
        _ubus_session = None
        return False

async def purge_unauthorized_macs(allowed_macs: set) -> bool:
    """Block all currently connected MACs not in allowed_macs."""
    try:
        devices = await scrape_devices()
        for d in devices:
            mac = _norm_mac(d.get("mac",""))
            if mac and mac not in allowed_macs:
                await block_device(mac)
        return True
    except Exception as e:
        logger.debug(f"purge_unauthorized_macs: {e}")
        return False

# ---------------------------------------------------------------------------
# disable_whitelist_mode — Zima System
# ---------------------------------------------------------------------------

async def disable_whitelist_mode() -> bool:
    global _ubus_session
    try:
        async with _lock:
            config = _load_config()
            router_ip = _get_router_ip()
            client = _get_client(router_ip)
            session = await _ensure_logged_in(client, router_ip, config)
            # Delete all hotzone rules
            await _delete_hotzone_rules(client, router_ip, session)
            # Switch OFF → ACCEPT default → everyone has internet
            ok, _, _ = await _set_filter_switch(client, router_ip, session, 0, "ACCEPT")
            if ok:
                logger.info("Zima System: all rules cleared, open internet restored")
            return ok
    except Exception as e:
        logger.debug(f"disable_whitelist_mode failed: {e}")
        _ubus_session = None
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
