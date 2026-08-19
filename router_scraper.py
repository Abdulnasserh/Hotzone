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
    code, data = await _ubus_call(client, router_ip, session,
        "zwrt_router.api", "router_set_macipport_filter_switch",
        {"macipport_filter_enable": enable, "default_firewall_policy": policy})
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
# Public API: block / unblock (voucher redemption + expiry)
#
# Router-level enforcement via macipport_filter (VERIFIED live):
#  - block   → add DROP rule for the MAC (internet cut, WiFi stays on)
#  - unblock → add ACCEPT rule for the MAC (whitelist mode) so internet flows
# ---------------------------------------------------------------------------

HOTZONE_TAG = "hotzone"   # tag used in rule comment; we only touch our own rules

async def _replace_mac_rule(client, router_ip, session, mac: str, target: str) -> bool:
    """Set a per-MAC rule to the desired target, replacing any existing
    hotzone rule for the same MAC (so we never end up with conflicting
    ACCEPT+DROP rules). Re-reads the rule list after every delete so
    router section-id re-indexing never leaves stale orphan rules."""
    # Delete all existing hotzone rules for this MAC — re-read each time
    # because the router re-indexes section IDs after every deletion.
    for _ in range(50):
        rules = await _get_macipport_rules(client, router_ip, session)
        target_rule = None
        for r in rules:
            if _norm_mac(r.get("src_mac")) == mac and str(r.get("name", "")).startswith(HOTZONE_TAG):
                target_rule = r
                break
        if target_rule is None:
            break
        await _delete_filter_rule(client, router_ip, session, target_rule["section_id"])

    comment = f"{HOTZONE_TAG}_allow_{mac}" if target == "ACCEPT" else f"{HOTZONE_TAG}_block_{mac}"
    return await _add_filter_rule(client, router_ip, session, mac, target, comment=comment)

async def block_device(mac: str) -> bool:
    """Voucher expired — set a router-level DROP rule for the MAC."""
    mac = _norm_mac(mac)
    config = _load_config()
    router_ip = _get_router_ip()
    try:
        async with _lock:
            client = _get_client(router_ip)
            session = await _ensure_logged_in(client, router_ip, config)
            ok = await _replace_mac_rule(client, router_ip, session, mac, "DROP")
            if ok:
                logger.info(f"Voucher expired for {mac} — DROP rule active, WiFi stays on")
            return ok
    except Exception as e:
        logger.error(f"block_device failed: {e}")
        _ubus_session = None
        return False

async def unblock_device(mac: str) -> bool:
    """Voucher redeemed — set an ACCEPT rule so the MAC gets internet
    even when the router default policy is DROP (whitelist mode)."""
    mac = _norm_mac(mac)
    config = _load_config()
    router_ip = _get_router_ip()
    try:
        async with _lock:
            client = _get_client(router_ip)
            session = await _ensure_logged_in(client, router_ip, config)
            ok = await _replace_mac_rule(client, router_ip, session, mac, "ACCEPT")
            if ok:
                logger.info(f"Voucher redeemed for {mac} — ACCEPT rule active")
            return ok
    except Exception as e:
        logger.error(f"unblock_device failed: {e}")
        _ubus_session = None
        return False

# ---------------------------------------------------------------------------
# sync_whitelist_to_router — Washa System
#
# Puts the router into WHITELIST / captive-portal mode:
#   1. switch = ON, default policy = DROP  → nobody has internet by default
#   2. add ACCEPT rule for every authorized MAC (whitelist + active vouchers)
#   3. delete any stale hotzone DROP/ACCEPT rules (blocked MACs are now
#      blocked by the DROP default alone)
# WiFi stays OPEN so customers can connect and reach the portal page
# (LAN→LAN is not filtered, only lan→wan internet).
# ---------------------------------------------------------------------------

async def sync_whitelist_to_router(whitelist: list[dict]) -> bool:
    global _ubus_session
    try:
        async with _lock:
            config = _load_config()
            router_ip = _get_router_ip()
            client = _get_client(router_ip)
            session = await _ensure_logged_in(client, router_ip, config)

            # Desired state: switch ON + DROP default
            ok, code, data = await _set_filter_switch(client, router_ip, session, 1, "DROP")
            if not ok:
                logger.error(f"switch ON/DROP failed: code={code} data={data}")
                return False
            logger.info("macipport switch ON, default policy DROP — WiFi open, internet gated")

            # Desired ACCEPT set = all authorized MACs
            desired = {_norm_mac(w.get("mac", "")) for w in whitelist if w.get("mac")}

            # Delete our stale rules first (ACCEPT no longer desired; DROP rules
            # are redundant since default DROP covers them). Re-read after every
            # delete so section-id re-indexing never leaves orphan rules.
            for _ in range(200):
                rules_now = await _get_macipport_rules(client, router_ip, session)
                stale = None
                for r in rules_now:
                    if not str(r.get("name", "")).startswith(HOTZONE_TAG):
                        continue
                    # keep ACCEPT rules whose MAC is still desired
                    if r["target"] == "ACCEPT" and r.get("src_mac") in desired:
                        continue
                    stale = r
                    break
                if stale is None:
                    break
                await _delete_filter_rule(client, router_ip, session, stale["section_id"])

            # Re-read AFTER deletions — kept_macs must reflect current router state,
            # not the pre-deletion snapshot (stale snapshot caused missing ACCEPT rules).
            rules_after = await _get_macipport_rules(client, router_ip, session)
            kept_macs = {r["src_mac"] for r in rules_after
                         if str(r.get("name", "")).startswith(HOTZONE_TAG) and r["target"] == "ACCEPT"}

            # Add ACCEPT for any desired MAC not already accepted
            for mac in sorted(desired):
                if mac and mac not in kept_macs:
                    ok2 = await _add_filter_rule(client, router_ip, session, mac,
                                                 "ACCEPT", comment=f"{HOTZONE_TAG}_allow_{mac}")
                    if not ok2:
                        logger.warning(f"Could not ACCEPT {mac}")

            logger.info(f"Whitelist synced: OK on switch DROP + {len(desired)} ACCEPT rules")
            return True
    except Exception as e:
        logger.error(f"sync_whitelist_to_router failed: {e}")
        _ubus_session = None
        return False

# ---------------------------------------------------------------------------
# purge_unauthorized_macs — block all currently connected non-whitelisted
# ---------------------------------------------------------------------------

async def purge_unauthorized_macs(allowed_macs: set) -> bool:
    """With whitelist mode active (default DROP), non-whitelisted devices are
    already blocked by the router's DROP default. This is a no-op that
    confirms the switch is still enforcing."""
    global _ubus_session
    try:
        async with _lock:
            config = _load_config()
            router_ip = _get_router_ip()
            client = _get_client(router_ip)
            session = await _ensure_logged_in(client, router_ip, config)
            state = await _get_filter_switch(client, router_ip, session)
            enforcing = state.get("enabled") == "1" and state.get("policy") == "DROP"
            logger.info(f"purge_unauthorized_macs: switch={state.get('enabled')} policy={state.get('policy')} "
                        f"enforcing={enforcing}")
            return enforcing
    except Exception as e:
        logger.debug(f"purge_unauthorized_macs failed (router offline?): {e}")
        return False

# ---------------------------------------------------------------------------
# disable_whitelist_mode — Zima System (open everything)
# ---------------------------------------------------------------------------

async def disable_whitelist_mode() -> bool:
    global _ubus_session
    try:
        async with _lock:
            config = _load_config()
            router_ip = _get_router_ip()
            client = _get_client(router_ip)
            session = await _ensure_logged_in(client, router_ip, config)

            # Delete our hotzone rules (re-read each iteration — the router
            # re-indexes section ids on every delete, so a stale list can miss)
            await _delete_hotzone_rules(client, router_ip, session)

            # Switch OFF → default ACCEPT → everyone has internet
            ok, _, _ = await _set_filter_switch(client, router_ip, session, 0, "ACCEPT")
            if ok:
                logger.info("Zima System: whitelist disabled, all devices allowed")
            return ok
    except Exception as e:
        logger.debug(f"disable_whitelist_mode failed (router offline?): {e}")
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
