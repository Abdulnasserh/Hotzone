"""
Quick self-test of the NEW router_scraper macipport functions against the
live router. Tests in this order, cleaning up after itself:
  1. disable_whitelist_mode  (baseline: allow all)
  2. unblock_device(fake)    -> ACCEPT rule added
  3. block_device(fake)      -> DROP rule added (goal: eventually DROP wins)
  4. sync_whitelist_to_router([{mac: fake}]) -> switch DROP + ACCEPT for fake
  5. disable_whitelist_mode  -> switch off, rules cleaned
Also queries the switch state to print current whitelist status.
"""
import asyncio, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from router_scraper import (
    disable_whitelist_mode, unblock_device, block_device,
    sync_whitelist_to_router, purge_unauthorized_macs,
    _load_config, _get_router_ip, _get_client, _ensure_logged_in,
    _get_filter_switch, _get_macipport_rules,
)

FAKE = "AA:BB:CC:DD:EE:99"

async def main():
    print("== 0. login setup ==")
    cfg = _load_config()
    ip = _get_router_ip()
    c = _get_client(ip)
    s = await _ensure_logged_in(c, ip, cfg)
    print("logged in, session", s[:12])

    print("\n== 1. disable_whitelist_mode (baseline) ==")
    await disable_whitelist_mode()
    state = await _get_filter_switch(c, ip, s)
    print("switch:", state)

    print("\n== 2. unblock_device(fake) -> ACCEPT ==")
    ok = await unblock_device(FAKE)
    print("result:", ok)
    rules = await _get_macipport_rules(c, ip, s)
    for r in rules:
        print("   rule:", r)

    print("\n== 3. block_device(fake) -> DROP ==")
    ok = await block_device(FAKE)
    print("result:", ok)
    rules = await _get_macipport_rules(c, ip, s)
    for r in rules:
        print("   rule:", r)

    print("\n== 4. sync_whitelist_to_router([fake]) ==")
    ok = await sync_whitelist_to_router([{"mac": FAKE}])
    print("result:", ok)
    state = await _get_filter_switch(c, ip, s)
    print("switch:", state)
    rules = await _get_macipport_rules(c, ip, s)
    print("rules now:")
    for r in rules:
        print("   rule:", r)

    print("\n== 5. disable_whitelist_mode (cleanup) ==")
    await disable_whitelist_mode()
    state = await _get_filter_switch(c, ip, s)
    print("switch:", state)
    rules = await _get_macipport_rules(c, ip, s)
    print("rules left:", rules)

asyncio.run(main())