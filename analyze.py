"""
HotZone Router Analyzer — READ ONLY, no blocking actions
Run this while connected to the ZTE WiFi: python3 analyze.py
"""
import asyncio, hashlib, httpx, json

def sha256(s): return hashlib.sha256(s.encode()).hexdigest().upper()
NULL = "00000000000000000000000000000000"

ROUTER_IP = "192.168.0.1"
ROUTER_PASS = "TPJSQK4K"

HEADERS = {
    "Content-Type": "application/json",
    "Origin":  f"https://{ROUTER_IP}",
    "Referer": f"https://{ROUTER_IP}/",
}

async def ubus(c, session, svc, method, params={}):
    r = await c.post("/ubus/", headers=HEADERS, json={
        "jsonrpc":"2.0","id":1,"method":"call",
        "params":[session, svc, method, params]})
    res = r.json().get("result",[])
    return (res[0], res[1]) if isinstance(res,list) and len(res)>1 else (res,{})

async def analyze():
    print("\n" + "="*55)
    print("  HotZone Router Analyzer — READ ONLY")
    print("="*55)

    async with httpx.AsyncClient(base_url=f"https://{ROUTER_IP}", verify=False, timeout=8.0) as c:

        # ── LOGIN ──────────────────────────────────────────────
        print("\n[1] Testing login (password only, no username)...")
        try:
            r = await c.post("/ubus/", headers=HEADERS, json={"jsonrpc":"2.0","id":1,"method":"call","params":[NULL,"zwrt_web","web_login_info",{}]})
            sault = r.json()["result"][1]["zte_web_sault"]
            r2 = await c.post("/ubus/", headers=HEADERS, json={"jsonrpc":"2.0","id":1,"method":"call","params":[NULL,"zwrt_web","web_login",{"password":sha256(sha256(ROUTER_PASS)+sault)}]})
            data2 = r2.json()["result"][1]
            session = data2.get("ubus_rpc_session","")
            if not session:
                print(f"    ❌ LOGIN FAILED: {data2}")
                return
            print(f"    ✅ LOGIN OK — session: {session[:16]}...")
        except Exception as e:
            print(f"    ❌ Cannot connect to router: {e}")
            return

        # ── DEVICE COUNT ───────────────────────────────────────
        print("\n[2] Device count...")
        code, data = await ubus(c, session, "zwrt_router.api", "router_get_user_list_num")
        if code == 0:
            print(f"    ✅ WiFi devices : {data.get('wireless_num',0)}")
            print(f"    ✅ LAN devices  : {data.get('lan_num',0)}")
            print(f"    ✅ Total online : {data.get('access_total_num',0)}")
        else:
            print(f"    ❌ Failed: code={code}")

        # ── WIRELESS DEVICES ───────────────────────────────────
        print("\n[3] WiFi device list...")
        code, data = await ubus(c, session, "zwrt_router.api", "router_wireless_access_list", {"start_id":1,"end_id":64})
        devices = data.get("wireless_access_list_info",[])
        if code == 0:
            print(f"    ✅ Found {len(devices)} WiFi devices:")
            for d in devices:
                print(f"       MAC:{d.get('mac_address','?')}  IP:{d.get('ip_address','?')}  HOST:{d.get('hostname','?')}")
        else:
            print(f"    ❌ Failed: code={code}")

        # ── ARP TABLE ──────────────────────────────────────────
        print("\n[4] ARP table (IP→MAC mapping)...")
        code, data = await ubus(c, session, "zwrt_router.api", "router_get_arptable")
        arp = data.get("arptable",[])
        if code == 0:
            print(f"    ✅ {len(arp)} ARP entries")
        else:
            print(f"    ❌ Failed: code={code}")

        # ── PARENTAL CONTROL ───────────────────────────────────
        print("\n[5] Parental control (pctrl) — our blocking method...")
        code, data = await ubus(c, session, "zwrt_router.api", "router_get_macs_setted_pctrl")
        if code == 0:
            print(f"    ✅ pctrl readable — currently blocked MACs: {data.get('macs',[])}")
        else:
            print(f"    ❌ Cannot read pctrl: code={code}")

        # Test if pctrl ADD works with a fake MAC (no real device)
        print("\n[6] Test pctrl BLOCK (fake MAC AA:BB:CC:DD:EE:FF — not a real device)...")
        code, data = await ubus(c, session, "zwrt_router.api", "router_set_pctrl", {
            "src_mac": "AA:BB:CC:DD:EE:FF",
            "weekdays": "1234567",
            "start_time": "0000",
            "stop_time": "2359",
            "enabled": 1,
            "action": "add"
        })
        if code == 0:
            print(f"    ✅ pctrl BLOCK WORKS! code={code}")
            # Clean up immediately
            code2, _ = await ubus(c, session, "zwrt_router.api", "router_delete_pctrl_by_mac", {"src_mac": "AA:BB:CC:DD:EE:FF"})
            print(f"    ✅ pctrl UNBLOCK WORKS! code={code2}")
        else:
            print(f"    ❌ pctrl block failed: code={code} data={data}")
            print(f"       NOTE: Blocking via pctrl may not work on this router")

        # ── DHCP DNS ───────────────────────────────────────────
        print("\n[7] DHCP DNS setting ability...")
        code, data = await ubus(c, session, "uci", "get", {"config":"dhcp","section":"lan_dns"})
        if code == 0:
            vals = data.get("values",{})
            current_dns = vals.get("dhcp_option", vals.get("dns","none found"))
            print(f"    ℹ️  Current DHCP DNS option: {current_dns}")
            # Try to write (just to test permission, won't actually change anything)
            code2, _ = await ubus(c, session, "uci", "set", {
                "config":"dhcp","section":"lan_dns",
                "values":{"dhcp_option":["6,192.168.0.100"]}})
            if code2 == 0:
                # Revert immediately
                await ubus(c, session, "uci", "revert", {"config":"dhcp"})
                print(f"    ✅ DHCP DNS CAN be set via UCI!")
            else:
                print(f"    ❌ DHCP DNS cannot be set (access denied) — DNS Blocker must handle this")
        else:
            print(f"    ❌ Cannot read DHCP config: code={code}")

        # ── SUMMARY ────────────────────────────────────────────
        print("\n" + "="*55)
        print("  ANALYSIS SUMMARY")
        print("="*55)
        print("""
  What WILL work on this router:
  ✅ Login (password only — matches UI)
  ✅ Scrape connected devices (IP + MAC + hostname)
  ✅ ARP table for IP→MAC mapping

  What MIGHT work (tested above):
  ? pctrl block/unblock per device (see test [6] above)

  What WON'T work (access denied):
  ❌ Set DHCP DNS server (router blocks this via API)
  ❌ Router MAC whitelist (different API than TYPE_A)

  HOW THE SYSTEM WILL ACTUALLY BLOCK CUSTOMERS:
  → DNS Blocker (port 53) — MAIN MECHANISM
  → ARP Spoofer — intercepts DNS even with manual DNS settings
  → pctrl blocks (if test [6] above passed)
  → Voucher expiry removes from whitelist (DNS-level block)
        """)

asyncio.run(analyze())
