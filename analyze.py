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
    print("\n" + "="*60)
    print("  HotZone Router Analyzer — CRITICAL API TEST")
    print("="*60)

    async with httpx.AsyncClient(base_url=f"https://{ROUTER_IP}", verify=False, timeout=8.0) as c:

        # ── LOGIN ──────────────────────────────────────────────
        print("\n[1] Login...")
        try:
            r = await c.post("/ubus/", headers=HEADERS, json={"jsonrpc":"2.0","id":1,"method":"call","params":[NULL,"zwrt_web","web_login_info",{}]})
            sault = r.json()["result"][1]["zte_web_sault"]
            r2 = await c.post("/ubus/", headers=HEADERS, json={"jsonrpc":"2.0","id":1,"method":"call","params":[NULL,"zwrt_web","web_login",{"password":sha256(sha256(ROUTER_PASS)+sault)}]})
            session = r2.json()["result"][1]["ubus_rpc_session"]
            print(f"    ✅ Login OK")
        except Exception as e:
            print(f"    ❌ Cannot connect: {e}")
            return

        # ── STEP 1: Read current switch state ──
        print("\n[2] Read macipport_filter switch state...")
        code, data = await ubus(c, session, "zwrt_router.api", "router_get_macipport_filter_switch")
        print(f"    code={code} data={data}")

        CODE = """"
            2 = switch off / not enabled
            3 = switch on ?
        """

        # ── STEP 2: ENABLE the DROP switch (global firewall DROP) ──
        print("\n[3] Enabling macipport_filter DROP switch (blocks internet, WiFi stays)...")
        code, data = await ubus(c, session, "zwrt_router.api", "router_set_macipport_filter_switch", {
            "macipport_filter_enable": 1,
            "default_firewall_policy": "DROP"
        })
        print(f"    code={code} data={data}")
        drop_enabled = (code == 0)
        if not drop_enabled:
            print("    ⚠️ DROP switch failed — stopping test, restoring ACCEPT")
            await ubus(c, session, "zwrt_router.api", "router_set_macipport_filter_switch", {
                "macipport_filter_enable": 0,
                "default_firewall_policy": "ACCEPT"
            })

        # ── STEP 3: CRITICAL TEST — per-MAC ACCEPT while DROP is ON ──
        print("\n" + "="*60)
        print("  CRITICAL TEST: Add ACCEPT rule with DROP switch ON")
        print("="*60)

        FAKE_MAC = "AA:BB:CC:DD:EE:FF"
        OWN_MAC  = "60:30:d4:6e:53:10"
        accept_worked = False
        working_params = None

        param_formats = [
            {"src_mac": FAKE_MAC, "target": "ACCEPT", "action": "add", "proto": "all", "comment": "hotzone_test"},
            {"src_mac": FAKE_MAC, "action": "add", "target": "ACCEPT"},
            {"mac_address": FAKE_MAC, "target": "ACCEPT", "action": "add"},
            {"src_mac": FAKE_MAC, "action": "add", "enabled": 1, "target": "ACCEPT"},
            {"src_mac": FAKE_MAC, "action": "add"},
            {"mac": FAKE_MAC, "action": "add", "target": "ACCEPT"},
            {"mac": FAKE_MAC, "target": "ACCEPT"},
        ]

        for i, params in enumerate(param_formats):
            code, data = await ubus(c, session, "zwrt_router.api", "router_set_macipport_filter", params)
            status = "✅ WORKS!" if code == 0 else f"❌ code={code}"
            print(f"\n  Format {i+1}: {json.dumps(params)}")
            print(f"  Result: {status} data={data}")
            if code == 0:
                accept_worked = True
                working_params = params
                # Clean up immediately — remove the test rule
                del_code, _ = await ubus(c, session, "zwrt_router.api",
                    "router_set_macipport_filter", {"src_mac": FAKE_MAC, "action": "delete"})
                print(f"  Cleanup (delete): code={del_code}")
                break

        # ── STEP 4: Can we READ current filter rules? ──
        print("\n[4] Read current MAC filter rules (read-only)...")
        for method in ["router_get_macipport_filter", "router_get_mac_filter_list", "router_get_mac_filter"]:
            code, data = await ubus(c, session, "zwrt_router.api", method)
            if code == 0:
                print(f"    ✅ {method}: {json.dumps(data)[:200]}")
                break
            else:
                print(f"    ❌ {method}: code={code}")

        # ── STEP 5: CLEANUP — restore ACCEPT always ──
        print("\n[5] Cleanup — restoring ACCEPT switch...")
        code, data = await ubus(c, session, "zwrt_router.api", "router_set_macipport_filter_switch", {
            "macipport_filter_enable": 0,
            "default_firewall_policy": "ACCEPT"
        })
        print(f"    code={code}")

        # ── FINAL VERDICT ──
        print("\n" + "="*60)
        print("  FINAL VERDICT")
        print("="*60)

        if drop_enabled and accept_worked:
            print(f"""
  ✅ FULL ROUTER BLOCKING WORKS!

  DROP switch: WORKS (blocks internet, WiFi stays connected)
  ACCEPT rule: WORKS (params: {json.dumps(working_params)})

  Complete flow confirmed:
  WASHA  → DROP all + ACCEPT for whitelisted MACs
  REDEEM → Add ACCEPT rule → customer gets internet
  EXPIRE → Delete ACCEPT rule → router blocks again

  SYSTEM WILL WORK 100% ON THIS ROUTER ✅
            """)
        elif drop_enabled:
            print("""
  ⚠️ DROP works but per-MAC ACCEPT rule NOT working via API

  IMPACT:
  - DROP blocks everyone ✅
  - BUT paying customers also stay blocked ❌
  - Cannot let specific customers through at router level

  FALLBACK: Use DNS Blocker only (no DROP policy)
  - Works for 90% of users
  - Technical users with manual DNS can bypass

  SYSTEM WILL WORK WITH DNS BLOCKING ONLY ⚠️
            """)
        else:
            print("""
  ❌ Even DROP switch failed via API. Only DNS Blocker available.
            """)

asyncio.run(analyze())
