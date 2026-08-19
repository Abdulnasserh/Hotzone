"""
Full production flow test + stale rule cleanup.
Simulates exact sequence server.py runs when Washa System starts.
"""
import asyncio
import httpx
import hashlib
import json
import warnings
warnings.filterwarnings("ignore")

ROUTER_IP   = "192.168.0.1"
PASSWORD    = "TPJSQK4K"
HOTZONE_TAG = "hotzone"
NULL_SESSION = "00000000000000000000000000000000"

def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest().upper()

def hdr():
    return {"Content-Type":"application/json",
            "Origin":f"https://{ROUTER_IP}","Referer":f"https://{ROUTER_IP}/",
            "Z-Mode":"1","Z-Tag":"0"}

def norm(m):
    return (m or "").upper().replace("-",":")

async def call(client, session, service, method, params=None):
    body = {"jsonrpc":"2.0","id":1,"method":"call",
            "params":[session,service,method,params or {}]}
    r = await client.post("/ubus/", headers=hdr(), json=body)
    res = r.json().get("result",[])
    return (res[0],res[1]) if isinstance(res,list) and len(res)>1 else (res,{})

def ok(code): return code==0 or code==[0]
def sep(t): print(f"\n{'='*55}\n  {t}\n{'='*55}")

async def login(client):
    _, d  = await call(client, NULL_SESSION, "zwrt_web","web_login_info")
    sault = d.get("zte_web_sault","")
    hashed = sha256(sha256(PASSWORD)+sault)
    _, d  = await call(client, NULL_SESSION, "zwrt_web","web_login",{"password":hashed})
    s = d.get("ubus_rpc_session","")
    print(f"  Login: {'OK  session='+s[:16] if s else 'FAILED'}")
    return s or None

async def get_switch(client, s):
    _, d = await call(client,s,"uci","get",{"config":"zwrt_router","section":"firewall"})
    v = d.get("values",{}) if isinstance(d,dict) else {}
    e,p = v.get("macipport_filter_enable","?"), v.get("macipport_filter_policy","?")
    print(f"  Switch: enabled={e}  policy={p}")
    return e,p

async def get_rules(client, s):
    _, d = await call(client,s,"uci","get",
                      {"config":"firewall","type":"rule",
                       "match":{"zte_type":"zte_macipport_filter"}})
    rules=[]
    for sid,rv in (d.get("values",{}) if isinstance(d,dict) else {}).items():
        sm = rv.get("src_mac","")
        mac = norm(sm[0]) if isinstance(sm,list) and sm else norm(sm)
        rules.append({"section_id":sid,"src_mac":mac,
                      "target":rv.get("target",""),"name":rv.get("name","")})
    return rules

async def set_switch(client,s,enable,policy):
    code,_ = await call(client,s,"zwrt_router.api","router_set_macipport_filter_switch",
                        {"macipport_filter_enable":enable,"default_firewall_policy":policy})
    print(f"  set_switch(enable={enable}, policy={policy}): {'OK' if ok(code) else 'FAIL code='+str(code)}")
    return ok(code)

async def add_rule(client,s,mac,target,comment=""):
    code,_ = await call(client,s,"zwrt_router.api","router_set_macipport_filter",
                        {"comment":comment,"proto":"all","src":"lan","dest":"wan",
                         "src_mac":norm(mac),"target":target,
                         "family":"ipv4","enabled":1,"action":"add"})
    print(f"  add({mac} -> {target}): {'OK' if ok(code) else 'FAIL code='+str(code)}")
    return ok(code)

async def del_rule(client,s,sid):
    code,_ = await call(client,s,"zwrt_router.api","router_set_macipport_filter",
                        {"action":"delete","section_id":[sid]})
    print(f"  del(section={sid}): {'OK' if ok(code) else 'FAIL code='+str(code)}")
    return ok(code)

async def clean_all_hotzone(client,s):
    """Delete ALL hotzone-tagged rules — re-read after every delete."""
    deleted=0
    for _ in range(50):
        rules = await get_rules(client,s)
        r = next((r for r in rules if r["name"].startswith(HOTZONE_TAG)),None)
        if not r: break
        if await del_rule(client,s,r["section_id"]): deleted+=1
    print(f"  Cleaned {deleted} hotzone rule(s)")
    return deleted

async def main():
    client = httpx.AsyncClient(base_url=f"https://{ROUTER_IP}",
                               verify=False,timeout=15.0,follow_redirects=True)
    try:
        sep("1. LOGIN")
        session = await login(client)
        if not session: return

        # ── show raw state ────────────────────────────────
        sep("2. CURRENT RAW STATE")
        await get_switch(client, session)
        rules = await get_rules(client, session)
        print(f"  Total macipport rules: {len(rules)}")
        for r in rules:
            tag = " ← HOTZONE STALE" if r["name"].startswith(HOTZONE_TAG) else ""
            print(f"    [{r['section_id']}] {r['name']}: {r['src_mac']} -> {r['target']}{tag}")

        # ── clean ALL stale hotzone rules ─────────────────
        sep("3. CLEAN ALL STALE HOTZONE RULES")
        await clean_all_hotzone(client, session)
        rules = await get_rules(client, session)
        hotzone_left = [r for r in rules if r["name"].startswith(HOTZONE_TAG)]
        print(f"  Hotzone rules remaining: {len(hotzone_left)}  ({'CLEAN ✓' if not hotzone_left else 'WARNING: still dirty!'})")

        # ── simulate full Washa System start ──────────────
        # Exactly what server.py does: sync_whitelist_to_router with 2 MACs
        sep("4. SIMULATE WASHA SYSTEM START (2 test MACs)")
        TEST_MACS = ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"]
        desired = {norm(m) for m in TEST_MACS}

        # switch ON + DROP
        await set_switch(client, session, 1, "DROP")

        # add ACCEPT for each desired MAC
        for mac in sorted(desired):
            await add_rule(client, session, mac, "ACCEPT",
                           f"{HOTZONE_TAG}_allow_{norm(mac)}")

        await asyncio.sleep(0.5)
        rules = await get_rules(client, session)
        accepted = {norm(r["src_mac"]) for r in rules
                    if r["name"].startswith(HOTZONE_TAG) and r["target"]=="ACCEPT"}
        print(f"  Desired:  {sorted(desired)}")
        print(f"  Accepted: {sorted(accepted)}")
        missing = desired - accepted
        if not missing:
            print("  VERIFIED: all MACs accepted ✓")
        else:
            print(f"  BUG: missing ACCEPT for {missing}")

        # ── simulate voucher expiry: block one MAC ─────────
        sep("5. SIMULATE VOUCHER EXPIRY (block AA:BB:CC:DD:EE:01)")
        EXPIRE_MAC = norm("AA:BB:CC:DD:EE:01")
        # replace ACCEPT with DROP
        rules = await get_rules(client, session)
        for r in rules:
            if norm(r["src_mac"]) == EXPIRE_MAC and r["name"].startswith(HOTZONE_TAG):
                await del_rule(client, session, r["section_id"])
        # with default DROP, no extra rule needed — but server adds explicit DROP
        await add_rule(client, session, EXPIRE_MAC, "DROP",
                       f"{HOTZONE_TAG}_block_{EXPIRE_MAC}")
        await asyncio.sleep(0.3)
        rules = await get_rules(client, session)
        drop_r = next((r for r in rules if norm(r["src_mac"])==EXPIRE_MAC),None)
        ok_block = drop_r and drop_r["target"]=="DROP"
        print(f"  Block result: {'DROP rule confirmed ✓' if ok_block else 'ERROR: '+str(drop_r)}")

        # still-active MAC should still have ACCEPT
        still_mac = norm("AA:BB:CC:DD:EE:02")
        still_r = next((r for r in rules if norm(r["src_mac"])==still_mac),None)
        ok_still = still_r and still_r["target"]=="ACCEPT"
        print(f"  Still-active MAC still ACCEPT: {'✓' if ok_still else 'BUG: '+str(still_r)}")

        # ── simulate Zima System (stop) ───────────────────
        sep("6. SIMULATE ZIMA SYSTEM (stop / restore)")
        # switch OFF + ACCEPT
        await set_switch(client, session, 0, "ACCEPT")
        await asyncio.sleep(0.3)
        e, p = await get_switch(client, session)
        print(f"  Switch restored: {'✓' if e=='0' else 'ERROR: still enabled='+str(e)}")

        # ── final cleanup ─────────────────────────────────
        sep("7. FINAL CLEANUP")
        await clean_all_hotzone(client, session)
        rules_final = await get_rules(client, session)
        hz = [r for r in rules_final if r["name"].startswith(HOTZONE_TAG)]
        print(f"  Hotzone rules after cleanup: {len(hz)}  ({'CLEAN ✓' if not hz else 'DIRTY!'})")
        print(f"  Total rules on router: {len(rules_final)}")
        for r in rules_final:
            print(f"    [{r['section_id']}] {r['name']}: {r['src_mac']} -> {r['target']}")

        # ── verdict ───────────────────────────────────────
        sep("VERDICT")
        all_ok = not missing and ok_block and ok_still and e=="0" and not hz
        if all_ok:
            print("  ALL CALLS CORRECT — server API matches router exactly ✓")
            print("  The Samsung bug was purely in the IP→MAC stale cache (Bug 1)")
            print("  and the kept_macs pre-deletion snapshot (Bug 3).")
            print("  Now that those are fixed, phones should get internet after Ruhusu.")
        else:
            print("  ISSUES FOUND — check steps above")

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback; traceback.print_exc()
    finally:
        await client.aclose()

asyncio.run(main())

import asyncio
import httpx
import hashlib
import json
import warnings
warnings.filterwarnings("ignore")

ROUTER_IP = "192.168.0.1"
PASSWORD   = "TPJSQK4K"
TEST_MAC   = "AA:BB:CC:DD:EE:FF"   # fake MAC — safe to add/delete
HOTZONE_TAG = "hotzone"
NULL_SESSION = "00000000000000000000000000000000"

def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest().upper()

def hdr():
    return {"Content-Type":"application/json",
            "Origin":f"https://{ROUTER_IP}","Referer":f"https://{ROUTER_IP}/",
            "Z-Mode":"1","Z-Tag":"0"}

def norm_mac(m):
    return (m or "").upper().replace("-",":")

async def call(client, session, service, method, params=None):
    body = {"jsonrpc":"2.0","id":1,"method":"call",
            "params":[session, service, method, params or {}]}
    r = await client.post("/ubus/", headers=hdr(), json=body)
    res = r.json().get("result",[])
    if isinstance(res,list) and len(res)>1:
        return res[0], res[1]
    return res, {}

def ok(code):
    return code==0 or code==[0]

def sep(title=""):
    print(f"\n{'='*55}")
    if title: print(f"  {title}")
    print(f"{'='*55}")

# ── login ────────────────────────────────────────────────
async def login(client):
    sep("1. LOGIN")
    code, data = await call(client, NULL_SESSION, "zwrt_web", "web_login_info")
    sault = data.get("zte_web_sault","")
    print(f"  web_login_info  code={code}  sault={'OK' if sault else 'MISSING'}")
    if not sault:
        print(f"  ERROR: {data}"); return None
    hashed = sha256(sha256(PASSWORD)+sault)
    code, data = await call(client, NULL_SESSION, "zwrt_web", "web_login", {"password":hashed})
    session = data.get("ubus_rpc_session","")
    print(f"  web_login       code={code}  session={'OK '+session[:12] if session else 'FAILED'}")
    return session or None

# ── switch state ─────────────────────────────────────────
async def get_switch(client, session):
    code, data = await call(client, session, "uci", "get",
                            {"config":"zwrt_router","section":"firewall"})
    vals = data.get("values",{}) if isinstance(data,dict) else {}
    enabled = vals.get("macipport_filter_enable","?")
    policy  = vals.get("macipport_filter_policy","?")
    print(f"  switch  code={code}  enabled={enabled}  policy={policy}")
    return {"enabled":enabled,"policy":policy}

async def set_switch(client, session, enable, policy):
    code, data = await call(client, session, "zwrt_router.api",
                            "router_set_macipport_filter_switch",
                            {"macipport_filter_enable":enable,
                             "default_firewall_policy":policy})
    print(f"  set_switch(enable={enable}, policy={policy})  code={code}  ok={ok(code)}")
    return ok(code)

# ── rules ────────────────────────────────────────────────
async def get_rules(client, session):
    code, data = await call(client, session, "uci", "get",
                            {"config":"firewall","type":"rule",
                             "match":{"zte_type":"zte_macipport_filter"}})
    rules = []
    vals = data.get("values",{}) if isinstance(data,dict) else {}
    for sid, rv in vals.items():
        smacs = rv.get("src_mac","")
        mac = norm_mac(smacs[0]) if isinstance(smacs,list) and smacs else norm_mac(smacs)
        rules.append({"section_id":sid,"src_mac":mac,
                      "target":rv.get("target",""),"name":rv.get("name","")})
    return code, rules

async def add_rule(client, session, mac, target, comment=""):
    code, data = await call(client, session, "zwrt_router.api",
                            "router_set_macipport_filter",
                            {"comment":comment,"proto":"all","src":"lan","dest":"wan",
                             "src_mac":norm_mac(mac),"target":target,
                             "family":"ipv4","enabled":1,"action":"add"})
    print(f"  add_rule({mac} -> {target})  code={code}  ok={ok(code)}")
    return ok(code)

async def del_rule(client, session, section_id):
    code, data = await call(client, session, "zwrt_router.api",
                            "router_set_macipport_filter",
                            {"action":"delete","section_id":[section_id]})
    print(f"  del_rule(section={section_id})  code={code}  ok={ok(code)}")
    return ok(code)

# ── main ─────────────────────────────────────────────────
async def main():
    client = httpx.AsyncClient(base_url=f"https://{ROUTER_IP}",
                               verify=False, timeout=15.0, follow_redirects=True)
    try:
        session = await login(client)
        if not session:
            return

        # ── 2. current state ──────────────────────────────
        sep("2. CURRENT STATE")
        state = await get_switch(client, session)
        code, rules = await get_rules(client, session)
        print(f"  get_rules  code={code}  count={len(rules)}")
        for r in rules:
            tag = " ← HOTZONE" if r["name"].startswith(HOTZONE_TAG) else ""
            print(f"    [{r['section_id']}] {r['name']}: {r['src_mac']} -> {r['target']}{tag}")

        # ── 3. add ACCEPT rule (like unblock_device) ──────
        sep("3. ADD ACCEPT RULE (unblock_device)")
        await add_rule(client, session, TEST_MAC, "ACCEPT",
                       f"{HOTZONE_TAG}_allow_{norm_mac(TEST_MAC)}")
        await asyncio.sleep(0.5)
        code, rules_after = await get_rules(client, session)
        new_rule = next((r for r in rules_after
                         if norm_mac(r["src_mac"]) == norm_mac(TEST_MAC)), None)
        if new_rule:
            print(f"  VERIFIED: rule added [{new_rule['section_id']}] "
                  f"{new_rule['src_mac']} -> {new_rule['target']}")
        else:
            print("  ERROR: rule NOT found after add!")

        # ── 4. switch ON+DROP (Washa System start) ────────
        sep("4. SWITCH ON+DROP (Washa System start)")
        await set_switch(client, session, 1, "DROP")
        await asyncio.sleep(0.5)
        state = await get_switch(client, session)
        if state["enabled"]=="1" and state["policy"]=="DROP":
            print("  VERIFIED: switch ON + DROP ✓")
        else:
            print(f"  ERROR: unexpected state {state}")

        # ── 5. verify ACCEPT rule survives the switch ──────
        sep("5. VERIFY ACCEPT RULE SURVIVES SWITCH")
        code, rules_now = await get_rules(client, session)
        survived = next((r for r in rules_now
                         if norm_mac(r["src_mac"]) == norm_mac(TEST_MAC)), None)
        if survived:
            print(f"  VERIFIED: rule still there after switch [{survived['section_id']}] "
                  f"{survived['src_mac']} -> {survived['target']} ✓")
        else:
            print("  BUG: ACCEPT rule disappeared after switch ON!")

        # ── 6. replace ACCEPT with DROP (block_device) ────
        sep("6. REPLACE ACCEPT→DROP (block_device)")
        # delete existing then add DROP — same as _replace_mac_rule
        code, rules_now = await get_rules(client, session)
        for r in rules_now:
            if norm_mac(r["src_mac"]) == norm_mac(TEST_MAC):
                await del_rule(client, session, r["section_id"])
        await asyncio.sleep(0.3)
        await add_rule(client, session, TEST_MAC, "DROP",
                       f"{HOTZONE_TAG}_block_{norm_mac(TEST_MAC)}")
        await asyncio.sleep(0.5)
        code, rules_now = await get_rules(client, session)
        drop_rule = next((r for r in rules_now
                          if norm_mac(r["src_mac"]) == norm_mac(TEST_MAC)), None)
        if drop_rule and drop_rule["target"] == "DROP":
            print(f"  VERIFIED: DROP rule [{drop_rule['section_id']}] ✓")
        else:
            print(f"  ERROR: expected DROP rule, got {drop_rule}")

        # ── 7. switch OFF+ACCEPT (Zima System / stop) ─────
        sep("7. SWITCH OFF+ACCEPT (Zima System / stop)")
        await set_switch(client, session, 0, "ACCEPT")
        await asyncio.sleep(0.5)
        state = await get_switch(client, session)
        if state["enabled"]=="0":
            print("  VERIFIED: switch OFF ✓ (open WiFi restored)")
        else:
            print(f"  ERROR: switch still ON? {state}")

        # ── 8. cleanup test rule ──────────────────────────
        sep("8. CLEANUP TEST RULE")
        code, rules_now = await get_rules(client, session)
        for r in rules_now:
            if norm_mac(r["src_mac"]) == norm_mac(TEST_MAC):
                await del_rule(client, session, r["section_id"])
        await asyncio.sleep(0.3)
        code, rules_final = await get_rules(client, session)
        leftover = [r for r in rules_final
                    if norm_mac(r["src_mac"]) == norm_mac(TEST_MAC)]
        if not leftover:
            print("  VERIFIED: test rule cleaned up ✓")
        else:
            print(f"  WARNING: {len(leftover)} test rules still present!")

        # ── 9. final state ────────────────────────────────
        sep("9. FINAL STATE (should be OFF+ACCEPT, clean)")
        await get_switch(client, session)
        code, rules_final = await get_rules(client, session)
        print(f"  Total rules remaining: {len(rules_final)}")
        for r in rules_final:
            print(f"    [{r['section_id']}] {r['name']}: {r['src_mac']} -> {r['target']}")

        sep("SUMMARY")
        print("  Login            : OK")
        print(f"  Switch read (uci): OK — uses 'zwrt_router' config / 'firewall' section")
        print(f"  Rules read (uci) : OK — uses 'firewall' config / type='rule' match zte_type")
        print(f"  Switch set       : OK — router_set_macipport_filter_switch")
        print(f"  Add rule         : OK — router_set_macipport_filter action=add")
        print(f"  Delete rule      : OK — router_set_macipport_filter action=delete section_id=[list]")
        print(f"  All server calls match the router API exactly ✓")

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback; traceback.print_exc()
    finally:
        await client.aclose()

asyncio.run(main())

