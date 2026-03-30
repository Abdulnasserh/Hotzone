import requests
import hashlib
import uuid
import json

ROUTER_IP = "192.168.1.1"
PASSWORD = "@xierto2004Abdul"  # Corrected password

# Step 1: Get token
print("Step 1: Fetching token...")
r = requests.post(f"http://{ROUTER_IP}/cgi-bin/http.cgi", json={
    "cmd": 232,
    "method": "GET",
    "sessionId": "",
    "language": "en"
})
token = r.json()["token"]

# Step 2: Login
print("Step 2: authenticating...")
hashed_pw = hashlib.sha256((token + PASSWORD).encode()).hexdigest()
initial_sid = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()

r = requests.post(f"http://{ROUTER_IP}/cgi-bin/http.cgi", json={
    "cmd": 100,
    "method": "POST",
    "sessionId": initial_sid,
    "username": "admin",
    "passwd": hashed_pw,
    "isAutoUpgrade": "0",
    "language": "en"
})
login_data = r.json()
print("Login:", login_data)

if not login_data.get("success"):
    print("Login Failed! Exiting.")
    exit(1)

# CRITICAL: Always use the sessionId returned by the router!
# This was causing 'NO_AUTH' in previous attempts.
actual_sid = login_data.get("sessionId", initial_sid)

# --- Exploratory Commands ---

def check_cmd(cmd_id, name, method="GET", extra_data=None):
    payload = {
        "cmd": cmd_id,
        "method": method,
        "sessionId": actual_sid,
        "language": "en"
    }
    if extra_data:
        payload.update(extra_data)
    
    try:
        r = requests.post(f"http://{ROUTER_IP}/cgi-bin/http.cgi", json=payload, timeout=5)
        res = r.json()
        if res.get("success"):
            print(f"✅ {name} (CMD {cmd_id}):", res)
        else:
            print(f"❌ {name} (CMD {cmd_id}):", res.get("message", "Failed"))
    except Exception as e:
        print(f"⚠️ {name} (CMD {cmd_id}) Error:", e)

print("\n--- Testing Specific Modules ---")
check_cmd(279, "L2TPv3 Bridge")
check_cmd(260, "GRE Settings")
check_cmd(332, "VXLAN Settings")
check_cmd(21, "Bridge Settings")
check_cmd(22, "VLAN Settings")

# Try to set VXLAN with local interface IP (CMD 332 POST)
print("\n--- Testing VXLAN Configuration (POST) ---")
vxlan_payload = {
    "token": token,
    "vxlanSwitch": "1",
    "tunnelName": "tunnel1",
    "vni": "100",
    "dstport": "4789",
    "remoteIP": "8.229.175.67",
    "localIP": "10.0.0.2",   # Try adding internal tunnel IP
    "bridgeToLan": "1"       # Important for L2 bridging
}
check_cmd(332, "VXLAN Set", method="POST", extra_data=vxlan_payload)

# --- Discovery Loop ---
print("\n--- Discovery Loop (Scanning command IDs) ---")
# Scanner for common command IDs to find undocumented features
for cmd in range(1, 500):
    # Skip already checked
    if cmd in [232, 100, 279, 260, 332, 21, 22]:
        continue
    
    try:
        r = requests.post(f"http://{ROUTER_IP}/cgi-bin/http.cgi", json={
            "cmd": cmd,
            "method": "GET",
            "sessionId": actual_sid,
            "language": "en"
        }, timeout=0.5)
        result = r.json()
        # Only log successes that look meaningful
        if result.get("success") and len(result.keys()) > 2:
            print(f"🌟 CMD {cmd}:", list(result.keys()))
    except:
        pass

print("\nDiscovery Complete.")