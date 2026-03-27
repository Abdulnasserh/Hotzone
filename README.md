# HotZone Pro — Automated WiFi Voucher System

An automated, ultra-fast WiFi Hotspot and Voucher system. It uses a **custom reverse-engineered native HTTP API** to directly inject firewall rules into ZTE-based 4G routers (like Airtel CPEs), dropping the internet authorization speed from 15 seconds to under **0.1 seconds**.

## How It Works

```text
STEP 1 — Scan to Connect WiFi
  Customer scans QR #1 → Phone auto-joins WiFi network
    ↓
  Connected to WiFi, but NO internet (Router firewall blocks them)

STEP 2 — Buy a Voucher
  Customer scans QR #2 or uses a pre-printed Voucher Code
    ↓
  Server authenticates the payment or verifies the active code
    ↓
  **Reverse-Engineered Native API kicks in!**
    ↓
  Python sends `{"cmd": 28}` directly to `/cgi-bin/http.cgi`
    ↓
  Router applies hardware-level WHITELIST instantly!
    ↓
  Voucher expires later → Python deletes the rule → Customer loses internet
```

## The Reverse-Engineered Router API

> **Compatible with:** ZTE-based 4G LTE CPE routers commonly branded by Airtel, MTN, Vodafone, and other African/Asian ISPs.

Unlike traditional hotspot systems that rely on a slow, RAM-heavy headless browser (Playwright) to click buttons on the router's admin panel, HotZone speaks the router's **internal JSON-RPC language** directly via raw HTTP. This section documents every API call so that any developer can reuse or extend this system.

**Base URL:** `http://192.168.1.1` (or your router's gateway IP)  
**Endpoint:** `POST /cgi-bin/http.cgi`  
**Content-Type:** `application/json`

---

### Step 1: Get a Login Challenge Token (CMD 232)

Before you can authenticate, you must request a one-time random challenge token from the router. No credentials are needed for this step.

**Request:**
```json
{
  "cmd": 232,
  "method": "GET",
  "sessionId": "",
  "language": "en"
}
```

**Response:**
```json
{
  "token": "a8f3b2c91d4e756f...",
  "sessionId": "tmp_session_abc123...",
  "success": true
}
```

The `token` is a random string generated fresh by the router every time. It expires after a few seconds.

---

### Step 2: Authenticate with SHA256 Hash (CMD 100)

You never send the raw password to the router. Instead, you concatenate the `token` from Step 1 with your admin password, then SHA256 hash the result. You also generate your own `sessionId` (two concatenated MD5 hashes of random UUIDs).

**Python Example:**
```python
import hashlib, uuid

token = "a8f3b2c91d4e756f..."  # From Step 1
password = "your_admin_password"

# Hash: SHA256(token + password)
hashed_pw = hashlib.sha256((token + password).encode()).hexdigest()

# Generate your own sessionId
def md5(s): return hashlib.md5(s.encode()).hexdigest()
session_id = md5(str(uuid.uuid4())) + md5(str(uuid.uuid4()))
```

**Request:**
```json
{
  "cmd": 100,
  "method": "POST",
  "sessionId": "your_generated_session_id",
  "username": "admin",
  "passwd": "sha256_hashed_password_here",
  "isAutoUpgrade": "0",
  "language": "en"
}
```

**Response (Success):**
```json
{
  "AUTH": "OK",
  "sessionId": "your_generated_session_id",
  "success": true
}
```

Your `sessionId` is now authenticated. Use it in **every** subsequent request.

---

### Step 3: Verify Session is Still Alive (CMD 269)

Router sessions expire after inactivity. Before making important calls, verify your session is still valid:

**Request:**
```json
{
  "cmd": 269,
  "method": "GET",
  "sessionId": "your_session_id",
  "language": "en"
}
```

If the response contains `"message": "NO_AUTH"`, your session has expired and you must re-authenticate from Step 1.

---

### Step 4: Read Connected Devices / DHCP List (CMD 223)

Fetch the list of all phones, laptops, and devices physically connected to the router's WiFi:

**Request:**
```json
{
  "cmd": 223,
  "method": "GET",
  "sessionId": "your_session_id",
  "language": "en"
}
```

**Response:**
```json
{
  "dhcp_list_info": [
    {
      "mac": "0E:E7:14:46:8A:D3",
      "ip": "192.168.1.101",
      "hostname": "iPhone-Abdul"
    },
    {
      "mac": "DC:29:19:46:1F:27",
      "ip": "192.168.1.105",
      "hostname": "SAMSUNG-Galaxy"
    }
  ],
  "success": true,
  "token": "abc123..."
}
```

Each object in `dhcp_list_info` represents a device currently associated with the router's WiFi antenna.

---

### Step 5: Read Current MAC Filter Rules (CMD 23 GET)

The router's MAC filter table controls who is **allowed** or **blocked** from accessing the internet. Read it first before making changes:

**Request:**
```json
{
  "cmd": 23,
  "method": "GET",
  "sessionId": "your_session_id",
  "language": "en"
}
```

**Response:**
```json
{
  "datas": [
    {
      "mac": "0E:E7:14:46:8A:D3",
      "enableRule": true,
      "ippro": "IPV4",
      "remark": "",
      "enableLink": true
    },
    {
      "mac": "DC:29:19:46:1F:27",
      "enableRule": true,
      "ippro": "IPV4",
      "remark": "",
      "enableLink": true
    }
  ],
  "token": "xyz789...",
  "success": true
}
```

> **IMPORTANT:** You must save the `token` from this response — it is required when writing changes back (anti-CSRF protection).

---

### Step 6: Write MAC Filter Rules (CMD 23 POST)

To grant or revoke internet access, modify the `datas` array from Step 5 and POST it back with the same `token`:

**To ADD a device** (grant internet): Append a new rule object to the `datas` array.  
**To REMOVE a device** (block internet): Filter the MAC out of the `datas` array.

**Request (write back the modified rules):**
```json
{
  "cmd": 23,
  "method": "POST",
  "sessionId": "your_session_id",
  "language": "en",
  "token": "xyz789...",
  "datas": [
    {
      "mac": "0E:E7:14:46:8A:D3",
      "enableRule": true,
      "ippro": "IPV4",
      "remark": "",
      "enableLink": true
    }
  ]
}
```

**Rule Object Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `mac` | string | Device MAC address (uppercase, colon-separated) |
| `enableRule` | bool | `true` = rule is active |
| `ippro` | string | Protocol: `"IPV4"` |
| `remark` | string | Optional label/note |
| `enableLink` | bool | `true` = device is allowed to connect |

---

### Step 7: Apply the Changes (CMD 20)

After writing rules with CMD 23, you **must** fire CMD 20 to tell the router to actually apply them to its firewall:

**Request:**
```json
{
  "cmd": 20,
  "method": "POST",
  "sessionId": "your_session_id",
  "language": "en",
  "token": "xyz789..."
}
```

Without this step, your rule changes will be saved but **not enforced** until the router reboots.

---

### Step 8: Enforce Whitelist Mode (CMD 28 & 30)

By default, routers may be in "Allow All" mode. To make the MAC filter actually block unauthorized devices, you must switch to Whitelist mode:

**Request (repeat for both CMD 28 and CMD 30):**
```json
{
  "cmd": 28,
  "method": "POST",
  "sessionId": "your_session_id",
  "language": "en",
  "token": "token_from_GET",
  "datas": [
    { "acceptAll": false }
  ]
}
```

Setting `"acceptAll": false` means: **"Block everyone by default. Only allow devices that appear in the MAC filter table."**

---

### Step 9: Manage Port Forwarding / Virtual Server (CMD 27)

To expose local servers or devices to the public internet, use the `OTHER_FILTER` command.

**Request (Fetch existing rules):**
```json
{
  "cmd": 27,
  "method": "GET",
  "sessionId": "your_session_id"
}
```

**Request (Add/Update a rule):**
```json
{
  "cmd": 27,
  "method": "POST",
  "sessionId": "your_session_id",
  "token": "token_from_GET",
  "datas": [
    {
      "port": "8080",            // External Port (or range "80:88")
      "mappingIp": "192.168.1.10", // Target Internal IP
      "mappingPort": "80",         // Target Internal Port
      "mappingIpPort": "192.168.1.10:80", // Combined internal IP:Port
      "remark": "MyWebServer",     // Rule Name
      "enableRule": "true",        // "true" to enable, "false" to disable
      "protocol": "TCP",           // "TCP", "UDP", or "TCP&UDP"
      "ifName": "DEFAULT"          // Usually "DEFAULT"
    }
  ]
}

---

### Complete CMD Reference Table

| CMD | Method | Purpose |
|-----|--------|---------|
| 232 | GET | Request a login challenge token (no auth required) |
| 100 | POST | Authenticate using SHA256(token + password) |
| 269 | GET | Verify if current session is still alive |
| 223 | GET | Fetch DHCP list (all connected devices with MAC, IP, hostname) |
| 23 | GET | Read the current MAC filter rules |
| 23 | POST | Write/save modified MAC filter rules |
| 20 | POST | Apply saved rules to the live firewall |
| 28 | GET/POST | Read/set the global MAC filter policy (acceptAll true/false) |
| 30 | GET/POST | Read/set secondary filter enforcement policy |
| 80 | GET | Fetch router system info (firmware version, model, etc.) |
| 27 | GET/POST | Manage Port Forwarding (Virtual Server) rules |
| 272 | GET | Fetch VPN (L2TP/PPTP) Client Settings |
| 269 | POST | Apply VPN Settings (Toggle ON/OFF) |
| 260 | GET/POST | Manage GRE Tunnel Settings |
| 279 | GET/POST | Manage L2TPv3 Bridge Settings |
| 332 | GET/POST | Manage VXLAN Tunnel Settings |


---

### Error Handling

| Response Field | Meaning |
|----------------|---------|
| `"success": true` | Request succeeded |
| `"success": false` | Request failed (check other fields) |
| `"message": "NO_AUTH"` | Session expired — re-authenticate from Step 1 |
| `"AUTH": "OK"` | Login was successful |
| No `token` in response | Something went wrong — retry the request |

### Important Notes

1. **Session Expiry:** Sessions expire after ~5 minutes of inactivity. Always verify with CMD 269 before critical operations.
2. **Rate Limiting:** These routers have weak CPUs. Never fire more than 2-3 requests per second or the router will freeze and require a physical reboot.
3. **Token Rotation:** The `token` field in GET responses is a CSRF-protection nonce. You must include it when POSTing changes, and it changes with every GET.
4. **Concurrency:** Never run two parallel sessions. Use an AsyncIO lock to serialize all router communication.

---
All communication in the HotZone codebase is done natively in Python via `httpx` and queued asynchronously within `router_scraper.py` to prevent crashing the router's fragile low-power CPU.

## Setup & Running

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```
*(No headless browser installation is required anymore!)*

### 2. Run the Server

```bash
python3 server.py
# Or run with the beautiful CustomTkinter window:
python3 gui.py
```

The server instantly starts up on `http://0.0.0.0:8000` and will automatically pop open the Admin Dashboard in your browser!

### 3. Configure the System

All configuration is managed securely through the **Admin Dashboard** (which saves to a local `hotzone.db` SQLite database).
Go to the **Mipangilio** (Settings) tab to enter:
- Your Router's IP and Password
- Your 4-digit Admin PIN
- Your WiFi SSID and Password (for printing QR codes)

### 4. Setup your Whitelist

In the **Whitelist** tab, add your personal phone, admin laptop, or Smart TVs. Devices in this list will **never** be blocked by the firewall, ensuring you don't accidentally lock yourself out!

### 5. Print your Signs

The system automatically generates beautifully branded QR cards:
1. **Connect QR:** Customers scan to effortlessly join the WiFi without typing the password.
2. **Payment Page QR:** Customers scan to buy internet time.
3. **Voucher Codes:** You can mass-generate 24-hour printable scratch-card codes.

## System Architecture

| File | Purpose |
|------|---------|
| `server.py` | FastAPI backend — handles APIs, WebSockets, background monitoring, and voucher expiry. |
| `router_scraper.py` | Core Networking — authenticates and fires the `cmd` JSON-RPC payloads to the router's HTTP CGI. |
| `gui.py` | Optional Cross-platform Desktop App interface for starting/stopping the server. |
| `hotzone-admin.html` | Beautiful, mobile-responsive Admin Dashboard. |
| `hotzone.db` | Single-file SQLite database storing all vouchers, whitelists, config, and system logs. |

## Advanced Features

*   **Offline Tracking**: Active customers who lock their phone screens are temporarily marked as "Offline" rather than completely erased from the dashboard, giving the Admin absolute tracking power.
*   **Spoof Protection**: The background monitor continuously guards against MAC Spoofing by comparing historical hostnames.
*   **Concurrency Safe**: Uses Python AsyncIO locks so the backend never drops a packet when multiple people buy vouchers at the exact same millisecond.

## Supported Routing Hardware
- Out of the box: **ZTE-based 4G LTE CPE Routers** (Commonly branded by Airtel, MTN, Vodafone).
---

## Step 10: VPN & Tunneling API (Bypassing CGNAT)

To enable remote management over the internet (where the router is behind an ISP's CGNAT), you must use the VPN/Tunneling capabilities of the ZTE firmware. 

**Important:** Only ONE tunnel type (VPN, GRE, L2TPv3, or VXLAN) can be active at a time.

### VPN Client (L2TP/PPTP)
*   **Fetch Settings (CMD 272)**
*   **Apply Change (CMD 269):** Use this to remotely switch the VPN on or update the server IP.
    *   `vpn_switch`: "1" (ON) / "0" (OFF)
    *   `vpn_mode`: "0" (L2TP) / "1" (PPTP)
    *   `vpn_url`: Your Google Cloud VM IP

### Advanced Tunnels
*   **GRE (CMD 260):** Ideal for fast, unencrypted point-to-point links.
*   **L2TPv3 (CMD 279):** Used for Layer 2 bridging (making the router appear local to your server).
*   **VXLAN (CMD 332):** Modern tunneling for cloud-based network orchestration.

---

## Step 11: Multi-tenant "SaaS Brain" Architecture (GCP)

To scale HotZone Pro to multiple cafes, the system is designed to run on a central **Google Cloud VM (e2-micro)** acting as the master controller.

### 1. Cloud Infrastructure Selection
*   **Region:** Use `us-west1`, `us-central1`, or `us-east1` to qualify for the **GCP Always Free Tier**.
*   **Machine Type:** `e2-micro` (2 vCPU, 1 GB RAM).
*   **OS:** `Ubuntu 24.04 LTS Minimal` (x86_64).
*   **Disk:** 30 GB Standard Persistent Disk (Free Tier limit).
*   **Static IP:** You **must** reserve a Static External IP for your VM so routers never lose the connection to the "Brain."

### 2. Networking Configuration
*   **Firewall:** Allow `HTTP` (80), `HTTPS` (443), and `UDP 500, 4500, 1701` (for L2TP/IPsec VPN).
*   **IP Forwarding:** This must be **Enabled** in the VM's network interface settings to allow the Brain to route customer traffic to the internet.

### 3. Server-Side Stack
*   **VPN Server:** `xl2tpd` + `strongswan` (L2TP/IPsec).
*   **DNS Interceptor:** `dnsmasq` (to capture captive portal checks and redirect them to the VM).
*   **Application:** `FastAPI` + `SQLite` (Managing users, multi-tenant router tokens, and payments).

By moving the logic to the cloud, the local Airtel router becomes a simple "remote enforcer" that receives "Block/Unblock" commands from the VM over the secure VPN tunnel.
