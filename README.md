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

Unlike previous versions that relied on a slow, ram-heavy headless browser (Playwright) to click buttons on the router's admin panel, this system speaks the router's internal JSON-RPC language directly.

### Technical API Documentation (ZTE / Airtel 4G CPE)
*Every request is a POST to `http://192.168.1.1/cgi-bin/http.cgi` with a JSON payload.*

#### 1. Authentication (CMD 232 & 100)
The router uses a SHA256 challenge-response login system.
1. **Get Token**: `{"cmd": 232, "method": "GET", "sessionId": "", "language": "en"}`. The router responds with a random `token` string and a temporary `sessionId`.
2. **Hash Password**: You must generate a hash locally using `SHA256(token + "your_admin_password")`.
3. **Login**: `{"cmd": 100, "method": "POST", "sessionId": sessionId, "param": {"password": Hash}}`. If successful, your `sessionId` is now firmly authenticated for all future router modifications.

#### 2. Read Connected Devices / DHCP (CMD 113)
To hunt down exactly who is physically connected to the router right now (their phone's MAC address and IP):
* **Payload:** `{"method": "GET", "cmd": 113, "sessionId": sessionId}`
* **Response:** Returns an enormous array of connected users under the `"lan_param"` object block. Example: `[{"mac": "AA:BB...", "ip": "192...", "host": "iPhone"}, ...]`

#### 3. Enforce the Whitelist (CMD 28 & CMD 30)
To grant or block internet access, you have to rewrite the router's internal MAC filter table.
1. **Write the Allowed MACs (CMD 28):** 
   `{"method": "POST", "cmd": 28, "sessionId": sessionId, "param": {"mac_filter_list": "AA:BB:CC:DD:EE:FF,11:22:33:44:55:66"}}`
   *(All actively paying customer MAC addresses must be joined by a comma)*
2. **Enforce Whitelist Blocking Mode (CMD 30):** 
   `{"method": "POST", "cmd": 30, "sessionId": sessionId, "param": {"mode": 1, "acceptAll": false}}`
   *(Setting `acceptAll: false` acts as a kill-switch, instantly dropping internet access for any MAC address globally that was not included in the CMD 28 string)*

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
- Any router where the web panel operates via `/cgi-bin/http.cgi` JSON commands.
