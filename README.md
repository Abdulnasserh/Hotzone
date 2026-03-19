# HotZone — WiFi Voucher Hotspot System

Automated WiFi voucher system using mobile money (Snippe API) with Playwright-driven router control for Airtel 4G routers.

## How It Works

```
STEP 1 — Scan to Connect WiFi
  Customer scans QR #1 → Phone auto-joins WiFi network
    ↓
  Connected to WiFi, but NO internet (not whitelisted)

STEP 2 — Scan to Pay
  Customer scans QR #2 → Opens http://<server-ip>:8000
    ↓
  Enters phone number → Clicks "Pay 1,000 TZS"
    ↓
  Snippe sends USSD push → Customer enters PIN
    ↓
  Webhook confirms payment → Server finds MAC via router DHCP
    ↓
  Playwright adds MAC to router whitelist → Customer gets internet!
    ↓
  Voucher expires → Playwright removes MAC → Customer loses internet
```

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
playwright install chromium
```

### 2. Configure

Edit `config.json`:

```json
{
  "routerIp": "192.168.1.1",
  "routerUser": "admin",
  "routerPass": "your_router_password",
  "playwrightEnabled": true,
  "serverIp": "192.168.1.162",
  "snippeApiKey": "your_snippe_api_key",
  "snippeWebhookSecret": "your_webhook_secret",
  "dailyMode": "24hrs",
  "dailyCutoffTime": "22:00",
  "wifiSSID": "HotZone WiFi",
  "wifiPassword": "your_wifi_password",
  "wifiSecurity": "WPA"
}
```

**Get your Snippe API key** at [https://snippe.sh](https://snippe.sh)

### 3. Whitelist Your Devices

Edit `whitelist.json` — add your own devices so they're never blocked:

```json
[
  { "mac": "60:30:D4:6E:53:10", "hostname": "Abduls-MacBook", "label": "Admin MacBook" }
]
```

Find your MAC from the router DHCP list:
- **Router Gateway**: `http://192.168.1.1/index.html?_t=182891#FW_RULE#0`
- Navigate to **System Status → DHCP Information → Device List**

### 4. Run the Server

```bash
python server.py
```

Server runs on `http://0.0.0.0:8000`

### 5. Print QR Code Signs

The system generates **two QR codes** — print both on a sign at your location:

| QR Code | Purpose | What it does |
|---------|---------|-------------|
| **Step 1 — Connect WiFi** | `/api/qr/connect` | Auto-joins the WiFi network (no internet) |
| **Step 2 — Pay for Internet** | `/api/qr/portal` | Opens the payment page on the local network |

Download both QR codes from the Admin Dashboard → QR Codes page.

## Pages

| URL | Description |
|-----|-------------|
| `http://<ip>:8000/` | Customer payment page |
| `http://<ip>:8000/admin` | Admin dashboard |

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI backend — all APIs, WebSocket, background monitor |
| `router_scraper.py` | Playwright automation — scrape devices, block/unblock MACs |
| `static/index.html` | Customer-facing mobile payment page |
| `hotzone-admin.html` | Admin dashboard — devices, vouchers, whitelist, settings |
| `config.json` | Server and router configuration |
| `whitelist.json` | Admin devices (never blocked) |
| `vouchers.json` | Active/expired voucher records |
| `devices.json` | Device tracking for anti-spoofing |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/pay` | Initiate payment `{ phone }` |
| GET | `/api/pay/status?reference=` | Poll payment status |
| POST | `/api/webhooks/snippe` | Snippe webhook receiver |
| GET | `/api/devices` | List devices with status |
| POST | `/api/devices/{mac}/block` | Block device |
| POST | `/api/devices/{mac}/unblock` | Unblock device |
| GET | `/api/whitelist` | List whitelist |
| POST | `/api/whitelist` | Add to whitelist |
| DELETE | `/api/whitelist/{mac}` | Remove from whitelist |
| GET | `/api/config` | Get config (masked) |
| POST | `/api/config` | Update config |
| GET | `/api/vouchers` | List vouchers |
| GET | `/api/revenue` | Revenue summary |
| GET | `/api/qr/connect` | WiFi connection QR (Step 1) |
| GET | `/api/qr/portal` | Payment portal QR (Step 2) |
| WS | `/ws` | WebSocket live events |

## Anti-Spoofing

- **Hostname match, MAC changed** → `suspected_spoof`, kept blocked, admin alerted
- **MAC match, hostname changed** → Logged, voucher stays valid
- Background monitor runs every 10 seconds

## Supported Networks

Airtel Money, M-Pesa, Mixx by Yas, Halotel (all Tanzania)

## Day Modes

- **24hrs**: Voucher valid for 24 hours from activation
- **cutoff**: Voucher expires at fixed time (e.g. 22:00 same day)

## Requirements

- Python 3.10+
- Chromium (installed via `playwright install chromium`)
- Airtel 4G router at 192.168.1.1
- Snippe API account

## Cross-Platform

Works on Windows, macOS, and Linux.
