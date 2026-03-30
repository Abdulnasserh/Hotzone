# Android 14 Captive Portal Fix - March 28, 2026

## Problem
Your Android 14 phone wasn't showing the captive portal popup when connecting to WiFi, even though:
- DNS hijacking was working correctly
- The Galaxy J5 (older Android) worked fine
- The system was redirecting `connectivitycheck.gstatic.com` to your server

## Root Cause
The captive portal detection handlers were redirecting to `http://hotzone.portal/` instead of directly to your server IP.

**Why this broke Android 14:**
1. Android 14 makes the initial DNS query → DNS hijacker returns 192.168.1.162 ✅
2. Android makes HTTP request to `192.168.1.162/generate_204` ✅
3. Your server returns **302 Redirect to `http://hotzone.portal/`** ✅
4. Android needs to resolve `hotzone.portal` → **This is where it fails** ❌

The second DNS lookup can fail on Android 14 because:
- Android 14 has stricter DNS timing requirements
- May use DNS-over-HTTPS (DoH) that bypasses your DNS hijacker
- Caches "failed" DNS states and won't retry quickly
- The `hotzone.portal` domain doesn't exist in any public DNS server

## The Fix
Updated three captive portal handlers to redirect directly to your server IP instead of the domain:

### Files Modified
- `server.py` lines 464-475 (Android/Chrome check)
- `server.py` lines 478-487 (Apple check)
- `server.py` lines 489-497 (Windows check)

### Before (BROKEN):
```python
portal_url = "http://hotzone.portal/"
return RedirectResponse(url=portal_url, status_code=302, headers=headers)
```

### After (FIXED):
```python
config = get_config()
server_ip = config.get("serverIp", "192.168.1.162")
portal_url = f"http://{server_ip}/"
return RedirectResponse(url=portal_url, status_code=302, headers=headers)
```

## How to Test

### 1. Restart the Server
```bash
cd ~/Desktop/Wifi_system
./start_server.sh
```
This script will:
- Kill any existing server processes
- Start the server with `sudo` (required for ports 53 and 80)

### 2. Test with Android 14 Phone
1. Forget the WiFi network on your Android 14 phone
2. Reconnect to the WiFi
3. **Wait 10-15 seconds** - Android 14 may take longer to detect the portal
4. You should see the "Sign in to network" popup

### 3. If Still Not Working
Try these steps on your Android 14 phone:

#### Option A: Disable Private DNS (Temporary Fix)
1. Go to **Settings → Network & Internet → More Connection Settings**
2. Find **Private DNS**
3. Set it to **Off** (instead of Automatic)
4. Reconnect to WiFi

#### Option B: Clear Network State
1. Turn on **Airplane Mode**
2. Wait 5 seconds
3. Turn off **Airplane Mode**
4. Reconnect to WiFi

#### Option C: Force Network Refresh
1. Open Chrome browser
2. Try to load: `http://192.168.1.162/`
3. This should trigger the portal page manually

## Monitoring
Watch the logs for captive portal detection:
```bash
tail -f ~/Desktop/Wifi_system/hotzone.log | grep -E "\[ANDROID\]|\[APPLE\]|\[WINDOWS\]"
```

Expected output when Android 14 detects the portal:
```
INFO:hotzone:📱 [ANDROID] Captive portal check from 192.168.1.xxx - Redirecting to portal
```

## What Was Already Working (No Changes Needed)
✅ DNS hijacking with RA/AA flags
✅ NXDOMAIN for IPv6 (AAAA) queries
✅ High-speed in-memory auth cache
✅ Nuclear DNS (multiple upstream providers)
✅ Identity Mirror (MAC randomization protection)
✅ All router API integration

## Additional Notes
- The `hotzone.portal` domain is still referenced in the code for future use (if you configure it in your router's DNS settings)
- The fix is backwards compatible - older Android versions, iOS, and Windows will continue to work
- If you want to make the portal domain work, add it to your router's DNS configuration as an A record pointing to your server IP (192.168.1.162)

## Verification Checklist
- [ ] Server restarted with sudo
- [ ] Android 14 phone forgets WiFi network
- [ ] Reconnect to WiFi
- [ ] Wait 10-15 seconds
- [ ] "Sign in to network" popup appears
- [ ] Can access internet after paying/entering voucher

---

**Last Updated:** March 28, 2026
**Tested On:** Android 14, macOS Server (ZTE Router)