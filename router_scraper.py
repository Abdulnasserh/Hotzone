"""
router_scraper.py — Playwright-based Airtel router automation
Handles: login, scrape DHCP device list, MAC Filtering whitelist management

Router operates in WHITELIST mode:
  - Firewall → Filtering Rules → Default Settings → Whitelist selected
  - MAC Filtering tab → devices listed here are ALLOWED internet
  - Devices NOT in the list are BLOCKED by default

Navigation path:
  1. Click #fw_menu (Firewall sidebar)
  2. Click "Filtering Rules"
  3. Click "MAC Filtering" tab

Add Rule flow:
  1. Click "Add Rule" button (el-button--primary)
  2. Fill input#ipAddress (the MAC field)
  3. Click row "Confirm" button
  4. Click "Save And Apply Rules" (el-button--primary)
  5. Click dialog "Confirm" if shown
"""

import asyncio
import json
import logging
import sys
import os
from pathlib import Path

# ---------------------------------------------------------------------------
# When running as a frozen PyInstaller app, tell Playwright where to find
# the bundled browser binaries.  We set PLAYWRIGHT_BROWSERS_PATH to the
# explicit .local-browsers directory we bundled, AND we discover the
# chrome executable ourselves so we can pass it as executable_path.
# ---------------------------------------------------------------------------
_frozen_chrome_exe = None   # Will be set if we find a bundled chrome binary

if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    _local_browsers = os.path.join(
        sys._MEIPASS, "playwright", "driver", "package", ".local-browsers"
    )
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = _local_browsers

    # --- Discover chrome executable explicitly ---
    # Playwright installs chromium-XXXX/ (full) and
    # chromium-headless-shell-XXXX/ (headless).  We prefer the full one.
    if os.path.isdir(_local_browsers):
        for entry in sorted(os.listdir(_local_browsers)):
            entry_path = os.path.join(_local_browsers, entry)
            if not os.path.isdir(entry_path):
                continue
            # Look for chrome.exe / headless_shell.exe inside
            candidates = [
                os.path.join(entry_path, "chrome-win", "chrome.exe"),
                os.path.join(entry_path, "chrome-win", "headless_shell.exe"),
                os.path.join(entry_path, "chrome-linux", "chrome"),
                os.path.join(entry_path, "chrome-linux", "headless_shell"),
                os.path.join(entry_path, "chrome-mac", "Chromium.app",
                             "Contents", "MacOS", "Chromium"),
            ]
            for c in candidates:
                if os.path.isfile(c):
                    _frozen_chrome_exe = c
                    break
            if _frozen_chrome_exe:
                break

# ---------------------------------------------------------------------------
# On Windows, prevent the black console window from appearing when
# Playwright spawns its Node.js driver subprocess.
# We monkey-patch subprocess.Popen to include CREATE_NO_WINDOW flag.
# ---------------------------------------------------------------------------
if sys.platform == "win32" and getattr(sys, 'frozen', False):
    import subprocess
    _original_popen = subprocess.Popen

    class _SilentPopen(_original_popen):
        def __init__(self, *args, **kwargs):
            CREATE_NO_WINDOW = 0x08000000
            creationflags = kwargs.get("creationflags", 0)
            kwargs["creationflags"] = creationflags | CREATE_NO_WINDOW
            super().__init__(*args, **kwargs)

    subprocess.Popen = _SilentPopen

from playwright.async_api import async_playwright, Browser, BrowserContext, Page

logger = logging.getLogger("router_scraper")

# ---------------------------------------------------------------------------
# Globals – reused browser session + lock for thread safety
# ---------------------------------------------------------------------------
_playwright = None
_browser: Browser | None = None
_context: BrowserContext | None = None
_page: Page | None = None
_logged_in = False
_lock = asyncio.Lock()  # Prevents concurrent router operations


def _load_config() -> dict:
    import sys, os, sqlite3, json, platform
    if getattr(sys, 'frozen', False):
        # Must match server.py DATA_DIR logic
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
        pass
    return {}


async def _ensure_browser():
    """Launch browser if not already running."""
    global _playwright, _browser, _context, _page, _logged_in
    if _browser is None or not _browser.is_connected():
        _playwright = await async_playwright().start()

        launch_kwargs = dict(
            headless=True,
            args=[
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-default-apps",
                "--disable-sync",
                "--disable-translate",
                "--metrics-recording-only",
                "--mute-audio",
                "--no-first-run",
            ],
        )

        # For frozen builds, pass the explicit path so Playwright doesn't
        # have to discover the browser itself (which often fails in
        # PyInstaller bundles).
        if _frozen_chrome_exe:
            launch_kwargs["executable_path"] = _frozen_chrome_exe
            logger.info(f"Using bundled browser: {_frozen_chrome_exe}")

        try:
            _browser = await _playwright.chromium.launch(**launch_kwargs)
        except Exception as e:
            logger.error(f"Chromium launch failed: {e}")
            # Log diagnostic info for debugging
            if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
                _lb = os.path.join(
                    sys._MEIPASS, "playwright", "driver", "package", ".local-browsers"
                )
                if os.path.isdir(_lb):
                    logger.error(f"  .local-browsers contents: {os.listdir(_lb)}")
                    for d in os.listdir(_lb):
                        dp = os.path.join(_lb, d)
                        if os.path.isdir(dp):
                            logger.error(f"    {d}/ contents: {os.listdir(dp)[:10]}")
                else:
                    logger.error(f"  .local-browsers dir NOT found at: {_lb}")
                logger.error(f"  _frozen_chrome_exe = {_frozen_chrome_exe}")
            raise

        _context = await _browser.new_context(ignore_https_errors=True)
        
        # Block expensive resources like router logos and heavy fonts to drastically speed up navigation!
        async def intercept_route(route):
            if route.request.resource_type in ["image", "media", "font"]:
                await route.abort()
            else:
                await route.continue_()
                
        await _context.route("**/*", intercept_route)
        _page = await _context.new_page()
        _logged_in = False
    return _page


async def _login(page: Page, config: dict):
    """Login to the Airtel router admin panel."""
    global _logged_in
    router_ip = config.get("routerIp", "192.168.1.1")
    username = config.get("routerUser", "admin")
    password = config.get("routerPass", "")

    login_url = f"http://{router_ip}/login.html"
    logger.info(f"Navigating to router login: {login_url}")

    try:
        await page.goto(login_url, timeout=15000, wait_until="domcontentloaded")
        await page.wait_for_timeout(2000)

        # Click the Login link to reveal the form
        try:
            pre_login_link = page.locator('a#loginBtn, a:has-text("Login")').first
            if await pre_login_link.is_visible(timeout=2000):
                await pre_login_link.click()
                await page.wait_for_timeout(1000)
        except Exception:
            pass

        # Fill username
        username_input = page.locator('input#username, input[name="username"]').first
        if await username_input.is_visible(timeout=2000):
            await username_input.click()
            await username_input.fill(username)
        else:
            raise Exception("Username input not visible")

        # Fill password
        password_input = None
        for selector in [
            'input#passwd:not([hidden])',
            'input#password:not([hidden])',
            'input[type="password"]:not([hidden])'
        ]:
            try:
                loc = page.locator(selector).first
                if await loc.is_visible(timeout=1000):
                    password_input = loc
                    break
            except Exception:
                continue

        if password_input:
            await password_input.click()
            await password_input.fill(password)
        else:
            raise Exception("Password input not visible")

        await page.wait_for_timeout(500)

        # Click login button
        login_btn = page.locator('button#btnLogin, input[type="submit"]').first
        if await login_btn.is_visible(timeout=1000):
            await login_btn.click(timeout=3000)
        else:
            await password_input.press("Enter")

        try:
            # Wait for dashboard to fully load by looking for common router elements
            await page.wait_for_selector('.el-submenu__title, #DHCP_INFO, #System_Status, div.menu, nav, #app, .sidebar', timeout=5000)
        except Exception as e:
            # Check if login failed by seeing if we are still on the login page
            if await page.locator('input#username, input[name="username"]').first.is_visible(timeout=1000):
                error_msg = ""
                try:
                    err_loc = page.locator('.el-message-box__message, .el-message, .error, :text("locked"), :text("incorrect")').first
                    if await err_loc.is_visible(timeout=500):
                        error_msg = await err_loc.inner_text()
                except Exception:
                    pass
                raise Exception(f"Still on login page! {error_msg}".strip())
                
            logger.warning("Dashboard elements did not appear within 5s, proceeding anyway...")

        await page.wait_for_timeout(2000)
        _logged_in = True
        logger.info("Router login successful")
    except Exception as e:
        _logged_in = False
        logger.error(f"Router login failed: {e}")
        raise


async def _ensure_logged_in(page: Page, config: dict):
    """Re-login if session expired."""
    global _logged_in
    try:
        needs_login = not _logged_in
        
        # Check if login form is actively shown on screen
        username_input = page.locator('input#username, input[name="username"]').first
        if await username_input.is_visible(timeout=500):
            needs_login = True
            
        # Verify if an admin UI element is actually visible.
        # If not, the session was likely kicked by another login (e.g. manual browser login).
        if not needs_login:
            # Support multiple router variants: element-ui classes, or basic IDs
            sidebar_check = page.locator('.el-submenu__title, #DHCP_INFO, .sidebar, nav, div.menu, .header, #header').first
            if not await sidebar_check.is_visible(timeout=1500):
                logger.warning("Admin UI elements missing. Session likely kicked out. Forcing re-login...")
                needs_login = True
                
                # Check for any "OK" or "Confirm" buttons on kickout popups
                try:
                    kick_btn = page.locator('button:has-text("Confirm"), button:has-text("OK")').first
                    if await kick_btn.is_visible(timeout=500):
                        await kick_btn.click(timeout=1000)
                except Exception:
                    pass
            
        if needs_login:
            await _login(page, config)
    except Exception:
        await _login(page, config)


async def _dismiss_alerts(page: Page):
    """Hide any blocking SUCCESS alert modals/shadows before clicking.
    IMPORTANT: Do NOT call this while a delete confirmation dialog is open —
    it will kill the dialog before Confirm is clicked.
    """
    try:
        await page.evaluate("""
            document.querySelectorAll('.fy-alert-box, .fy-alert-shadow, .fy-alert-header').forEach(el => {
                el.style.display = 'none';
                el.remove();
            });
        """)
    except Exception:
        pass


async def _confirm_delete_dialog(page: Page):
    """After clicking a row Delete button the router shows an .fy-alert-box
    confirmation. We must click its Confirm button FIRST, then wait for the
    success overlay to vanish before proceeding.
    """
    try:
        # Wait up to 3s for the confirm dialog to appear
        confirm_btn = page.locator('button:has-text("Confirm"):visible').first
        await confirm_btn.wait_for(state="visible", timeout=3000)
        try:
            await confirm_btn.click(timeout=3000)
        except Exception:
            await confirm_btn.click(force=True, timeout=3000)
        logger.info("Confirmed delete dialog")
        # Wait for the success overlay to disappear before next action
        await page.wait_for_timeout(1500)
        # Now it's safe to dismiss any remaining success banners
        await _dismiss_alerts(page)
    except Exception:
        # No dialog appeared — delete may not need confirmation on this firmware
        pass


async def _navigate_to_mac_filtering(page: Page, router_ip: str):
    """
    Navigate: Firewall sidebar → Filtering Rules → MAC Filtering tab.
    This is the correct path to reach the MAC Filtering table.
    """
    await _dismiss_alerts(page)
    fr = page.locator('text="Filtering Rules" >> visible=true').first
    try:
        await fr.wait_for(state="visible", timeout=1000)
    except Exception:
        # Step 1: Click Firewall in sidebar
        fw_menu = page.locator('.el-submenu__title:has-text("Firewall")').first
        try:
            await fw_menu.click(force=True, timeout=5000)
            await page.wait_for_timeout(1000)
            logger.info("Clicked Firewall sidebar")
        except Exception as e:
            logger.warning(f"Could not click Firewall sidebar: {e}")
            
    # Step 2: Click "Filtering Rules" submenu
    try:
        await fr.click(force=True, timeout=5000)
        await page.wait_for_timeout(2000)
        logger.info("Clicked Filtering Rules")
    except Exception as e:
        logger.warning(f"Could not click Filtering Rules: {e}")

    # Step 3: Click "MAC Filtering" tab
    mac_tab = page.locator('text="MAC Filtering"').first
    try:
        await mac_tab.click(force=True, timeout=3000)
        await page.wait_for_timeout(2000)
        logger.info("Clicked MAC Filtering tab")
    except Exception as e:
        logger.warning(f"Could not click MAC Filtering: {e}")


async def _save_and_apply(page: Page):
    """Click 'Save And Apply Rules' then handle any confirm dialog.
    
    The router UI sometimes shows a green alert banner (fy-alert-box)
    that overlays the button. We dismiss it first, then click.
    """
    # Dismiss any lingering success banners (NOT delete confirm dialogs —
    # those are handled by _confirm_delete_dialog before we get here)
    await _dismiss_alerts(page)

    save_btn = page.locator('button:has-text("Save And Apply Rules")').first
    try:
        await save_btn.wait_for(state="visible", timeout=3000)
        try:
            await save_btn.click(timeout=5000)
        except Exception:
            # Force click if normal click is blocked by overlay
            logger.warning("Normal click blocked by overlay, force-clicking...")
            await save_btn.click(force=True, timeout=5000)
        logger.info("Clicked 'Save And Apply Rules'")
        await page.wait_for_timeout(3000)

        # Handle confirm dialog — could be a modal with a Confirm button
        try:
            confirm_btn = page.locator('button:has-text("Confirm"):visible').first
            await confirm_btn.wait_for(state="visible", timeout=3000)
            try:
                await confirm_btn.click(timeout=3000)
            except Exception:
                await confirm_btn.click(force=True, timeout=3000)
            logger.info("Clicked dialog 'Confirm'")
            await page.wait_for_timeout(1500)
        except Exception:
            pass
    except Exception:
        logger.warning("'Save And Apply Rules' button not visible")


async def _get_existing_macs(page: Page) -> set:
    """Get set of MAC addresses currently in the MAC Filtering table."""
    macs = set()
    rows = await page.locator('table tr').all()
    for row in rows:
        text = await row.inner_text()
        # Look for MAC pattern (XX:XX:XX:XX:XX:XX)
        parts = text.upper().split()
        for p in parts:
            p = p.strip()
            if len(p) == 17 and p.count(":") == 5:
                macs.add(p)
    return macs


async def _add_single_mac(page: Page, mac: str) -> bool:
    """
    Add one MAC address via the Add Rule form.
    Steps: Click "Add Rule" → fill #ipAddress → click row "Confirm"
    """
    # Click "Add Rule"
    add_btn = page.locator('button:has-text("Add Rule")').first
    if not await add_btn.is_visible(timeout=3000):
        logger.error("'Add Rule' button not found")
        return False

    await add_btn.click()
    await page.wait_for_timeout(1500)

    # Fill the MAC address in input#ipAddress
    mac_input = page.locator('input#ipAddress').first
    if await mac_input.is_visible(timeout=2000):
        await mac_input.click()
        await mac_input.fill(mac)
        logger.info(f"Filled MAC input (#ipAddress) with {mac}")
    else:
        # Fallback: try any empty el-input__inner
        filled = False
        all_inputs = await page.locator('input.el-input__inner').all()
        for inp in all_inputs:
            if await inp.is_visible():
                val = await inp.input_value()
                if not val:
                    await inp.click()
                    await inp.fill(mac)
                    filled = True
                    logger.info(f"Filled fallback input with {mac}")
                    break
        if not filled:
            logger.error(f"Could not find MAC input for {mac}")
            return False

    await page.wait_for_timeout(500)

    # Click the row-level "Confirm" button (NOT the page-level Save And Apply)
    # This is the last "Confirm" button visible in the form area
    confirm_buttons = await page.locator('button:has-text("Confirm")').all()
    # Find the one that's inside the add-rule form area (usually the last visible one)
    row_confirmed = False
    for btn in confirm_buttons:
        try:
            if await btn.is_visible():
                # Check if this is NOT the "Save And Apply" confirm dialog
                btn_text = (await btn.inner_text()).strip()
                if btn_text == "Confirm":
                    await btn.click()
                    await page.wait_for_timeout(1000)
                    row_confirmed = True
                    logger.info(f"Confirmed new rule row for {mac}")
                    break
        except Exception:
            continue

    if not row_confirmed:
        # The row might auto-confirm, or the Confirm text might be in a td
        try:
            td_confirm = page.locator('td:has-text("Confirm"), a:has-text("Confirm")').last
            if await td_confirm.is_visible(timeout=1000):
                await td_confirm.click()
                await page.wait_for_timeout(1000)
                logger.info(f"Confirmed via table cell for {mac}")
                row_confirmed = True
        except Exception:
            pass

    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def scrape_devices() -> list[dict]:
    """Scrape the DHCP device list from the router with high redundancy."""
    config = _load_config()
    if not config.get("playwrightEnabled", True):
        return []

    async with _lock:
        router_ip = config.get("routerIp", "192.168.1.1")
        devices = []

        try:
            page = await _ensure_browser()
            await _ensure_logged_in(page, config)
            await _dismiss_alerts(page)
            
            # ----- Strategy 1: Direct JS click on #DHCP_INFO -----
            # The router sidebar uses an Element UI accordion. The DHCP
            # Information item has id="DHCP_INFO" but is hidden inside
            # a collapsed parent submenu. Using JavaScript .click()
            # bypasses Playwright's visibility check and triggers the
            # router's own navigation handler.
            success = False
            try:
                clicked = await page.evaluate("""() => {
                    const el = document.getElementById('DHCP_INFO');
                    if (el) { el.click(); return true; }
                    return false;
                }""")
                if clicked:
                    success = True
                    logger.info("Navigated to DHCP via JS click on #DHCP_INFO")
            except Exception as e:
                logger.debug(f"JS click on #DHCP_INFO failed: {e}")

            # ----- Strategy 2: Expand "System Status" then click -----
            if not success:
                try:
                    parent = page.locator('.el-submenu__title:has-text("System Status")').first
                    await parent.click(force=True, timeout=3000)
                    await page.wait_for_timeout(800)
                    logger.info("Expanded 'System Status' sidebar")

                    dhcp_item = page.locator('#DHCP_INFO').first
                    if await dhcp_item.is_visible(timeout=2000):
                        await dhcp_item.click(timeout=3000)
                        success = True
                        logger.info("Clicked DHCP Information after expanding System Status")
                except Exception as e:
                    logger.debug(f"Sidebar expand+click failed: {e}")

            # ----- Strategy 3: Direct URL hash navigation -----
            if not success:
                logger.warning("Sidebar DHCP link not found via click, attempting direct URL hash...")
                for h in ["DHCP_INFO", "DHCP_CLIENT_LIST", "connected_devices"]:
                    try:
                        await page.goto(f"http://{router_ip}/index.html#{h}", timeout=8000)
                        await page.wait_for_timeout(2500)
                        # Check if a DHCP table actually rendered
                        rows = await page.locator('table tr').count()
                        if rows > 0:
                            success = True
                            logger.info(f"Navigated via hash #{h}, found {rows} table rows")
                            break
                    except Exception:
                        continue

            if not success:
                raise Exception("Critically failed to navigate to the DHCP devices page! Aborting scrape to avoid reading rogue data.")

            await page.wait_for_timeout(2000)  # Give it time to render

            # Step 2: Click "Device List" tab if it exists
            tabs = ['text="Device List"', 'text="DHCP Client List"', 'text="LAN Devices"']
            for t in tabs:
                try:
                    tab = page.locator(f'{t} >> visible=true').first
                    if await tab.is_visible(timeout=1000):
                        await tab.click(timeout=2000)
                        await page.wait_for_timeout(1500)
                        break
                except Exception:
                    continue

            # Step 3: Wait for table rows. Increase timeout for slow Windows/Router environments.
            try:
                await page.wait_for_selector('table tr', timeout=8000)
            except Exception:
                logger.warning("No table found on DHCP page after 8s.")

            # Step 4: Scrape rows
            rows = await page.locator('table tr').all()
            for row in rows:
                cells = await row.locator('td').all()
                if len(cells) > 0:
                    try:
                        host = "unknown"
                        mac = ""
                        ip = ""
                        
                        for cell in cells:
                            text = (await cell.inner_text()).strip()
                            if not text:
                                continue
                            
                            # Check if it's a MAC address
                            if ":" in text and len(text) == 17 and text.count(":") == 5:
                                mac = text.upper()
                            # Check if it's an IP address
                            elif text.count(".") == 3 and any(c.isdigit() for c in text):
                                ip = text
                            # Otherwise assume it might be a hostname (skip simple numbers or time strings)
                            elif len(text) > 1 and not text.replace(".", "").isdigit() and "day" not in text.lower() and "hour" not in text.lower():
                                host = text
                        
                        if mac and len(mac) == 17:
                            devices.append({"host": host, "mac": mac, "ip": ip})
                        else:
                            # Log skipped rows for debugging
                            row_text = (await row.inner_text()).replace("\n", " | ")
                            logger.debug(f"Skipped row (no MAC found): {row_text}")
                    except Exception as e:
                        logger.warning(f"Error parsing row: {e}")
                        continue

            logger.info(f"Successfully scraped {len(devices)} DHCP connected devices from router")
            
            # --- Check actual router MAC Filters ---
            try:
                await _navigate_to_mac_filtering(page, router_ip)
                allowed_macs = await _get_existing_macs(page)
                
                # Mark connected devices that are allowed
                dhcp_macs = set()
                for d in devices:
                    mac_upper = d["mac"].upper()
                    dhcp_macs.add(mac_upper)
                    d["router_allowed"] = mac_upper in allowed_macs
                
                # Add allowed devices that are NOT in DHCP
                for mac in allowed_macs:
                    if mac not in dhcp_macs:
                        devices.append({
                            "host": "Sio Mtandaoni",
                            "mac": mac,
                            "ip": "—",
                            "router_allowed": True
                        })
            except Exception as e:
                logger.warning(f"Failed to scrape MAC filtering table: {e}")
        except Exception as e:
            logger.error(f"Failed to scrape devices: {e}")
            global _logged_in
            _logged_in = False

        return devices


# ---------------------------------------------------------------------------
# Background Batch Worker for High Concurrency (16+ Users)
# ---------------------------------------------------------------------------
_pending_adds = set()
_pending_deletes = set()
_queue_task = None
_queue_event = asyncio.Event()

def _start_queue_worker():
    global _queue_task
    if _queue_task is None or _queue_task.done():
        _queue_task = asyncio.create_task(_queue_worker())

async def _queue_worker():
    while True:
        await _queue_event.wait()
        _queue_event.clear()

        # Batch window: collect concurrent requests
        await asyncio.sleep(2)

        global _pending_adds, _pending_deletes
        adds = list(_pending_adds)
        deletes = list(_pending_deletes)
        _pending_adds.clear()
        _pending_deletes.clear()

        if not adds and not deletes:
            continue

        config = _load_config()
        if not config.get("playwrightEnabled", True):
            continue

        # Retry up to 3 times on failure
        for attempt in range(1, 4):
            try:
                async with _lock:
                    page = await _ensure_browser()
                    await _ensure_logged_in(page, config)
                    router_ip = config.get("routerIp", "192.168.1.1")
                    await _navigate_to_mac_filtering(page, router_ip)

                    existing = await _get_existing_macs(page)
                    changed = False

                    for mac in deletes:
                        mac_upper = mac.upper()
                        if mac_upper in existing:
                            rows = await page.locator('table tr').all()
                            for row in rows:
                                text = await row.inner_text()
                                if mac_upper in text.upper():
                                    del_link = row.locator('a:has-text("Delete"), button:has-text("Delete")').first
                                    try:
                                        await del_link.click(timeout=3000)
                                    except Exception:
                                        await del_link.click(force=True, timeout=3000)
                                    # Handle the confirmation dialog the router shows after Delete
                                    await _confirm_delete_dialog(page)
                                    changed = True
                                    logger.info(f"Batched delete for {mac_upper}")
                                    break
                        else:
                            logger.info(f"{mac_upper} already absent from router — no delete needed")
                            changed = True  # Still call save if we had adds

                    for mac in adds:
                        mac_upper = mac.upper()
                        if mac_upper not in existing:
                            if await _add_single_mac(page, mac_upper):
                                changed = True
                                await page.wait_for_timeout(500)

                    if changed:
                        await _save_and_apply(page)
                        logger.info("Batched updates successfully applied routing rules.")

                break  # Success — exit retry loop

            except Exception as e:
                logger.error(f"Batch worker attempt {attempt}/3 failed: {e}")
                global _logged_in
                _logged_in = False
                if attempt < 3:
                    # Put items back in the queue for retry
                    _pending_adds.update(adds)
                    _pending_deletes.update(deletes)
                    await asyncio.sleep(5 * attempt)  # Backoff: 5s, 10s
                else:
                    logger.error(f"Batch worker gave up after 3 attempts for adds={adds} deletes={deletes}")

async def unblock_device(mac: str) -> bool:
    """
    GRANT access — asynchronously append MAC to the batch add queue.
    """
    _pending_adds.add(mac)
    _start_queue_worker()
    _queue_event.set()
    logger.info(f"Queued unblock for {mac}")
    return True

async def block_device(mac: str) -> bool:
    """
    REVOKE access — asynchronously append MAC to the batch block queue.
    """
    _pending_deletes.add(mac)
    _start_queue_worker()
    _queue_event.set()
    logger.info(f"Queued block for {mac}")
    return True



async def sync_whitelist_to_router(whitelist: list[dict]) -> bool:
    """
    Sync ALL whitelisted devices to the router in ONE session.
    Adds missing MACs one by one, each with its own row Confirm,
    then does a single Save And Apply at the end.
    """
    config = _load_config()
    if not config.get("playwrightEnabled", True):
        return False

    if not whitelist:
        return True

    async with _lock:
        try:
            page = await _ensure_browser()
            await _ensure_logged_in(page, config)
            router_ip = config.get("routerIp", "192.168.1.1")

            await _navigate_to_mac_filtering(page, router_ip)

            existing = await _get_existing_macs(page)
            logger.info(f"Existing MACs in router: {existing}")

            to_add = []
            for entry in whitelist:
                mac = entry["mac"].upper()
                if mac not in existing:
                    to_add.append(mac)

            if not to_add:
                logger.info("All whitelisted devices already in router")
                return True

            logger.info(f"Need to add {len(to_add)} devices: {to_add}")

            added_count = 0
            for mac in to_add:
                if await _add_single_mac(page, mac):
                    added_count += 1
                    await page.wait_for_timeout(500)
                else:
                    logger.error(f"Failed to add {mac}")

            if added_count > 0:
                await _save_and_apply(page)
                logger.info(f"✅ Synced {added_count}/{len(to_add)} devices to router")
            else:
                logger.warning("No devices were added during sync")

            return True

        except Exception as e:
            logger.error(f"Whitelist sync failed: {e}")
            global _logged_in
            _logged_in = False
            return False


async def purge_unauthorized_macs(allowed_macs: set) -> bool:
    """
    Open the router MAC Filtering page and remove any MAC that is NOT in
    `allowed_macs`. Called at startup to evict expired/blocked devices that
    survived a previous failed block attempt.
    """
    config = _load_config()
    if not config.get("playwrightEnabled", True):
        return False

    async with _lock:
        try:
            page = await _ensure_browser()
            await _ensure_logged_in(page, config)
            router_ip = config.get("routerIp", "192.168.1.1")

            await _navigate_to_mac_filtering(page, router_ip)
            existing = await _get_existing_macs(page)
            allowed_upper = {m.upper() for m in allowed_macs}

            to_remove = existing - allowed_upper
            if not to_remove:
                logger.info("Router MAC filter is clean — no unauthorized MACs found")
                return True

            logger.info(f"Purging {len(to_remove)} unauthorized MACs from router: {to_remove}")
            changed = False

            for mac_upper in to_remove:
                rows = await page.locator('table tr').all()
                for row in rows:
                    text = await row.inner_text()
                    if mac_upper in text.upper():
                        del_link = row.locator('a:has-text("Delete"), button:has-text("Delete")').first
                        try:
                            await del_link.click(timeout=3000)
                        except Exception:
                            await del_link.click(force=True, timeout=3000)
                        # Confirm the router's delete confirmation dialog
                        await _confirm_delete_dialog(page)
                        changed = True
                        logger.info(f"Purged unauthorized MAC: {mac_upper}")
                        break

            if changed:
                await _save_and_apply(page)
                logger.info(f"✅ Purge complete — removed {len(to_remove)} unauthorized MACs")

            return True

        except Exception as e:
            logger.error(f"MAC purge failed: {e}")
            global _logged_in
            _logged_in = False
            return False


async def cleanup():
    """Close browser resources."""
    global _browser, _playwright, _context, _page, _logged_in
    if _browser:
        try:
            await _browser.close()
        except Exception:
            pass
    if _playwright:
        try:
            await _playwright.stop()
        except Exception:
            pass
    _browser = None
    _context = None
    _page = None
    _playwright = None
    _logged_in = False


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    async def _test():
        devices = await scrape_devices()
        print("=== Devices ===")
        for d in devices:
            print(f"  {d['host']:30s}  {d['mac']}  {d['ip']}")
        await cleanup()

    asyncio.run(_test())
