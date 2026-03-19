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
from pathlib import Path
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
    cfg_path = Path(__file__).parent / "config.json"
    with open(cfg_path, "r") as f:
        return json.load(f)


async def _ensure_browser():
    """Launch browser if not already running."""
    global _playwright, _browser, _context, _page, _logged_in
    if _browser is None or not _browser.is_connected():
        _playwright = await async_playwright().start()
        _browser = await _playwright.chromium.launch(headless=True)
        _context = await _browser.new_context(ignore_https_errors=True)
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
            await login_btn.click()
        else:
            await password_input.press("Enter")

        await page.wait_for_timeout(3000)
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
        current_url = page.url
        if "login" in current_url.lower() or not _logged_in:
            await _login(page, config)
    except Exception:
        await _login(page, config)


async def _navigate_to_mac_filtering(page: Page, router_ip: str):
    """
    Navigate: Firewall sidebar → Filtering Rules → MAC Filtering tab.
    This is the correct path to reach the MAC Filtering table.
    """
    # Step 1: Click Firewall in sidebar (#fw_menu)
    fw_menu = page.locator('#fw_menu .el-submenu__title').first
    try:
        if await fw_menu.is_visible(timeout=3000):
            await fw_menu.click()
            await page.wait_for_timeout(1000)
            logger.info("Clicked Firewall sidebar")
    except Exception:
        # Might already be expanded
        pass

    # Step 2: Click "Filtering Rules" submenu
    fr = page.locator('text="Filtering Rules"').first
    try:
        if await fr.is_visible(timeout=2000):
            await fr.click()
            await page.wait_for_timeout(2000)
            logger.info("Clicked Filtering Rules")
    except Exception as e:
        logger.warning(f"Could not click Filtering Rules: {e}")

    # Step 3: Click "MAC Filtering" tab
    mac_tab = page.locator('text="MAC Filtering"').first
    try:
        if await mac_tab.is_visible(timeout=2000):
            await mac_tab.click()
            await page.wait_for_timeout(2000)
            logger.info("Clicked MAC Filtering tab")
        else:
            logger.warning("MAC Filtering tab not visible")
    except Exception as e:
        logger.warning(f"Could not click MAC Filtering: {e}")


async def _save_and_apply(page: Page):
    """Click 'Save And Apply Rules' then handle any confirm dialog.
    
    The router UI sometimes shows a green alert banner (fy-alert-box)
    that overlays the button. We dismiss it first, then click.
    """
    # Dismiss any alert banners that might be blocking the button
    try:
        alert_box = page.locator('.fy-alert-box, .fy-alert-header').first
        if await alert_box.is_visible(timeout=1000):
            # Try clicking the alert to dismiss it
            await alert_box.click(timeout=2000)
            logger.info("Dismissed router alert banner")
            await page.wait_for_timeout(500)
    except Exception:
        pass

    # Also try to hide it via JS if it's still there
    try:
        await page.evaluate("""
            document.querySelectorAll('.fy-alert-box').forEach(el => {
                el.style.display = 'none';
                el.remove();
            });
        """)
    except Exception:
        pass

    save_btn = page.locator('button:has-text("Save And Apply Rules")').first
    if await save_btn.is_visible(timeout=3000):
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
            confirm_btn = page.locator('button:has-text("Confirm")').first
            if await confirm_btn.is_visible(timeout=3000):
                try:
                    await confirm_btn.click(timeout=3000)
                except Exception:
                    await confirm_btn.click(force=True, timeout=3000)
                logger.info("Clicked dialog 'Confirm'")
                await page.wait_for_timeout(1500)
        except Exception:
            pass
    else:
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
    """Scrape the DHCP device list from the router."""
    config = _load_config()
    if not config.get("playwrightEnabled", True):
        return []

    async with _lock:
        page = await _ensure_browser()
        await _ensure_logged_in(page, config)

        router_ip = config.get("routerIp", "192.168.1.1")
        devices = []

        try:
            # Step 1: Click "DHCP Information" in the sidebar menu
            dhcp_item = page.locator('.el-menu-item:has-text("DHCP Information")').first
            try:
                if await dhcp_item.is_visible(timeout=3000):
                    await dhcp_item.click()
                    await page.wait_for_timeout(2000)
                    logger.info("Clicked DHCP Information sidebar item")
                else:
                    # Fallback: expand System Status first, then click
                    sys_status = page.locator('.el-submenu__title:has-text("System Status")').first
                    if await sys_status.is_visible(timeout=2000):
                        await sys_status.click()
                        await page.wait_for_timeout(1000)
                    await dhcp_item.click()
                    await page.wait_for_timeout(2000)
            except Exception:
                # Last resort: navigate by URL
                await page.goto(f"http://{router_ip}/index.html#DHCP_INFO", timeout=15000)
                await page.wait_for_timeout(3000)

            # Step 2: Click the "Device List" tab (changes hash to #DHCP_INFO#1)
            device_list_tab = page.locator('text="Device List"').first
            try:
                if await device_list_tab.is_visible(timeout=3000):
                    await device_list_tab.click()
                    await page.wait_for_timeout(2000)
                    logger.info("Clicked Device List tab")
                else:
                    logger.warning("Device List tab not visible")
            except Exception as e:
                logger.warning(f"Could not click Device List tab: {e}")

            # Step 3: Parse the table (columns: No., Host, MAC Address, IP)
            rows = await page.locator('table tr').all()
            for row in rows:
                cells = await row.locator('td').all()
                if len(cells) >= 4:
                    try:
                        host = (await cells[1].inner_text()).strip()
                        mac = (await cells[2].inner_text()).strip().upper()
                        ip = (await cells[3].inner_text()).strip()
                        if mac and ":" in mac and len(mac) == 17:
                            devices.append({"host": host, "mac": mac, "ip": ip})
                    except Exception:
                        continue

            logger.info(f"Scraped {len(devices)} devices from router")
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

        # Batch window: wait for more concurrent requests to arrive
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

        async with _lock:
            try:
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
                                del_btn = row.locator('button:has-text("Delete")').first
                                if await del_btn.is_visible(timeout=1000):
                                    await del_btn.click()
                                    await page.wait_for_timeout(1000)
                                    changed = True
                                    logger.info(f"Batched delete for {mac_upper}")
                                    break

                for mac in adds:
                    mac_upper = mac.upper()
                    if mac_upper not in existing:
                        if await _add_single_mac(page, mac_upper):
                            changed = True
                            await page.wait_for_timeout(500)

                if changed:
                    await _save_and_apply(page)
                    logger.info("Batched updates successfully applied routing rules.")

            except Exception as e:
                logger.error(f"Batch worker failed: {e}")
                global _logged_in
                _logged_in = False
                # Simple retry mechanism could be added here

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
        page = await _ensure_browser()
        await _ensure_logged_in(page, config)
        router_ip = config.get("routerIp", "192.168.1.1")

        try:
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
