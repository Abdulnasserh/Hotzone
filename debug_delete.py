import asyncio
import logging
from playwright.async_api import async_playwright
import router_scraper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("debug_delete")

async def test_delete_and_screenshot():
    config = router_scraper._load_config()
    if not config:
        config = {
            "routerIp": "192.168.1.1",
            "routerUser": "admin",
            "routerPass": "admin" # fallback if not in db
        }
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True) # running headless but we will take screenshots
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        try:
            logger.info("Logging in...")
            await router_scraper._login(page, config)
            
            logger.info("Navigating to MAC Filtering...")
            await router_scraper._navigate_to_mac_filtering(page, config.get("routerIp", "192.168.1.1"))
            
            # Add a fake MAC to delete if none exist
            test_mac = "AA:BB:CC:DD:EE:FF"
            existing = await router_scraper._get_existing_macs(page)
            if test_mac not in existing:
                logger.info(f"Adding test MAC {test_mac} to delete it...")
                await router_scraper._add_single_mac(page, test_mac)
                await router_scraper._save_and_apply(page)
                await page.wait_for_timeout(3000)
                await page.reload()
                await router_scraper._navigate_to_mac_filtering(page, config.get("routerIp", "192.168.1.1"))
            
            logger.info("Attempting to delete MAC...")
            # Find the row
            rows = await page.locator('table tr').all()
            found = False
            for row in rows:
                text = await row.inner_text()
                if test_mac in text.upper():
                    found = True
                    del_link = row.locator('a:has-text("Delete"), button:has-text("Delete")').first
                    logger.info("Found row, clicking Delete...")
                    # Screenshot before delete
                    await page.screenshot(path="debug_1_before_delete.png")
                    
                    try:
                        await del_link.click(timeout=3000)
                    except Exception:
                        await del_link.click(force=True, timeout=3000)
                    
                    # Screenshot right after delete click
                    await page.wait_for_timeout(1000)
                    await page.screenshot(path="debug_2_after_delete_click.png")
                    logger.info("Took screenshot: debug_2_after_delete_click.png")
                    
                    # Handle confirm delete dialog using the fixed function from router_scraper
                    try:
                        await router_scraper._confirm_delete_dialog(page)
                        await page.screenshot(path="debug_3_after_delete_confirm.png")
                        logger.info("Confirmed delete dialog")
                    except Exception as e:
                        logger.info(f"Delete confirm failed or unnecessary: {e}")
                    
                    await page.wait_for_timeout(1500)
                    await router_scraper._dismiss_alerts(page)
                    break
            
            if not found:
                logger.error(f"Test MAC {test_mac} not found in table.")
                return

            logger.info("Clicking Save And Apply...")
            await page.screenshot(path="debug_4_before_save_apply.png")
            
            save_btn = page.locator('button:has-text("Save And Apply Rules")').first
            try:
                await save_btn.wait_for(state="visible", timeout=3000)
                try:
                    await save_btn.click(timeout=5000)
                except Exception:
                    await save_btn.click(force=True, timeout=5000)
                logger.info("Clicked 'Save And Apply Rules'")
                
                # Immediately capture what happens
                await page.wait_for_timeout(500)
                await page.screenshot(path="debug_5_right_after_save_click.png")
                logger.info("Took screenshot: debug_5_right_after_save_click.png")
                
                await page.wait_for_timeout(2500)
                
                # Check for confirm dialog using the same approach
                await page.screenshot(path="debug_6_save_confirm_dialog.png")
                logger.info("Took screenshot: debug_6_save_confirm_dialog.png")
                
                try:
                    confirm_btn = page.locator('button:has-text("Confirm"):visible').first
                    if await confirm_btn.is_visible():
                        logger.info("Save confirm dialog is visible, clicking confirm...")
                        try:
                            await confirm_btn.click(timeout=3000)
                        except Exception:
                            await confirm_btn.click(force=True, timeout=3000)
                        logger.info("Clicked dialog 'Confirm'")
                        await page.wait_for_timeout(1500)
                    else:
                        logger.info("Save confirm dialog is NOT visible")
                except Exception as e:
                    logger.info(f"Save Confirm logic error: {e}")
                
            except Exception as e:
                logger.warning(f"'Save And Apply Rules' button not visible or click failed: {e}")

            await page.wait_for_timeout(2000)
            await page.screenshot(path="debug_7_final_state.png")
            logger.info("Took screenshot: debug_7_final_state.png")
            
        finally:
            await browser.close()

if __name__ == "__main__":
    asyncio.run(test_delete_and_screenshot())
