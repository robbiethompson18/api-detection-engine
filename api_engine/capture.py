import json
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

from utils.logger import get_logger

logger = get_logger(__name__)


class HarCapture:
    """Captures network traffic in HAR format using Playwright."""

    def __init__(self, timeout=5000):
        """Initialize the HAR capture with configurable timeout.

        Args:
            timeout: Time to wait after page load in milliseconds
        """
        self.timeout = timeout

    def _parse_cookies(self, cookie_string, url):
        """Parse cookie string into Playwright cookie format.

        Args:
            cookie_string: Cookie string in format "name1=value1; name2=value2"
            url: URL to extract domain from

        Returns:
            list: List of cookie dicts in Playwright format
        """
        if not cookie_string:
            return []

        cookies = []
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        for cookie_pair in cookie_string.split(";"):
            cookie_pair = cookie_pair.strip()
            if "=" in cookie_pair:
                name, value = cookie_pair.split("=", 1)
                cookies.append(
                    {
                        "name": name.strip(),
                        "value": value.strip(),
                        "domain": domain,
                        "path": "/",
                    }
                )

        return cookies

    def capture(self, url, output_file=None, cookies=None):
        """Capture HAR data from the given URL.

        Args:
            url: The URL to navigate to
            output_file: Optional path to save the HAR file
            cookies: Optional cookie string or list of cookie dicts

        Returns:
            tuple: (success, har_data_dict)
        """
        try:
            # Add protocol if missing
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "https://" + url

            logger.info(f"Capturing HAR data for {url}")
            temp_har_path = "temp_capture.har"

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(record_har_path=temp_har_path)

                # Add cookies if provided
                if cookies:
                    if isinstance(cookies, str):
                        parsed_cookies = self._parse_cookies(cookies, url)
                    else:
                        parsed_cookies = cookies

                    if parsed_cookies:
                        context.add_cookies(parsed_cookies)
                        logger.info(f"Added {len(parsed_cookies)} cookies to browser context")

                page = context.new_page()

                logger.info(f"Navigating to {url}...")
                page.goto(url)
                page.wait_for_timeout(self.timeout)

                logger.info("Closing browser and collecting HAR data...")
                context.close()
                browser.close()

                # Load the HAR data from the temporary file
                with open(temp_har_path, "r") as f:
                    har_data = json.load(f)

                # Optionally save to the specified output file
                if output_file:
                    with open(output_file, "w") as f:
                        json.dump(har_data, f)
                    logger.info(f"HAR file saved to {output_file}")

                logger.info("HAR capture completed successfully")

            return True, har_data

        except Exception as e:
            logger.error(f"Failed to capture HAR: {str(e)}")
            return False, None
