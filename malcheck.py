import argparse
import asyncio
import pickle
from pyppeteer import launch
import requests
from collections import deque
from urllib.parse import urlparse

# Replace with your Google Safe Browsing API key
SAFE_BROWSING_API_KEY = "YOUR_API_KEY"

# Initialize set to track visited URLs
visited_urls_file = "visited_urls.pk1"  # Define file for saving visited URLs

# Create an empty set or load the existing set of visited URLs
try:
    with open(visited_urls_file, "rb") as f:
        visited_urls = pickle.load(f)
except FileNotFoundError:
    visited_urls = set()

# Launch headless web browser, go to URL, extract links
async def get_links_from_page(url):
    browser = await launch(headless=True)
    page = await browser.newPage()
    await page.goto(url)

    # Wait for JavaScript to load (adjust the time as needed)
    await asyncio.sleep(3)

    # Execute JavaScript function to extract links from the page
    links = await page.evaluate('''() => {
        const links = [];
        document.querySelectorAll("a").forEach(a => {
            if (a.href) {
                links.push(a.href);
            }
        });
        return links;
    }''')
    # Close the browser page to free up resources when finished
    await browser.close()
    return links

# Cross-reference the URLs with Google Safe Browsing
def check_url_with_safe_browsing(url):
    try:
        safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {
                "clientId": "your-client-id",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            }
        }
        response = requests.post(safe_browsing_url, json=payload)
        data = response.json()
        if 'matches' in data:
            return True  # The URL is flagged as malicious
        else:
            return False  # The URL is safe
    # Error handling e.g. network or API issues
    except Exception as e:
        print(f"Error checking URL: {e}")
        return False

# Verifies URL is within the same domain
def is_same_domain(base_url, url_to_check):
    base_domain = urlparse(base_url).netloc
    check_domain = urlparse(url_to_check).netloc
    return base_domain == check_domain

# Control crawling process, tracks visited URLs, generates a report
async def main():
    # Allow a command-line argument to specify the site to crawl
    parser = argparse.ArgumentParser(description="Web Crawler with Safe Browsing API")
    parser.add_argument("target_url", help="The URL of the website to crawl")
    args = parser.parse_args()

    target_url = args.target_url  # Extracts and stores the value of the command-line argument
    url_queue = deque([target_url])  # Initialize a deque to manage URLs to be crawled

    # Initialize counters for the report
    safe_links_count = 0
    malicious_links_count = 0

    # Iterate and call defined functions until the queue is empty
    try:
        while url_queue:
            current_url = url_queue.popleft()
            if current_url in visited_urls:
                continue

            visited_urls.add(current_url)
            print(f"Crawling: {current_url}")

            links = await get_links_from_page(current_url)

            for link in links:
                # Check if link has "mailto:" or "tel:" scheme and skip
                if link.startswith(("mailto:", "tel:")):
                    continue

                # Check if link is in the same domain
                if is_same_domain(target_url, link):
                    if check_url_with_safe_browsing(link):
                        print(f"Malicious link found: {link}")
                        malicious_links_count += 1
                    else:
                        print(f"Safe link: {link}")
                        safe_links_count += 1

                    # Add new links to the queue for further crawling
                    url_queue.append(link)
                else:
                    if check_url_with_safe_browsing(link):
                        print(f"Malicious link found: {link}")
                        malicious_links_count += 1
                    else:
                        print(f"Safe link: {link}")
                        safe_links_count += 1
    finally:
        # Save visited URLs to the file
        with open(visited_urls_file, "wb") as f:
            pickle.dump(visited_urls, f)

    # Generate a report
    total_links_checked = safe_links_count + malicious_links_count
    print("\n**** Report ****")
    print(f"Total Links Checked: {total_links_checked}")
    print(f"Safe Links Found: {safe_links_count}")
    print(f"Malicious Links Found: {malicious_links_count}")

# Convention to make sure the script only runs intentionally
if __name__ == '__main__':
    # Create a new event loop and run the main coroutine
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
    event_loop.run_until_complete(main())
