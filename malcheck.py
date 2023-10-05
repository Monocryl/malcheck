import argparse
import asyncio 
from pyppeteer import launch
import requests 
from collections import deque 

#Replace with your GSB API key
SAFE_BROWSING_API_KEY = 'YOUR_API_KEY'

async def get_links_from_page(url):
    browser = await launch(headless=true)
    page = await browser.newPage()
    await page.goto(url)

    #Allow javascript to load (adjust as needed)
    await asyncio.sleep(5)

    #Extract links from page
    links = await page.evaluation('''() => {
        const links = [];
        document.querySelectorAll('a').forEach(a => {
            if (a.href) {
                links.push(a.href);
            }
        });
        return links;
    }''')

    await browser.close()
    return links 

def check_url_with_safe_browsing(url):
    try: 
        safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
        payload = {
                "client": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                    }
                }

        response = requests.post(safe_browsing_url, json=payload)
        data = response.json()
        if 'matches' in data: 
            return True #URL is flagged as malicious 
        else:
            return False #URL is flagged as safe 
        except Exception as e: 
            print(f"Error checking URL: {e}") 
            return False 

async def main(): 
    parser = argparse.ArgumentParser(description="Google Safe Browsing Web Crawler")
    parser.add_argument("target_url", help="The URL of the website to crawl")
    args = parser.parse_args()

    target_url = args.target_url
    visited_urls = set() #Track visited URLs 
    url_queue = deque([target_url]) #Queue for crawling 

    while url_queue: 
        current_url = url_queue.popleft()
        if current_url in visited_urls: 
            continue 

        visited_urls.add(current_url)
        print(f"Crawling: {current_url}")

        links = await get_links_from_page(current_url)

        for link in links: 
            if check_url_with_safe_browsing(link):
                print(f"Malicious link found: {link}")
            else:
                print(f"Safe link: {link}") 

            #add new links to queue for further crawling 
            if link not in visited_urls: 
                url_queue.append(link)

if __name_ '__main__':
    asyncio.get_event_loop().run_until_complete(main())
