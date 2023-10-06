import argparse
import asyncio
from pyppeteer import launch
import requests
from collections import deque
from urllib.parse import urlparse 

#Replace with your Google Safe Browsing API key
SAFE_BROWSING_API_KEY = "AIzaSyCYDKSiA6Gt_cfRhvmHGFHW7wrAsvsb4Dc"

#launch headless web browser, go to url, extract links
async def get_links_from_page(url):
    browser = await launch(headless=True)
    page = await browser.newPage()
    await page.goto(url)
    
    #Wait for JavaScript to load (adjust the time as needed)
    await asyncio.sleep(3)
    
    #execute javascript function to extract links from page
    links = await page.evaluate('''() => {
        const links = [];
        document.querySelectorAll("a").forEach(a => {
            if (a.href) {
                links.push(a.href);
            }
        });
        return links;
    }''')
    #close browser page to free up resources when finished 
    await browser.close()
    return links

#Crossreferences the URLs with Google Safe Browsing
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
    #error handling e.g. network or api issues 
    except Exception as e:
            print(f"Error checking URL: {e}")
            return False

#verifies URL is within same domain
def is_same_domain(base_url, url_to_check):
    base_domain = urlparse(base_url).netloc
    check_domain = urlparse(url_to_check).netloc
    return base_domain == check_domain

#control crawling process, tracks visited urls, generates report 
async def main():
    #allow command-line argument to specify site to crawl 
    parser = argparse.ArgumentParser(description="Web Crawler with Safe Browsing API")
    parser.add_argument("target_url", help="The URL of the website to crawl")
    args = parser.parse_args()
    
    target_url = args.target_url #extracts and stores value of command line argument
    visited_urls = set()  #initialize empty set to track visited URLs
    url_queue = deque([target_url])  #initialize deque to manage URLs to be crawled 
    #initialize counters for report 
    safe_links_count = 0 
    malicious_links_count = 0
    
    #iterate and call defined functions until queue is empty  
    while url_queue:
        current_url = url_queue.popleft()
        if current_url in visited_urls:
            continue
        
        visited_urls.add(current_url)
        print(f"Crawling: {current_url}")
        
        links = await get_links_from_page(current_url)
        
        for link in links:
            #Check if link has "mailto:" or "tel:" scheme and skip
            if link.startswith("mailto:" or "tel:"):
                continue
            #check if link is in same domain 
            if is_same_domain(target_url, link): 
                if check_url_with_safe_browsing(link):
                    print(f"Malicious link found: {link}")
                    malicious_links_count += 1
                else:
                    print(f"Safe link: {link}")
                    safe_links_count += 1 

                #Add new links to the queue for further crawling
                if link not in visited_urls:
                    url_queue.append(link)
            else: 
                if check_url_with_safe_browsing(link):
                    print(f"Malicious link found: {link}")
                    malicious_links_count += 1 
                else: 
                    print(f"Safe link: {link}")
                    safe_links_count += 1 

    #Generate report 
    total_links_checked = safe_links_count + malicious_links_count
    print("\n**** Report ****")
    print(f"Total Links Checked: {total_links_checked}")
    print(f"Safe Links Found: {safe_links_count}")
    print(f"Malicious Links Found: {malicious_links_count}")

#convention to make sure script only runs intentionally 
if __name__ == '__main__':
    #Create new event loop and run the main coroutine
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
    event_loop.run_until_complete(main())
