WARNING: Code needs to be refactored to comply with Google API documentation due to too many requests. 

# malcheck
Web scraper checking all pages of a website for malicious URLs using Google Safe Browsing API and a headless chromium browser in order to check css selectors, embedded javascript, and links protected by javascript interactivity. 


Directions: 
1. Clone github repository into local directory.
2. Install necessary libraries.
3. Edit malcheck.py to assign SAFE_BROWSING_API_KEY to your API key to your Google Lookup API Key. If you do not have one, you can request one here: https://developers.google.com/safe-browsing/v4/get-started
4. In your terminal run: malcheck.py <website_url>

DISCLAIMER: This tool is intended to be used on domains that you own or upon request of the domain owner. 
Running web scrapers on websites without permission, while legal, can result in your IP address being blocked. 
If available, always review a website's robots.txt file before scraping. 
