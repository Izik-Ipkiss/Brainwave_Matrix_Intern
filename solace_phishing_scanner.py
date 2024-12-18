import re
import tldextract
import requests
import socket
from urllib.parse import urlparse

# Google Safe Browsing API (Insert your API key)
GOOGLE_API_KEY = "AIzaSyA7QF8Z81fo8pUOBbveZvwP1uOuevJro2g"  # Replace with your Google API key

# VirusTotal API (Insert your API key)
VIRUSTOTAL_API_KEY = "9d1876eee4c0978f08a78ae17c2d8b457fd86407e66bbcb983c43ab7e6c6077c"  # Replace with your VirusTotal API key

# Trusted Domains
trusted_domains = [
    "google.com", "microsoft.com", "github.com", "facebook.com", "amazon.com",
    "apple.com", "twitter.com", "linkedin.com", "zoom.us", "youtube.com",
    "netflix.com", "paypal.com", "adobe.com", "wikipedia.org", "yahoo.com",
    "instagram.com", "whatsapp.com", "salesforce.com", "sap.com", "tesla.com",
    "bbc.co.uk", "cnn.com", "nytimes.com", "oracle.com", "ibm.com",
    "dropbox.com", "pinterest.com", "shopify.com", "spotify.com", "reddit.com",
    "uber.com", "airbnb.com", "alibaba.com", "baidu.com", "tencent.com",
    "wechat.com", "quora.com", "stackoverflow.com", "ebay.com", "medium.com",
    "coursera.org", "edx.org", "khanacademy.org", "stripe.com", "cloudflare.com",
    "zoominfo.com", "atlassian.com", "hulu.com", "duckduckgo.com", "bing.com"
]

# Blacklisted Domains
blacklisted_domains = [
    "g0ogle.com", "phishingsite.com", "fakebank.com", "malicioussite.net",
    "stealyourdata.com", "dangerouswebsite.com", "suspicious-link.com", "untrustedsite.com",
    "scammerpage.com", "badactor.net", "fake-login.com", "freegifts.com", "clickmefast.net",
    "phishingscamsite.com", "identitytheftsite.org", "dodgysite.co", "spoofedsites.com",
    "fraudulentloginpage.com", "email-stealer.org", "shadybiz.com", "toxicwebpage.net",
    "hackyou.net", "stealdata.net", "virusinjectionpage.org", "scamwebsite.com",
    "unknownsite.net", "malwaresite.com", "insecureloginpage.org", "badguysite.com",
    "trojanpage.net", "untrustedlink.com", "hijackdomain.net", "fakeupdater.com",
    "spammerpage.org", "ransompage.net", "malicious-download.com", "cheatdomain.org",
    "darksite.net", "phishingtricks.com", "exploitsite.com", "hackertrap.org",
    "fraudsterspage.net", "datastealersite.com", "maliciouslogin.net", "bogussite.org",
    "notasafesite.com", "unsafe-access.net"
]

# Normalize URL by adding "http://" or "https://" if missing
def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url  # Default to http
    return url

# Check if URL format is valid
def is_valid_url(url):
    regex = re.compile(
        r"^(http|https)://"
        r"(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3})"
    )
    return re.match(regex, url)

# Check if URL is an IP address
def is_ip_address(url):
    try:
        ip = urlparse(url).hostname
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# Check if the domain has SSL
def check_ssl(url):
    try:
        hostname = urlparse(url).hostname
        socket.create_connection((hostname, 443), timeout=5)
        return True
    except Exception:
        return False

# Check if URL is accessible on the internet
def is_site_working(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

# Alternative for WHOIS lookup: Try using HTTP headers or basic info
def get_site_info(url):
    try:
        response = requests.head(url, timeout=5)
        headers = response.headers
        return headers
    except Exception:
        return None

# Google Safe Browsing API check
def google_safe_browsing_check(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {
            "clientId": "phishing-checker",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=payload, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except requests.exceptions.RequestException:
        return None

# VirusTotal API check
def virustotal_check(url):
    api_url = f"https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        # Normalize URL for VirusTotal
        url_id = requests.utils.quote(url, safe="")
        response = requests.post(f"{api_url}/{url_id}", headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except requests.exceptions.RequestException:
        return None

# Phishing link scanner
def phishing_link_scanner(url):
    print(f"Checking URL: {url}")
    url = normalize_url(url)
    print(f"Normalized URL: {url}")

    if not is_valid_url(url):
        print("[ERROR] Incorrect URL format!")
        return "Invalid URL format."

    print("[INFO] URL format is valid.")

    # Check if it's an IP address
    if is_ip_address(url):
        print("[WARNING] The URL is an IP address. Proceed with caution.")
        return "Potentially suspicious: URL is an IP address."

    # Extract domain
    domain = tldextract.extract(url).registered_domain

    # Check against trusted and blacklisted domains
    if domain in trusted_domains:
        print("[INFO] The website is trusted.")
        return "Trusted Website."
    elif domain in blacklisted_domains:
        print("[WARNING] The website is blacklisted!")
        return "Blacklisted Website."

    # Check if the site is online
    if not is_site_working(url):
        print("[WARNING] The website is not accessible.")
        return "Not a working site."

    # Check for SSL certificate
    if check_ssl(url):
        print("[INFO] The website has a valid SSL certificate.")
    else:
        print("[WARNING] The website does not have an SSL certificate.")

    # Get site information as an alternative to WHOIS
    site_info = get_site_info(url)
    if site_info:
        print("[INFO] Retrieved site information:")
        for key, value in site_info.items():
            print(f"{key}: {value}")
    else:
        print("[WARNING] Failed to retrieve site information.")

    # Google Safe Browsing Check
    gsb_result = google_safe_browsing_check(url)
    if gsb_result:
        print("[ALERT] Google Safe Browsing flagged this URL:")
        print(gsb_result)
    else:
        print("[INFO] Google Safe Browsing did not flag this URL.")

    # VirusTotal Check
    vt_result = virustotal_check(url)
    if vt_result:
        print("[ALERT] VirusTotal flagged this URL:")
        print(vt_result)
    else:
        print("[INFO] VirusTotal did not flag this URL.")

    print("Final Verdict: Scanning Complete.")

# Input URL
url_to_check = input("Enter the URL to check: ")
phishing_link_scanner(url_to_check)
