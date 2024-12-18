import re  # For pattern matching
import tldextract  # For extracting main domain components from a URL
from urllib.parse import urlparse  # For parsing and validating URLs
from rapidfuzz import fuzz  # For fuzzy string matching

# Add a list of known trusted domains
trusted_domains = ["google.com", "facebook.com", "amazon.com", "microsoft.com", "paypal.com"]

# Blacklist of known malicious domains
blacklist = ["phishingsite.com", "malicious-domain.net", "fakebank.com"]

def normalize_url(url):
    """
    Add 'https://' to the URL if no scheme (http/https) is provided.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  # Default to HTTPS
    return url

def is_valid_url(url):
    """
    Check if the URL is valid using urllib.parse.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_http_insecure(url):
    """
    Check if the URL uses an insecure 'http://' connection.
    """
    return url.startswith("http://")

def is_suspicious_url(url):
    """
    Check if the URL contains patterns commonly found in phishing attacks.
    """
    suspicious_patterns = [
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP address instead of domain
        r"@",  # '@' symbol in URL (common in phishing attacks)
        r"%",  # Encoded characters like '%20' or '%2F'
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True
    return False

def extract_domain(url):
    """
    Extract the main domain (excluding subdomains) from a URL.
    """
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    return domain

def is_blacklisted(url):
    """
    Check if the domain of the URL is in the blacklist.
    """
    domain = extract_domain(url)
    return domain in blacklist

def is_lookalike_domain(url):
    """
    Check if the URL's domain closely matches a trusted domain (typosquatting detection).
    """
    domain = extract_domain(url)
    for trusted_domain in trusted_domains:
        similarity_ratio = fuzz.ratio(domain, trusted_domain)
        if similarity_ratio > 80:  # Threshold for similarity
            print(f"[WARNING] Potential lookalike domain detected! '{domain}' resembles '{trusted_domain}'")
            return True
    return False

# Main Program Loop
while True:
    url_input = input("\nEnter a URL to check (or type 'exit' to quit): ").strip()
    if url_input.lower() == "exit":
        print("Exiting the phishing link scanner. Stay safe!")
        break

    # Normalize and validate URL
    url = normalize_url(url_input)

    if not is_valid_url(url):
        print("[ERROR] Invalid URL. Please enter a properly formatted URL (e.g., google.com, example.com).")
    else:
        domain = extract_domain(url)

        if is_http_insecure(url):
            print(f"[WARNING] The URL '{url}' uses an insecure connection (HTTP). Consider HTTPS for security.")

        if is_blacklisted(url):
            print(f"[ALERT] This URL belongs to a blacklisted domain: {domain}")
        elif is_lookalike_domain(url):
            print(f"[ALERT] This URL '{domain}' resembles a trusted domain. Be cautious!")
        elif is_suspicious_url(url):
            print(f"[ALERT] Suspicious URL detected: {url}")
        else:
            print(f"[INFO] Domain: {domain}")
            print("[INFO] URL does not appear suspicious.")
