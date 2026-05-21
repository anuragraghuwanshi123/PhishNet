# ============================================================
# PhishNet - Automatic Feature Extraction from URL
# ============================================================
# Install required libraries:
# pip install requests beautifulsoup4 python-whois dnspython
import os
import re
import ssl
import socket
import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
import pandas as pd


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_domain(url):
    """Extract domain from URL"""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split('/')[0]


def get_soup(url):
    """Get page HTML content"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        return BeautifulSoup(response.text, 'html.parser'), response
    except:
        return None, None


# ============================================================
# FEATURE 1: UsingIP
# Check if URL uses IP address instead of domain name
# -1 = Phishing (has IP), 1 = Legitimate (has domain)
# ============================================================
def using_ip(url):
    ip_pattern = re.compile(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
    )
    match = re.search(ip_pattern, url)
    if match:
        return -1   # Phishing - using IP address
    return 1        # Legitimate - using domain name


# ============================================================
# FEATURE 2: LongURL
# Check URL length
# -1 = Phishing (>75 chars), 0 = Suspicious (54-75), 1 = Legitimate (<54)
# ============================================================
def long_url(url):
    length = len(url)
    if length < 54:
        return 1    # Short URL = Legitimate
    elif 54 <= length <= 75:
        return 0    # Medium URL = Suspicious
    return -1       # Long URL = Phishing


# ============================================================
# FEATURE 3: ShortURL
# Check if URL uses shortening services (bit.ly, tinyurl etc.)
# -1 = Phishing (uses shortener), 1 = Legitimate
# ============================================================
def short_url(url):
    shortening_services = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee'
    ]
    domain = get_domain(url).lower()
    for service in shortening_services:
        if service in domain:
            return -1   # Phishing - uses URL shortener
    return 1            # Legitimate


# ============================================================
# FEATURE 4: Symbol@
# Check if URL contains @ symbol
# -1 = Phishing (has @), 1 = Legitimate
# ============================================================
def symbol_at(url):
    if '@' in url:
        return -1   # Phishing - @ symbol tricks browser
    return 1        # Legitimate


# ============================================================
# FEATURE 5: Redirecting//
# Check if URL has double slash redirect
# -1 = Phishing (has //), 1 = Legitimate
# ============================================================
def redirecting_double_slash(url):
    # Check for // after the protocol
    url_without_protocol = url.split('://')[1] if '://' in url else url
    if '//' in url_without_protocol:
        return -1   # Phishing - double slash redirect
    return 1        # Legitimate


# ============================================================
# FEATURE 6: PrefixSuffix-
# Check if domain has dash (-) in it
# -1 = Phishing (has dash), 1 = Legitimate
# ============================================================
def prefix_suffix(url):
    domain = get_domain(url)
    if '-' in domain:
        return -1   # Phishing - dash in domain name
    return 1        # Legitimate


# ============================================================
# FEATURE 7: SubDomains
# Count number of subdomains
# -1 = Phishing (3+), 0 = Suspicious (2), 1 = Legitimate (1)
# ============================================================
def sub_domains(url):
    domain = get_domain(url)
    # Remove www
    domain = domain.replace('www.', '')
    # Count dots
    dot_count = domain.count('.')
    if dot_count == 1:
        return 1    # One dot = Legitimate (google.com)
    elif dot_count == 2:
        return 0    # Two dots = Suspicious (sub.google.com)
    return -1       # Three+ dots = Phishing


# ============================================================
# FEATURE 8: HTTPS
# Check if website has valid SSL certificate
# -1 = Phishing (no SSL), 1 = Legitimate (has SSL)
# ============================================================
def https_check(url):
    domain = get_domain(url)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # Check certificate validity
                expire_date = datetime.strptime(
                    cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                )
                if expire_date > datetime.now():
                    return 1    # Valid SSL = Legitimate
    except:
        pass
    return -1   # No SSL or expired = Phishing


# ============================================================
# FEATURE 9: DomainRegLen
# Check domain registration length (from WHOIS)
# -1 = Phishing (<1 year), 1 = Legitimate (>1 year)
# ============================================================
def domain_reg_len(url):
    domain = get_domain(url)
    try:
        w = whois.whois(domain)
        # Get expiration date
        exp_date = w.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
        if exp_date:
            remaining = (exp_date - datetime.now()).days
            if remaining > 365:
                return 1    # Long registration = Legitimate
    except:
        pass
    return -1   # Short/no registration = Phishing


# ============================================================
# FEATURE 10: Favicon
# Check if favicon is loaded from external domain
# -1 = Phishing (external favicon), 1 = Legitimate
# ============================================================
def favicon(url):
    domain = get_domain(url)
    soup, _ = get_soup(url)
    if soup:
        for link in soup.find_all('link', rel='icon'):
            href = link.get('href', '')
            if href and domain not in href and href.startswith('http'):
                return -1   # External favicon = Phishing
    return 1    # Same domain favicon = Legitimate


# ============================================================
# FEATURE 11: NonStdPort
# Check if URL uses non-standard port
# -1 = Phishing (non-standard port), 1 = Legitimate
# ============================================================
def non_std_port(url):
    parsed = urlparse(url)
    port = parsed.port
    standard_ports = [80, 443, None]
    if port not in standard_ports:
        return -1   # Non-standard port = Phishing
    return 1        # Standard port = Legitimate


# ============================================================
# FEATURE 12: HTTPSDomainURL
# Check if "https" appears in the domain name (trick!)
# -1 = Phishing (https in domain), 1 = Legitimate
# ============================================================
def https_domain_url(url):
    domain = get_domain(url)
    if 'https' in domain.lower():
        return -1   # "https" in domain name = Phishing trick
    return 1        # Normal domain = Legitimate


# ============================================================
# FEATURE 13: RequestURL
# Check if page resources load from external domains
# -1 = Phishing (>61% external), 0 = Suspicious (22-61%), 1 = Legitimate
# ============================================================
def request_url(url):
    domain = get_domain(url)
    soup, _ = get_soup(url)
    if not soup:
        return -1
    
    total = 0
    external = 0
    
    # Check images, scripts, links
    tags = soup.find_all(['img', 'script', 'link'])
    for tag in tags:
        src = tag.get('src') or tag.get('href') or ''
        if src.startswith('http'):
            total += 1
            if domain not in src:
                external += 1
    
    if total == 0:
        return 1
    
    percentage = (external / total) * 100
    if percentage < 22:
        return 1    # Low external = Legitimate
    elif 22 <= percentage <= 61:
        return 0    # Medium external = Suspicious
    return -1       # High external = Phishing


# ============================================================
# FEATURE 14: AnchorURL
# Check if anchor tags link to external/different domains
# -1 = Phishing (>67% external), 0 = Suspicious (31-67%), 1 = Legitimate
# ============================================================
def anchor_url(url):
    domain = get_domain(url)
    soup, _ = get_soup(url)
    if not soup:
        return -1
    
    total = 0
    unsafe = 0
    
    for a in soup.find_all('a', href=True):
        href = a['href']
        total += 1
        if href.startswith('http') and domain not in href:
            unsafe += 1
        elif href in ['#', '#content', '#skip', 'javascript::void(0)']:
            unsafe += 1
    
    if total == 0:
        return 1
    
    percentage = (unsafe / total) * 100
    if percentage < 31:
        return 1    # Low unsafe = Legitimate
    elif 31 <= percentage <= 67:
        return 0    # Medium unsafe = Suspicious
    return -1       # High unsafe = Phishing


# ============================================================
# FEATURE 15: LinksInScriptTags
# Check links inside <script> and <meta> tags
# -1 = Phishing (>81% external), 0 = Suspicious (17-81%), 1 = Legitimate
# ============================================================
def links_in_script_tags(url):
    domain = get_domain(url)
    soup, _ = get_soup(url)
    if not soup:
        return -1
    
    total = 0
    external = 0
    
    for tag in soup.find_all(['script', 'meta', 'link']):
        src = tag.get('src') or tag.get('href') or tag.get('content') or ''
        if 'http' in src:
            total += 1
            if domain not in src:
                external += 1
    
    if total == 0:
        return 1
    
    percentage = (external / total) * 100
    if percentage < 17:
        return 1
    elif 17 <= percentage <= 81:
        return 0
    return -1


# ============================================================
# FEATURE 16: ServerFormHandler
# Check where form data is sent (action attribute)
# -1 = Phishing (different domain/blank), 0 = Suspicious (about:blank)
# 1 = Legitimate (same domain)
# ============================================================
def server_form_handler(url):
    domain = get_domain(url)
    soup, _ = get_soup(url)
    if not soup:
        return -1
    
    for form in soup.find_all('form', action=True):
        action = form['action']
        if not action or action == '#':
            return -1   # Empty action = Phishing
        if 'about:blank' in action:
            return 0    # About blank = Suspicious
        if action.startswith('http') and domain not in action:
            return -1   # External form handler = Phishing
    
    return 1    # Same domain form = Legitimate


# ============================================================
# FEATURE 17: InfoEmail
# Check if page uses mailto: to submit info
# -1 = Phishing (uses email), 1 = Legitimate
# ============================================================
def info_email(url):
    soup, response = get_soup(url)
    if not soup:
        return -1
    
    # Check for mailto in forms or links
    page_text = str(soup)
    if 'mailto:' in page_text:
        return -1   # Email submission = Phishing
    return 1        # No email submission = Legitimate


# ============================================================
# FEATURE 18: AbnormalURL
# Check if hostname matches WHOIS data
# -1 = Phishing (mismatch), 1 = Legitimate (match)
# ============================================================
def abnormal_url(url):
    domain = get_domain(url)
    try:
        w = whois.whois(domain)
        if w.domain_name:
            whois_domain = w.domain_name
            if isinstance(whois_domain, list):
                whois_domain = whois_domain[0]
            if whois_domain.lower() in domain.lower():
                return 1    # WHOIS matches = Legitimate
    except:
        pass
    return -1   # WHOIS mismatch = Phishing


# ============================================================
# FEATURE 19: WebsiteForwarding
# Count number of redirects
# -1 = Phishing (>4 redirects), 0 = Suspicious (2-4), 1 = Legitimate (0-1)
# ============================================================
def website_forwarding(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        redirect_count = len(response.history)
        if redirect_count <= 1:
            return 1    # Few redirects = Legitimate
        elif 2 <= redirect_count <= 4:
            return 0    # Some redirects = Suspicious
        return -1       # Many redirects = Phishing
    except:
        return -1


# ============================================================
# FEATURE 20: StatusBarCust
# Check if JavaScript customizes status bar (onmouseover)
# -1 = Phishing (customizes status bar), 1 = Legitimate
# ============================================================
def status_bar_cust(url):
    soup, _ = get_soup(url)
    if not soup:
        return -1
    
    page_text = str(soup)
    if 'onmouseover' in page_text.lower():
        return -1   # Status bar customization = Phishing
    return 1        # No customization = Legitimate


# ============================================================
# FEATURE 21: DisableRightClick
# Check if right-click is disabled via JavaScript
# -1 = Phishing (disabled), 1 = Legitimate
# ============================================================
def disable_right_click(url):
    soup, _ = get_soup(url)
    if not soup:
        return -1
    
    page_text = str(soup)
    if 'event.button==2' in page_text or 'contextmenu' in page_text:
        return -1   # Disabled right-click = Phishing
    return 1        # Right-click enabled = Legitimate


# ============================================================
# FEATURE 22: UsingPopupWindow
# Check if page uses popup windows with text fields
# -1 = Phishing (uses popups), 1 = Legitimate
# ============================================================
def using_popup_window(url):
    soup, _ = get_soup(url)
    if not soup:
        return -1
    
    page_text = str(soup)
    if 'window.open' in page_text and 'prompt(' in page_text:
        return -1   # Popup with input = Phishing
    return 1        # No suspicious popup = Legitimate


# ============================================================
# FEATURE 23: IframeRedirection
# Check if page uses hidden iframes
# -1 = Phishing (has iframe), 1 = Legitimate
# ============================================================
def iframe_redirection(url):
    soup, _ = get_soup(url)
    if not soup:
        return -1
    
    iframes = soup.find_all('iframe')
    for iframe in iframes:
        # Check for hidden/invisible iframes
        style = iframe.get('style', '')
        width = iframe.get('width', '100')
        height = iframe.get('height', '100')
        
        if ('display:none' in style or
            'visibility:hidden' in style or
            width == '0' or height == '0'):
            return -1   # Hidden iframe = Phishing
    
    if iframes:
        return 0    # Visible iframe = Suspicious
    return 1        # No iframe = Legitimate


# ============================================================
# FEATURE 24: AgeofDomain
# Check age of domain (from WHOIS)
# -1 = Phishing (<6 months), 1 = Legitimate (>6 months)
# ============================================================
def age_of_domain(url):
    domain = get_domain(url)
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            if age_days > 180:  # 6 months
                return 1    # Old domain = Legitimate
    except:
        pass
    return -1   # New/unknown domain = Phishing


# ============================================================
# FEATURE 25: DNSRecording
# Check if domain has DNS records
# -1 = Phishing (no DNS), 1 = Legitimate (has DNS)
# ============================================================
def dns_recording(url):
    domain = get_domain(url)
    try:
        dns.resolver.resolve(domain, 'A')
        return 1    # Has DNS records = Legitimate
    except:
        return -1   # No DNS records = Phishing


# ============================================================
# FEATURE 26: WebsiteTraffic
# Check Alexa/traffic rank (lower number = more popular)
# -1 = Phishing (no rank/low traffic), 0 = Suspicious, 1 = Legitimate
# ============================================================
def website_traffic(url):
    domain = get_domain(url)
    try:
        # Using a free alternative traffic check
        response = requests.get(
            f'https://api.similarweb.com/v1/website/{domain}/total-traffic-and-engagement/visits',
            timeout=5
        )
        if response.status_code == 200:
            return 1    # Has traffic data = Legitimate
    except:
        pass
    
    # Fallback: check if site is accessible and has content
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200 and len(response.text) > 1000:
            return 0    # Accessible but unknown traffic = Suspicious
    except:
        pass
    return -1   # Not accessible = Phishing


# ============================================================
# FEATURE 27: PageRank
# Check Google PageRank (domain authority)
# -1 = Phishing (low rank), 1 = Legitimate (high rank)
# ============================================================
def page_rank(url):
    domain = get_domain(url)
    try:
        # Using Open PageRank API (free)
        response = requests.get(
            f'https://openpagerank.com/api/v1.0/getPageRank?domains[]={domain}',
            headers={'API-OPR': 'YOUR_API_KEY'},  # Get free key at openpagerank.com
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            rank = data['response'][0]['page_rank_integer']
            if rank >= 2:
                return 1    # Good rank = Legitimate
            return 0        # Low rank = Suspicious
    except:
        pass
    return -1   # No rank = Phishing


# ============================================================
# FEATURE 28: GoogleIndex
# Check if page is indexed by Google
# -1 = Phishing (not indexed), 1 = Legitimate (indexed)
# ============================================================
def google_index(url):
    try:
        # Search Google for the site
        search_url = f'https://www.google.com/search?q=site:{url}'
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(search_url, headers=headers, timeout=10)
        
        if 'did not match any documents' not in response.text:
            return 1    # Indexed = Legitimate
        return -1       # Not indexed = Phishing
    except:
        return -1


# ============================================================
# FEATURE 29: LinksPointingToPage
# Check number of backlinks pointing to page
# -1 = Phishing (0 links), 0 = Suspicious (1-2 links), 1 = Legitimate (3+)
# ============================================================
def links_pointing_to_page(url):
    try:
        # Using a free backlink checker alternative
        domain = get_domain(url)
        response = requests.get(
            f'https://api.moz.com/links/v2/url_metrics',
            params={'target': domain},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            links = data.get('external_links', 0)
            if links > 2:
                return 1
            elif links >= 1:
                return 0
    except:
        pass
    return -1


# ============================================================
# FEATURE 30: StatsReport
# Check if URL is in known phishing blacklists
# -1 = Phishing (blacklisted), 1 = Legitimate
# ============================================================
def stats_report(url):
    domain = get_domain(url)
    try:
        # Check Google Safe Browsing (you need API key)
        # Free alternative: check PhishTank
        response = requests.post(
            'https://checkurl.phishtank.com/checkurl/',
            data={'url': url, 'format': 'json'},
            headers={'User-Agent': 'phishtank/check'},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('results', {}).get('in_database'):
                return -1   # In PhishTank = Phishing
    except:
        pass
    return 1    # Not in blacklist = Legitimate


# ============================================================
# MAIN FUNCTION: Extract ALL 30 Features from URL
# ============================================================
def extract_all_features(url):
    """
    Extract all 30 phishing detection features from a URL
    
    Returns: dict with all feature values and final feature array
    """
    print(f"\n🔍 Analyzing URL: {url}")
    print("=" * 60)
    
    features = {}
    
    # Extract each feature
    print("Extracting features...")
    
    features['UsingIP']            = using_ip(url)
    print(f"✓ Feature 1  - UsingIP: {features['UsingIP']}")
    
    features['LongURL']            = long_url(url)
    print(f"✓ Feature 2  - LongURL: {features['LongURL']}")
    
    features['ShortURL']           = short_url(url)
    print(f"✓ Feature 3  - ShortURL: {features['ShortURL']}")
    
    features['Symbol@']            = symbol_at(url)
    print(f"✓ Feature 4  - Symbol@: {features['Symbol@']}")
    
    features['Redirecting//']      = redirecting_double_slash(url)
    print(f"✓ Feature 5  - Redirecting//: {features['Redirecting//']}")
    
    features['PrefixSuffix-']      = prefix_suffix(url)
    print(f"✓ Feature 6  - PrefixSuffix-: {features['PrefixSuffix-']}")
    
    features['SubDomains']         = sub_domains(url)
    print(f"✓ Feature 7  - SubDomains: {features['SubDomains']}")
    
    features['HTTPS']              = https_check(url)
    print(f"✓ Feature 8  - HTTPS: {features['HTTPS']}")
    
    features['DomainRegLen']       = domain_reg_len(url)
    print(f"✓ Feature 9  - DomainRegLen: {features['DomainRegLen']}")
    
    features['Favicon']            = favicon(url)
    print(f"✓ Feature 10 - Favicon: {features['Favicon']}")
    
    features['NonStdPort']         = non_std_port(url)
    print(f"✓ Feature 11 - NonStdPort: {features['NonStdPort']}")
    
    features['HTTPSDomainURL']     = https_domain_url(url)
    print(f"✓ Feature 12 - HTTPSDomainURL: {features['HTTPSDomainURL']}")
    
    features['RequestURL']         = request_url(url)
    print(f"✓ Feature 13 - RequestURL: {features['RequestURL']}")
    
    features['AnchorURL']          = anchor_url(url)
    print(f"✓ Feature 14 - AnchorURL: {features['AnchorURL']}")
    
    features['LinksInScriptTags']  = links_in_script_tags(url)
    print(f"✓ Feature 15 - LinksInScriptTags: {features['LinksInScriptTags']}")
    
    features['ServerFormHandler']  = server_form_handler(url)
    print(f"✓ Feature 16 - ServerFormHandler: {features['ServerFormHandler']}")
    
    features['InfoEmail']          = info_email(url)
    print(f"✓ Feature 17 - InfoEmail: {features['InfoEmail']}")
    
    features['AbnormalURL']        = abnormal_url(url)
    print(f"✓ Feature 18 - AbnormalURL: {features['AbnormalURL']}")
    
    features['WebsiteForwarding']  = website_forwarding(url)
    print(f"✓ Feature 19 - WebsiteForwarding: {features['WebsiteForwarding']}")
    
    features['StatusBarCust']      = status_bar_cust(url)
    print(f"✓ Feature 20 - StatusBarCust: {features['StatusBarCust']}")
    
    features['DisableRightClick']  = disable_right_click(url)
    print(f"✓ Feature 21 - DisableRightClick: {features['DisableRightClick']}")
    
    features['UsingPopupWindow']   = using_popup_window(url)
    print(f"✓ Feature 22 - UsingPopupWindow: {features['UsingPopupWindow']}")
    
    features['IframeRedirection']  = iframe_redirection(url)
    print(f"✓ Feature 23 - IframeRedirection: {features['IframeRedirection']}")
    
    features['AgeofDomain']        = age_of_domain(url)
    print(f"✓ Feature 24 - AgeofDomain: {features['AgeofDomain']}")
    
    features['DNSRecording']       = dns_recording(url)
    print(f"✓ Feature 25 - DNSRecording: {features['DNSRecording']}")
    
    features['WebsiteTraffic']     = website_traffic(url)
    print(f"✓ Feature 26 - WebsiteTraffic: {features['WebsiteTraffic']}")
    
    features['PageRank']           = page_rank(url)
    print(f"✓ Feature 27 - PageRank: {features['PageRank']}")
    
    features['GoogleIndex']        = google_index(url)
    print(f"✓ Feature 28 - GoogleIndex: {features['GoogleIndex']}")
    
    features['LinksPointingToPage']= links_pointing_to_page(url)
    print(f"✓ Feature 29 - LinksPointingToPage: {features['LinksPointingToPage']}")
    
    features['StatsReport']        = stats_report(url)
    print(f"✓ Feature 30 - StatsReport: {features['StatsReport']}")
    
    # Convert to array for model input (in correct order)
    feature_array = [
        features['UsingIP'],
        features['LongURL'],
        features['ShortURL'],
        features['Symbol@'],
        features['Redirecting//'],
        features['PrefixSuffix-'],
        features['SubDomains'],
        features['HTTPS'],
        features['DomainRegLen'],
        features['Favicon'],
        features['NonStdPort'],
        features['HTTPSDomainURL'],
        features['RequestURL'],
        features['AnchorURL'],
        features['LinksInScriptTags'],
        features['ServerFormHandler'],
        features['InfoEmail'],
        features['AbnormalURL'],
        features['WebsiteForwarding'],
        features['StatusBarCust'],
        features['DisableRightClick'],
        features['UsingPopupWindow'],
        features['IframeRedirection'],
        features['AgeofDomain'],
        features['DNSRecording'],
        features['WebsiteTraffic'],
        features['PageRank'],
        features['GoogleIndex'],
        features['LinksPointingToPage'],
        features['StatsReport']
    ]
    
    return features, feature_array