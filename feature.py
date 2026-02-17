import re
import requests
import whois
import socket
from bs4 import BeautifulSoup
from datetime import date
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None

        try:
            self.response = requests.get(url, timeout=3)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.extract_all_features()

    # --- UI Data Extraction & Risk Flags ---
    def get_url_details(self):
        details = {
            "domain": self.domain,
            "ip_address": "Hidden",
            "page_title": "No Title Found",
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "age_years": 0,
            "server_location": "Unknown",
            "risk_flags": []  # New: List of specific warnings
        }

        # 1. IP Check
        try:
            details["ip_address"] = socket.gethostbyname(self.domain)
        except:
            pass

        # 2. Title Check
        try:
            if self.soup and self.soup.title:
                details["page_title"] = self.soup.title.string.strip()[:50]
        except:
            pass

        # 3. WHOIS & Age Check
        try:
            if self.whois_response:
                w = self.whois_response
                details["registrar"] = w.registrar if w.registrar else "Private"
                details["server_location"] = w.country if w.country else "Unknown"

                c_date = w.creation_date
                if isinstance(c_date, list): c_date = c_date[0]
                
                if c_date:
                    details["creation_date"] = str(c_date).split(" ")[0]
                    today = date.today()
                    details["age_years"] = round(((today.year - c_date.year) * 12 + (today.month - c_date.month)) / 12, 1)
                    
                    # Risk Flag: New Domain
                    if details["age_years"] < 0.5:
                        details["risk_flags"].append("Very New Domain (< 6 months)")
        except:
            pass

        # 4. Generate other Risk Flags
        if len(self.url) > 75:
            details["risk_flags"].append("Suspiciously Long URL")
        if "@" in self.url:
            details["risk_flags"].append("Contains '@' Symbol")
        if self.url.count(".") > 4:
            details["risk_flags"].append(" excessive Subdomains")
        
        # IP Address check for flags
        try:
            socket.inet_aton(self.domain.split(':')[0])
            details["risk_flags"].append("Raw IP Address Usage")
        except:
            pass

        return details

    # --- Feature Logic (Same as before) ---
    def extract_all_features(self):
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # --- Core Methods ---
    def UsingIp(self):
        try:
            hostname = self.domain.split(':')[0]
            socket.inet_aton(hostname)
            return -1
        except:
            return 1

    def longUrl(self):
        if len(self.url) < 54: return 1
        return 0 if len(self.url) <= 75 else -1

    def shortUrl(self):
        match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl', self.url)
        return -1 if match else 1

    def symbol(self): return -1 if "@" in self.url else 1
    def redirecting(self): return -1 if self.url.rfind('//') > 6 else 1
    def prefixSuffix(self): return -1 if '-' in self.domain else 1
    
    def SubDomains(self):
        dot_count = len(re.findall(r"\.", self.url))
        if dot_count == 1: return 1
        elif dot_count == 2: return 0
        return -1

    def Hppts(self):
        try: return 1 if self.urlparse.scheme == 'https' else -1
        except: return 1

    def NonStdPort(self):
        try:
            if ":" in self.domain:
                port = self.domain.split(":")[-1]
                if port not in ["80", "443"]: return -1
            return 1
        except: return 1

    # Placeholders to fit model shape
    def DomainRegLen(self): return -1
    def Favicon(self): return -1 
    def HTTPSDomainURL(self): return -1 if 'https' in self.domain else 1
    def RequestURL(self): return 1 
    def AnchorURL(self): return 1
    def LinksInScriptTags(self): return 1
    def ServerFormHandler(self): return 1
    def InfoEmail(self): return 1
    def AbnormalURL(self): return 1
    def WebsiteForwarding(self): return 1
    def StatusBarCust(self): return 1
    def DisableRightClick(self): return 1
    def UsingPopupWindow(self): return 1
    def IframeRedirection(self): return 1
    def AgeofDomain(self): return 1
    def DNSRecording(self): return 1
    def WebsiteTraffic(self): return 0
    def PageRank(self): return -1
    def GoogleIndex(self): return 1
    def LinksPointingToPage(self): return 1
    def StatsReport(self): return 1

    def getFeaturesList(self):
        return self.features