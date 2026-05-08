import re 
from urllib.parse import urlparse 
import tldextract 

class EthioShieldDetector: 
    def __init__(self): 
        # Global & Local URL shorteners
        self.url_shorteners = [ 
            'bit.ly', 'tinyurl.com', 'shorturl.at', 'ow.ly', 'is.gd', 
            'buff.ly', 'adf.ly', 'goo.gl', 't.co', 'cutt.ly', 'rebrand.ly' 
        ] 
         
        # Suspicious TLDs often used in free phishing kits
        self.suspicious_tlds = [ 
            '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.click', '.link' 
        ] 
         
        # ETHIOPIAN SPECIFIC KEYWORDS
        # These target the "urgent" and "banking" scams common in local SMS
        self.phishing_keywords = [ 
            'cbe', 'telebirr', 'birr', 'award', 'lottery', 'enat', 'dashen', 
            'abyssinia', 'awash', 'hibret', 'coop', 'bank', 'winner', 'urgent',
            'login', 'signin', 'verify', 'secure', 'account', 'update'
        ] 
         
        # ETHIOPIAN WHITELIST (Legitimate Local Domains)
        # If the domain is exactly one of these, it's safer.
        self.legitimate_domains = [ 
            'combanketh.et', 'ethiotelecom.et', 'telebirr.com.et', 
            'insa.gov.et', 'wcu.edu.et', 'mint.gov.et', 'ebc.et',
            'google.com', 'facebook.com', 'github.com'
        ] 
     
    def extract_urls(self, text): 
        """Extract URLs from text using regex""" 
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\??[\w=&%]*' 
        urls = re.findall(url_pattern, text, re.IGNORECASE) 
        return list(set(urls)) 
     
    def analyze_url(self, url): 
        """Comprehensive Ethiopian Phishing Analysis""" 
        try: 
            parsed = urlparse(url) 
            domain = parsed.netloc or parsed.path.split('/')[0] 
             
            extracted = tldextract.extract(domain) 
            subdomain = extracted.subdomain 
            domain_name = extracted.domain 
            suffix = extracted.suffix 
             
            is_suspicious = False 
            reasons = [] 
             
            # 1. Check for URL shorteners 
            if any(shortener in domain for shortener in self.url_shorteners): 
                is_suspicious = True 
                reasons.append("URL shortener detected (hides destination)") 
             
            # 2. Check for suspicious TLDs 
            if any(domain.endswith(tld) for tld in self.suspicious_tlds): 
                is_suspicious = True 
                reasons.append(f"Suspicious TLD extension: {suffix}") 
             
            # 3. ETHIOPIAN CONTEXT: Keyword Analysis 
            # Detects "cbe-birr-award.tk" or "telebirr-login.ml"
            for keyword in self.phishing_keywords: 
                if keyword in domain.lower() or keyword in parsed.path.lower(): 
                    is_suspicious = True 
                    reasons.append(f"Ethiopian-specific threat keyword detected: '{keyword}'") 
                    break 
             
            # 4. Check for IP address usage 
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain): 
                is_suspicious = True 
                reasons.append("Direct IP address usage (avoids DNS blacklists)") 
             
            # 5. ETHIOPIAN CONTEXT: Typosquatting protection
            # Checks for "telebiir.com" or "cbe-bank.net"
            for legit in self.legitimate_domains: 
                if legit in domain and legit != domain: 
                    is_suspicious = True 
                    reasons.append(f"Potential typosquatting impersonating {legit}") 
                    break 

            # 6. Check for HTTPS (Security Protocol)
            if parsed.scheme == 'http': 
                reasons.append("⚠️ Missing SSL Encryption (Insecure Communication)") 
             
            # Calculate Risk Score
            risk_score = len(reasons) * 20 
            risk_level = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW" 
             
            return { 
                'url': url, 
                'is_suspicious': is_suspicious, 
                'risk_level': risk_level, 
                'risk_score': min(risk_score, 100), 
                'all_reasons': reasons if reasons else ["No immediate indicators found"] 
            } 
             
        except Exception as e: 
            return {'url': url, 'is_suspicious': True, 'risk_level': "ERROR", 'risk_score': 100}