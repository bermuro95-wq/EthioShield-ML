import re
from urllib.parse import urlparse
import tldextract

class PhishingDetector:
    def __init__(self):
        # Known URL shorteners
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'shorturl.at', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'goo.gl', 't.co', 'cutt.ly', 'rebrand.ly'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.click', '.link'
        ]
        
        # Phishing keywords in URLs
        self.phishing_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'update',
            'confirm', 'authenticate', 'banking', 'paypal', 'amazon',
            'apple', 'microsoft', 'facebook', 'instagram', 'security'
        ]
        
        # Known legitimate domains (whitelist)
        self.legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'youtube.com', 'twitter.com', 'linkedin.com'
        ]
    
    def extract_urls(self, text):
        """Extract all URLs from text using regex"""
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\??[\w=&%]*'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        return list(set(urls))
    
    def analyze_url(self, url):
        """Comprehensive URL phishing analysis"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            # Extract domain components
            extracted = tldextract.extract(domain)
            subdomain = extracted.subdomain
            domain_name = extracted.domain
            suffix = extracted.suffix
            
            is_suspicious = False
            reasons = []
            
            # Check for URL shorteners
            if any(shortener in domain for shortener in self.url_shorteners):
                is_suspicious = True
                reasons.append("URL shortener detected (often used to hide malicious links)")
            
            # Check suspicious TLDs
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                is_suspicious = True
                reasons.append(f"Suspicious domain extension: {domain.split('.')[-1]}")
            
            # Check for phishing keywords
            for keyword in self.phishing_keywords:
                if keyword in domain.lower() or keyword in parsed.path.lower():
                    is_suspicious = True
                    reasons.append(f"Suspicious keyword '{keyword}' in URL")
                    break
            
            # Check for IP address usage
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                is_suspicious = True
                reasons.append("IP address used instead of domain name (phishing indicator)")
            
            # Check for excessive subdomains
            if subdomain.count('.') > 2:
                is_suspicious = True
                reasons.append("Multiple subdomains detected (potential phishing domain)")
            
            # Check for HTTPS
            if parsed.scheme == 'http':
                reasons.append("⚠️ No HTTPS encryption (communication not secure)")
            
            # Check against legitimate domains (typosquatting)
            for legit in self.legitimate_domains:
                if legit in domain and legit != domain:
                    if len(domain) > len(legit) + 2:
                        is_suspicious = True
                        reasons.append(f"Possible typosquatting targeting {legit}")
                        break
            
            # Calculate risk score
            risk_score = len(reasons) * 25
            risk_level = "HIGH" if risk_score > 50 else "MEDIUM" if risk_score > 25 else "LOW"
            
            return {
                'url': url,
                'domain': domain,
                'is_suspicious': is_suspicious,
                'risk_level': risk_level,
                'risk_score': min(risk_score, 100),
                'reason': reasons[0] if reasons else "Looks legitimate",
                'all_reasons': reasons if reasons else ["No suspicious indicators found"]
            }
            
        except Exception as e:
            return {
                'url': url,
                'domain': 'unknown',
                'is_suspicious': True,
                'risk_level': "HIGH",
                'risk_score': 100,
                'reason': f"Error analyzing URL",
                'all_reasons': [f"Analysis error: {str(e)}"]
            }