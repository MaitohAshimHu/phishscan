import requests
import whois
import tldextract
import urllib3
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import re

class PhishingScanner:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'bank',
            'paypal', 'amazon', 'ebay', 'password', 'update', 'confirm'
        ]
        self.model = None
        self.load_model()

    def load_model(self):
        """Load the pre-trained model if it exists, otherwise create a new one"""
        if os.path.exists('phishing_model.joblib'):
            self.model = joblib.load('phishing_model.joblib')
        else:
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)

    def check_ssl_certificate(self, url):
        """Check SSL certificate validity and expiration"""
        try:
            domain = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expiry_date - datetime.now()).days
                    return {
                        'valid': True,
                        'days_remaining': days_remaining,
                        'issuer': dict(x[0] for x in cert['issuer'])
                    }
        except Exception as e:
            return {'valid': False, 'error': str(e)}

    def analyze_domain(self, url):
        """Analyze domain information using WHOIS"""
        try:
            domain = urlparse(url).netloc
            w = whois.whois(domain)
            return {
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'registrar': w.registrar,
                'name_servers': w.name_servers
            }
        except Exception as e:
            return {'error': str(e)}

    def extract_url_features(self, url):
        """Extract features from URL for analysis"""
        features = {}
        
        # Basic URL parsing
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        features['url_length'] = len(url)
        features['domain_length'] = len(ext.domain)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_signs'] = url.count('@')
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_www'] = 1 if 'www' in url else 0
        
        # Check for suspicious keywords
        features['suspicious_keywords'] = sum(1 for keyword in self.suspicious_keywords if keyword in url.lower())
        
        return features

    def check_redirects(self, url):
        """Check for suspicious redirects"""
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            redirect_chain = response.history
            final_url = response.url
            
            return {
                'num_redirects': len(redirect_chain),
                'final_url': final_url,
                'redirect_chain': [r.url for r in redirect_chain]
            }
        except Exception as e:
            return {'error': str(e)}

    def scan_url(self, url):
        """Perform comprehensive URL scan"""
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'ssl_check': self.check_ssl_certificate(url),
            'domain_info': self.analyze_domain(url),
            'url_features': self.extract_url_features(url),
            'redirects': self.check_redirects(url)
        }
        
        # Calculate risk score
        risk_score = 0
        
        # SSL certificate check
        if not results['ssl_check'].get('valid', False):
            risk_score += 30
        
        # Domain age check
        if results['domain_info'].get('creation_date'):
            domain_age = (datetime.now() - results['domain_info']['creation_date']).days
            if domain_age < 30:
                risk_score += 20
        
        # URL features analysis
        features = results['url_features']
        if features['suspicious_keywords'] > 3:
            risk_score += 15
        if features['num_dots'] > 3:
            risk_score += 10
        if features['num_hyphens'] > 3:
            risk_score += 10
        
        # Redirects check
        if results['redirects'].get('num_redirects', 0) > 2:
            risk_score += 15
        
        results['risk_score'] = min(risk_score, 100)
        results['risk_level'] = 'High' if risk_score > 70 else 'Medium' if risk_score > 30 else 'Low'
        
        return results

    def train_model(self, training_data):
        """Train the machine learning model with new data"""
        X = pd.DataFrame([self.extract_url_features(url) for url in training_data['urls']])
        y = training_data['labels']
        self.model.fit(X, y)
        joblib.dump(self.model, 'phishing_model.joblib')

def main():
    scanner = PhishingScanner()
    
    # Example usage
    test_url = input("Enter URL to scan: ")
    results = scanner.scan_url(test_url)
    
    print("\nPhishing Scan Results:")
    print("=" * 50)
    print(f"URL: {results['url']}")
    print(f"Risk Score: {results['risk_score']}/100")
    print(f"Risk Level: {results['risk_level']}")
    print("\nSSL Certificate:")
    print(f"Valid: {results['ssl_check'].get('valid', False)}")
    if results['ssl_check'].get('valid'):
        print(f"Days Remaining: {results['ssl_check'].get('days_remaining')}")
    
    print("\nDomain Information:")
    for key, value in results['domain_info'].items():
        if key != 'error':
            print(f"{key}: {value}")
    
    print("\nURL Features:")
    for key, value in results['url_features'].items():
        print(f"{key}: {value}")
    
    print("\nRedirect Information:")
    print(f"Number of Redirects: {results['redirects'].get('num_redirects', 0)}")
    if results['redirects'].get('redirect_chain'):
        print("Redirect Chain:")
        for url in results['redirects']['redirect_chain']:
            print(f"  -> {url}")

if __name__ == "__main__":
    main() 