import requests
import time
import os
import base64
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
from dotenv import load_dotenv
from urllib.parse import urlparse


class ThreatLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectionResult:
    detector_name: str
    threat_level: ThreatLevel
    confidence: float
    details: Dict[str, Any]
    urls_checked: List[str]
    success: bool = True
    error_message: Optional[str] = None


class SecLookupDetector:
    """
    SecLookup detector for malicious domains
    
    SecLookup provides domain security scanning services to identify 
    malicious domains using various threat intelligence sources.
    
    Requires API key from SecLookup service.
    """
    
    def __init__(self, api_key: str):
        """
        Initialize SecLookup detector
        
        Args:
            api_key: SecLookup API key (required)
        """
        if not api_key:
            raise ValueError("SecLookup API key is required")
            
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecLookupDetector/1.0',
            'Accept': 'application/json'
        })
        self.base_url = "https://api.seclookup.com/api/v1/scan/api"
    
    def _extract_domain(self, url: str) -> str:
        """
        Extract domain from URL
        
        Args:
            url: The URL to extract domain from
            
        Returns:
            The domain part of the URL
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            # If parsing fails, return the original URL and let API handle it
            return url.lower()
    
    def check_url(self, url: str) -> DetectionResult:
        """
        Check a single URL against SecLookup
        
        Args:
            url: The URL to check
            
        Returns:
            DetectionResult with threat assessment
        """
        return self.check_urls([url])
    
    def check_urls(self, urls: List[str]) -> DetectionResult:
        """
        Check multiple URLs against SecLookup
        
        Args:
            urls: List of URLs to check
            
        Returns:
            DetectionResult with threat assessment for all URLs
        """
        if not urls:
            return DetectionResult(
                detector_name="SecLookup",
                threat_level=ThreatLevel.SAFE,
                confidence=0.0,
                details={"error": "No URLs provided"},
                urls_checked=[],
                success=False,
                error_message="No URLs provided"
            )
        
        try:
            # Extract unique domains from URLs
            domains_to_check = []
            url_to_domain_map = {}
            
            for url in urls:
                domain = self._extract_domain(url)
                if domain and domain not in domains_to_check:
                    domains_to_check.append(domain)
                url_to_domain_map[url] = domain
            
            # Check each domain via SecLookup API
            malicious_domains = []
            safe_domains = []
            errors = []
            all_results = []
            
            for domain in domains_to_check:
                try:
                    # Make API request
                    params = {
                        'api_key': self.api_key,
                        'domain': domain
                    }
                    
                    response = self.session.get(
                        self.base_url,
                        params=params,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Process API response
                        if data.get('code') == 'OK':
                            domain_data = data.get('data', {})
                            is_malicious = domain_data.get('is_malicious', False)
                            reference = domain_data.get('reference', '')
                            
                            # If malicious, generate a more specific VirusTotal URL
                            if is_malicious:
                                # Find the first original URL that maps to this malicious domain
                                original_url_for_domain = next((url for url, d in url_to_domain_map.items() if d == domain), None)
                                
                                if original_url_for_domain:
                                    # Create a VirusTotal-compatible base64 encoded URL
                                    encoded_url = base64.urlsafe_b64encode(original_url_for_domain.encode()).rstrip(b'=').decode('ascii')
                                    reference = f"https://www.virustotal.com/gui/url/{encoded_url}"

                            domain_result = {
                                "domain": domain,
                                "is_malicious": is_malicious,
                                "reference": reference,
                                "http_code": data.get('http_code'),
                                "message": data.get('message'),
                                "full_api_response": data
                            }
                            
                            all_results.append(domain_result)
                            
                            if is_malicious:
                                malicious_domains.append(domain_result)
                            else:
                                safe_domains.append(domain_result)
                        else:
                            error_msg = data.get('message', 'Unknown API error')
                            errors.append({
                                "domain": domain,
                                "error": error_msg,
                                "api_response": data
                            })
                    
                    elif response.status_code == 400:
                        error_text = response.text
                        try:
                            error_data = response.json()
                            error_detail = error_data.get('message', error_text)
                        except:
                            error_detail = error_text
                            
                        errors.append({
                            "domain": domain,
                            "error": f"Bad request: {error_detail}",
                            "status_code": 400
                        })
                    
                    elif response.status_code == 401:
                        return DetectionResult(
                            detector_name="SecLookup",
                            threat_level=ThreatLevel.SAFE,
                            confidence=0.0,
                            details={
                                "error": "Unauthorized - check API key",
                                "status_code": 401,
                                "api_key_present": bool(self.api_key),
                                "api_key_length": len(self.api_key) if self.api_key else 0
                            },
                            urls_checked=[],
                            success=False,
                            error_message="Unauthorized - invalid API key"
                        )
                    
                    elif response.status_code == 429:
                        return DetectionResult(
                            detector_name="SecLookup",
                            threat_level=ThreatLevel.SAFE,
                            confidence=0.0,
                            details={"error": "Rate limited by SecLookup API"},
                            urls_checked=[],
                            success=False,
                            error_message="Rate limited by API"
                        )
                    
                    else:
                        errors.append({
                            "domain": domain,
                            "error": f"HTTP {response.status_code}: {response.text}",
                            "status_code": response.status_code
                        })
                
                except requests.exceptions.Timeout:
                    errors.append({
                        "domain": domain,
                        "error": "Request timeout"
                    })
                except requests.exceptions.RequestException as e:
                    errors.append({
                        "domain": domain,
                        "error": f"Request error: {str(e)}"
                    })
                except Exception as e:
                    errors.append({
                        "domain": domain,
                        "error": f"Unexpected error: {str(e)}"
                    })
                
                # Add small delay between requests to be respectful
                time.sleep(0.1)
            
            # Determine overall threat level
            if malicious_domains:
                # If any domain is malicious, mark as high threat
                threat_level = ThreatLevel.HIGH
                confidence = 0.9
            elif errors:
                # If there were errors but no confirmed threats, mark as low confidence safe
                threat_level = ThreatLevel.SAFE
                confidence = 0.5
            else:
                # All domains checked and found safe
                threat_level = ThreatLevel.SAFE
                confidence = 0.85
            
            # Map domains back to original URLs
            url_results = []
            for url in urls:
                domain = url_to_domain_map.get(url, url)
                domain_result = next((r for r in all_results if r['domain'] == domain), None)
                if domain_result:
                    url_results.append({
                        "url": url,
                        "domain": domain,
                        "is_malicious": domain_result['is_malicious'],
                        "reference": domain_result.get('reference', ''),
                        "domain_result": domain_result
                    })
            
            # Prepare detailed results
            details = {
                "malicious_domains": malicious_domains,
                "safe_domains": safe_domains,
                "errors": errors,
                "url_results": url_results,
                "total_urls_checked": len(urls),
                "total_domains_checked": len(domains_to_check),
                "total_malicious": len(malicious_domains),
                "total_safe": len(safe_domains),
                "total_errors": len(errors),
                "unique_domains": domains_to_check
            }
            
            success = len(errors) == 0 or len(all_results) > 0
            error_message = None if success else f"Failed to check {len(errors)} domains"
            
        except Exception as e:
            return DetectionResult(
                detector_name="SecLookup",
                threat_level=ThreatLevel.SAFE,
                confidence=0.0,
                details={"error": f"Unexpected error: {str(e)}"},
                urls_checked=[],
                success=False,
                error_message=f"Unexpected error: {str(e)}"
            )
        
        return DetectionResult(
            detector_name="SecLookup",
            threat_level=threat_level,
            confidence=confidence,
            details=details,
            urls_checked=urls,
            success=success,
            error_message=error_message
        )
    
    def get_detector_info(self) -> Dict[str, Any]:
        """
        Get information about this detector
        
        Returns:
            Dictionary with detector metadata
        """
        return {
            "name": "SecLookup",
            "description": "Domain security scanning service for malicious domain detection",
            "website": "https://seclookup.com",
            "api_endpoint": "https://api.seclookup.com/api/v1/scan/api",
            "requires_api_key": True,
            "request_method": "GET",
            "rate_limits": "API-dependent (check with SecLookup)",
            "input_type": "domains",
            "specializes_in": [
                "Malicious domain detection",
                "Domain reputation checking",
                "Threat intelligence integration"
            ],
            "response_format": {
                "is_malicious": "Boolean indicating if domain is malicious",
                "reference": "URL reference for additional information",
                "domain": "The domain that was checked"
            },
            "supported_protocols": ["HTTP", "HTTPS"],
            "threat_detection": [
                "Malware hosting domains",
                "Phishing domains",
                "Command and control servers",
                "Suspicious domains"
            ]
        }


# Example usage and testing
if __name__ == "__main__":
    # Load environment variables from .env file
    load_dotenv()
    
    # Get API key from environment
    api_key = os.getenv('SECLOOKUP_KEY')
    
    if not api_key:
        print("Error: SECLOOKUP_KEY not found in environment variables")
        print("Please create a .env file with your API key:")
        print("SECLOOKUP_KEY=your_actual_api_key_here")
        exit(1)
    
    try:
        # Initialize detector with environment API key
        detector = SecLookupDetector(api_key)
        
        # Test URLs/domains - mix of safe and potentially malicious
        test_urls = [
            # Safe domains
            "https://google.com/",
            "https://github.com/",
            "https://stackoverflow.com/",
            
            # Test with the example from the API documentation
            # Google's Official Test URLs for Safe Browsing API
            "http://malware.testing.google.test/testing/malware/",  # Test malware URL
            "http://phishing.testing.google.test/",  # Test phishing URL
            "http://testsafebrowsing.appspot.com/s/malware.html",  # Google's test malware page
            "http://testsafebrowsing.appspot.com/s/phishing.html",  # Google's test phishing page
            
            # Known malicious domains (for testing - DO NOT VISIT directly)
            "http://ianfette.org",  # Known test malware site
            "http://gumblar.cn",  # Known malware domain
            
            # Additional test URL
            "https://api.pump.fund/buy/",  # Test URL for API verification
            "https://docs.solanaapis.net"
        ]
        
        print("SecLookup Detector Test")
        print("=" * 50)
        print("Note: This test requires a valid SecLookup API key")
        print()
        
        # Test single URL
        result = detector.check_url("malicious.com")
        print(f"Single URL Test (malicious.com):")
        print(f"  Threat Level: {result.threat_level.value}")
        print(f"  Confidence: {result.confidence:.2f}")
        print(f"  Success: {result.success}")
        
        if result.success:
            print(f"  URLs Checked: {result.details['total_urls_checked']}")
            print(f"  Domains Checked: {result.details['total_domains_checked']}")
            print(f"  Malicious Found: {result.details['total_malicious']}")
            
            if result.details['malicious_domains']:
                print("  Malicious domains found:")
                for mal_domain in result.details['malicious_domains']:
                    print(f"    - Domain: {mal_domain['domain']}")
                    print(f"      Is Malicious: {mal_domain['is_malicious']}")
                    print(f"      Reference: {mal_domain['reference']}")
                    print(f"      API Message: {mal_domain['message']}")
                    print()
        else:
            print(f"  Error: {result.error_message}")
        print()
        
        # Test multiple URLs
        result = detector.check_urls(test_urls)
        print(f"Multiple URLs Test:")
        print(f"  Threat Level: {result.threat_level.value}")
        print(f"  Confidence: {result.confidence:.2f}")
        print(f"  Success: {result.success}")
        
        if result.success:
            print(f"  URLs Checked: {result.details['total_urls_checked']}")
            print(f"  Unique Domains: {result.details['total_domains_checked']}")
            print(f"  Malicious: {result.details['total_malicious']}")
            print(f"  Safe: {result.details['total_safe']}")
            print(f"  Errors: {result.details['total_errors']}")
            
            print(f"  Domains checked: {', '.join(result.details['unique_domains'])}")
            
            if result.details['malicious_domains']:
                print("  Detailed Malicious Domains:")
                for i, mal_domain in enumerate(result.details['malicious_domains'], 1):
                    print(f"    {i}. Domain: {mal_domain['domain']}")
                    print(f"       Is Malicious: {mal_domain['is_malicious']}")
                    print(f"       Reference: {mal_domain['reference']}")
                    print(f"       API Response: {mal_domain['full_api_response']}")
                    print()
            
            if result.details['errors']:
                print("  Errors encountered:")
                for error in result.details['errors']:
                    print(f"    - Domain: {error['domain']}")
                    print(f"      Error: {error['error']}")
                    print()
        else:
            print(f"  Error: {result.error_message}")
        
        print()
        print("Detector Info:")
        info = detector.get_detector_info()
        for key, value in info.items():
            if isinstance(value, list):
                print(f"  {key}:")
                for item in value:
                    print(f"    - {item}")
            elif isinstance(value, dict):
                print(f"  {key}:")
                for sub_key, sub_value in value.items():
                    print(f"    {sub_key}: {sub_value}")
            else:
                print(f"  {key}: {value}")
            
    except ValueError as e:
        print(f"Error: {e}")
        print("Please provide a valid SecLookup API key to test this detector.") 