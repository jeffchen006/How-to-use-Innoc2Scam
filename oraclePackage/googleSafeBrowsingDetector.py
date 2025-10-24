import requests
import time
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
from dotenv import load_dotenv
import itertools


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


class GoogleSafeBrowsingDetector:
    """
    Google Safe Browsing detector for malicious URLs with API key rotation support
    
    Google Safe Browsing protects over 4 billion devices every day by showing 
    warnings to users when they attempt to navigate to dangerous sites or 
    download dangerous files.
    
    Supports multiple API keys for rotation to avoid rate limits and improve reliability.
    """
    
    def __init__(self, api_keys: Optional[List[str]] = None):
        """
        Initialize Google Safe Browsing detector with API key rotation
        
        Args:
            api_keys: List of API keys to use in rotation. If None, will load from environment.
        """
        # Load API keys from environment if not provided
        if api_keys is None:
            api_keys = self._load_api_keys_from_env()
        
        if not api_keys:
            raise ValueError("At least one Google Safe Browsing API key is required")
            
        # Filter out empty/None keys
        self.api_keys = [key for key in api_keys if key and key.strip()]
        
        if not self.api_keys:
            raise ValueError("No valid Google Safe Browsing API keys found")
            
        # Create a cycle iterator for API key rotation
        self.api_key_cycle = itertools.cycle(self.api_keys)
        self.current_api_key = next(self.api_key_cycle)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GoogleSafeBrowsingDetector/1.0',
            'Content-Type': 'application/json'
        })
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        
        # Threat types to check for (from official documentation)
        self.threat_types = [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
        ]
        
        # Platform types (from official documentation)  
        self.platform_types = ["ANY_PLATFORM"]
    
    def _load_api_keys_from_env(self) -> List[str]:
        """
        Load API keys from environment variables
        
        Returns:
            List of API keys found in environment
        """
        load_dotenv()
        
        api_keys = []
        key_names = [
            'GOOGLE_SAFEBROWSING_API_KEY',
            'GOOGLE_SAFEBROWSING_API_KEY2', 
            'GOOGLE_SAFEBROWSING_API_KEY3',
            'GOOGLE_SAFEBROWSING_API_KEY4'
        ]
        
        for key_name in key_names:
            key = os.getenv(key_name)
            if key and key.strip():
                api_keys.append(key.strip())
        
        return api_keys
    
    def _get_next_api_key(self) -> str:
        """
        Get the next API key in rotation
        
        Returns:
            Next API key to use
        """
        self.current_api_key = next(self.api_key_cycle)
        return self.current_api_key
    
    def _make_api_request(self, payload: Dict[str, Any], max_retries: int = None) -> requests.Response:
        """
        Make API request with key rotation and retry logic
        
        Args:
            payload: Request payload
            max_retries: Maximum number of keys to try (defaults to number of available keys)
            
        Returns:
            Response object
            
        Raises:
            Exception: If all API keys fail
        """
        if max_retries is None:
            max_retries = len(self.api_keys)
        
        last_exception = None
        
        for attempt in range(max_retries):
            api_key = self._get_next_api_key()
            
            try:
                response = self.session.post(
                    f"{self.base_url}?key={api_key}",
                    json=payload,
                    timeout=30
                )
                
                # If successful or client error (not server/rate limit), return immediately
                if response.status_code == 200 or 400 <= response.status_code < 500:
                    return response
                    
                # For server errors or rate limits, try next key
                if response.status_code >= 500 or response.status_code == 429:
                    last_exception = Exception(f"API key {attempt + 1} failed with status {response.status_code}")
                    continue
                    
            except requests.exceptions.RequestException as e:
                last_exception = e
                continue
        
        # If we get here, all keys failed
        if last_exception:
            raise last_exception
        else:
            raise Exception("All API keys failed")

    def check_url(self, url: str) -> DetectionResult:
        """
        Check a single URL against Google Safe Browsing
        
        Args:
            url: The URL to check
            
        Returns:
            DetectionResult with threat assessment
        """
        return self.check_urls([url])
    
    def check_urls(self, urls: List[str], max_urls: int = 500) -> DetectionResult:
        """
        Check multiple URLs against Google Safe Browsing
        
        Args:
            urls: List of URLs to check
            max_urls: Maximum number of URLs per request (API limit is 500)
            
        Returns:
            DetectionResult with threat assessment for all URLs
        """
        if not urls:
            return DetectionResult(
                detector_name="Google Safe Browsing",
                threat_level=ThreatLevel.SAFE,
                confidence=0.0,
                details={"error": "No URLs provided"},
                urls_checked=[],
                success=False,
                error_message="No URLs provided"
            )
        
        # Limit URLs to API maximum
        urls_to_check = urls[:max_urls]
        
        try:
            # Prepare API request payload (following official documentation format)
            payload = {
                "client": {
                    "clientId": "malware-oracle-detector",
                    "clientVersion": "1.5.2"
                },
                "threatInfo": {
                    "threatTypes": self.threat_types,
                    "platformTypes": self.platform_types,
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url} for url in urls_to_check]
                }
            }
            
            # Make API request with rotation
            response = self._make_api_request(payload)
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                
                # Process threat matches using actual API response data
                malicious_urls = []
                threat_summary = {}
                
                for match in matches:
                    # Extract all available data from the API response
                    threat_type = match.get('threatType', 'Unknown')
                    platform_type = match.get('platformType', 'Unknown')
                    threat_entry = match.get('threat', {})
                    url = threat_entry.get('url', 'Unknown')
                    threat_entry_type = match.get('threatEntryType', 'Unknown')
                    cache_duration = match.get('cacheDuration', 'Unknown')
                    
                    # Include all data Google provides
                    malicious_url_info = {
                        "url": url,
                        "threat_type": threat_type,
                        "threat_entry_type": threat_entry_type,
                        "platform_type": platform_type,
                        "cache_duration": cache_duration,
                        "full_api_response": match  # Include complete API response for transparency
                    }
                    
                    malicious_urls.append(malicious_url_info)
                    
                    # Count threat types
                    if threat_type in threat_summary:
                        threat_summary[threat_type] += 1
                    else:
                        threat_summary[threat_type] = 1
                
                # Determine threat level based on findings
                if malicious_urls:
                    # High severity threats
                    if any(match['threat_type'] in ['MALWARE', 'POTENTIALLY_HARMFUL_APPLICATION'] 
                           for match in malicious_urls):
                        threat_level = ThreatLevel.CRITICAL
                        confidence = 0.95
                    # Medium severity threats  
                    elif any(match['threat_type'] == 'SOCIAL_ENGINEERING' 
                            for match in malicious_urls):
                        threat_level = ThreatLevel.HIGH
                        confidence = 0.9
                    # Lower severity threats
                    else:
                        threat_level = ThreatLevel.MEDIUM
                        confidence = 0.8
                else:
                    threat_level = ThreatLevel.SAFE
                    confidence = 0.85
                
                # Prepare detailed results
                details = {
                    "malicious_urls": malicious_urls,
                    "total_checked": len(urls_to_check),
                    "total_malicious": len(malicious_urls),
                    "threat_summary": threat_summary,
                    "threat_types_checked": self.threat_types,
                    "api_response_size": len(str(data)),
                    "api_keys_available": len(self.api_keys),
                    "current_api_key_index": self.api_keys.index(self.current_api_key) + 1
                }
                
                success = True
                error_message = None
                
            elif response.status_code == 400:
                error_text = response.text
                try:
                    error_data = response.json()
                    error_detail = error_data.get('error', {}).get('message', error_text)
                except:
                    error_detail = error_text
                    
                return DetectionResult(
                    detector_name="Google Safe Browsing",
                    threat_level=ThreatLevel.SAFE,
                    confidence=0.0,
                    details={
                        "error": "Bad request - check API key and request format",
                        "status_code": 400,
                        "error_detail": error_detail,
                        "api_keys_available": len(self.api_keys),
                        "current_api_key_index": self.api_keys.index(self.current_api_key) + 1,
                        "current_api_key_length": len(self.current_api_key) if self.current_api_key else 0
                    },
                    urls_checked=[],
                    success=False,
                    error_message=f"Bad request to Google Safe Browsing API: {error_detail}"
                )
            elif response.status_code == 429:
                return DetectionResult(
                    detector_name="Google Safe Browsing",
                    threat_level=ThreatLevel.SAFE,
                    confidence=0.0,
                    details={
                        "error": "Rate limited by Google Safe Browsing API", 
                        "api_keys_available": len(self.api_keys),
                        "note": "All available API keys have been rate limited"
                    },
                    urls_checked=[],
                    success=False,
                    error_message="Rate limited by API"
                )
            else:
                return DetectionResult(
                    detector_name="Google Safe Browsing",
                    threat_level=ThreatLevel.SAFE,
                    confidence=0.0,
                    details={
                        "error": f"HTTP {response.status_code}: {response.text}",
                        "api_keys_available": len(self.api_keys)
                    },
                    urls_checked=[],
                    success=False,
                    error_message=f"API returned HTTP {response.status_code}"
                )
        
        except requests.exceptions.Timeout:
            return DetectionResult(
                detector_name="Google Safe Browsing",
                threat_level=ThreatLevel.SAFE,
                confidence=0.0,
                details={
                    "error": "Request timeout",
                    "api_keys_available": len(self.api_keys)
                },
                urls_checked=[],
                success=False,
                error_message="Request timeout"
            )
        except requests.exceptions.RequestException as e:
            return DetectionResult(
                detector_name="Google Safe Browsing",
                threat_level=ThreatLevel.SAFE,
                confidence=0.0,
                details={
                    "error": f"Request error: {str(e)}",
                    "api_keys_available": len(self.api_keys)
                },
                urls_checked=[],
                success=False,
                error_message=f"Request error: {str(e)}"
            )
        except Exception as e:
            return DetectionResult(
                detector_name="Google Safe Browsing",
                threat_level=ThreatLevel.SAFE,
                confidence=0.0,
                details={
                    "error": f"Unexpected error: {str(e)}",
                    "api_keys_available": len(self.api_keys)
                },
                urls_checked=[],
                success=False,
                error_message=f"Unexpected error: {str(e)}"
            )
        
        return DetectionResult(
            detector_name="Google Safe Browsing",
            threat_level=threat_level,
            confidence=confidence,
            details=details,
            urls_checked=urls_to_check,
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
            "name": "Google Safe Browsing",
            "description": "Google's database of unsafe web resources protecting 4+ billion devices",
            "website": "https://safebrowsing.google.com",
            "api_docs": "https://developers.google.com/safe-browsing/v4",
            "api_endpoint": "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            "requires_api_key": True,
            "api_key_url": "https://console.cloud.google.com/",
            "request_method": "POST",
            "rate_limits": "10,000 requests per day (default quota)",
            "max_urls_per_request": 500,
            "threat_types": self.threat_types,
            "platform_types": ["ANY_PLATFORM"],
            "api_keys_configured": len(self.api_keys),
            "api_key_rotation": "Enabled" if len(self.api_keys) > 1 else "Disabled",
            "specializes_in": [
                "Malware hosting sites",
                "Phishing websites", 
                "Social engineering attacks",
                "Unwanted software distribution",
                "Potentially harmful applications"
            ],
            "threat_categories": {
                "MALWARE": "Sites that host malware or infected downloads",
                "SOCIAL_ENGINEERING": "Phishing and deceptive sites",
                "UNWANTED_SOFTWARE": "Sites distributing unwanted software",
                "POTENTIALLY_HARMFUL_APPLICATION": "Mobile apps that may be harmful"
            }
        }


# Example usage and testing
if __name__ == "__main__":
    try:
        # Initialize detector (will automatically load API keys from environment)
        detector = GoogleSafeBrowsingDetector()
        
        print(f"Google Safe Browsing Detector with API Key Rotation")
        print(f"API Keys configured: {len(detector.api_keys)}")
        print("=" * 60)
        
        # Test URLs - mix of safe and malicious for comprehensive testing
        test_urls = [
            # Safe URLs
            "https://google.com/",  # Should be safe
            "https://chainpatrol.io/",  # Should be safe
            "https://github.com/",  # Should be safe
            
            # Google's Official Test URLs for Safe Browsing API
            "http://malware.testing.google.test/testing/malware/",  # Test malware URL
            "http://phishing.testing.google.test/",  # Test phishing URL
            "http://testsafebrowsing.appspot.com/s/malware.html",  # Google's test malware page
            "http://testsafebrowsing.appspot.com/s/phishing.html",  # Google's test phishing page
            
            # Known malicious domains (for testing - DO NOT VISIT directly)
            "http://ianfette.org",  # Known test malware site
            "http://gumblar.cn",  # Known malware domain
            
            # Additional test URL
            "https://api.pump.fund/buy/"  # Test URL for API verification
        ]
        
        print("Note: This test requires valid Google Safe Browsing API keys in .env file")
        print()
        
        # Test single URL with known malicious site
        result = detector.check_url("http://testsafebrowsing.appspot.com/s/malware.html")
        print(f"Single URL Test:")
        print(f"  Threat Level: {result.threat_level.value}")
        print(f"  Confidence: {result.confidence:.2f}")
        print(f"  Success: {result.success}")
        
        if result.success:
            print(f"  URLs Checked: {result.details['total_checked']}")
            print(f"  Malicious Found: {result.details['total_malicious']}")
            print(f"  API Key Used: {result.details['current_api_key_index']}/{result.details['api_keys_available']}")
            
            if result.details['malicious_urls']:
                print("  Malicious URLs found:")
                for mal_url in result.details['malicious_urls']:
                    print(f"    - URL: {mal_url['url']}")
                    print(f"      Threat Type: {mal_url['threat_type']}")
                    print(f"      Threat Entry Type: {mal_url['threat_entry_type']}")
                    print(f"      Platform: {mal_url['platform_type']}")
                    print(f"      Cache Duration: {mal_url['cache_duration']}")
                    print()
        else:
            print(f"  Error: {result.error_message}")
        print()
        
        # Test multiple URLs to demonstrate key rotation
        result = detector.check_urls(test_urls)
        print(f"Multiple URLs Test:")
        print(f"  Threat Level: {result.threat_level.value}")
        print(f"  Confidence: {result.confidence:.2f}")
        print(f"  Success: {result.success}")
        
        if result.success:
            print(f"  URLs Checked: {result.details['total_checked']}")
            print(f"  Malicious Found: {result.details['total_malicious']}")
            print(f"  API Key Used: {result.details['current_api_key_index']}/{result.details['api_keys_available']}")
            
            if result.details['threat_summary']:
                print("  Threat Summary:")
                for threat_type, count in result.details['threat_summary'].items():
                    print(f"    {threat_type}: {count}")
            
            if result.details['malicious_urls']:
                print("  Detailed Malicious URLs:")
                for i, mal_url in enumerate(result.details['malicious_urls'], 1):
                    print(f"    {i}. URL: {mal_url['url']}")
                    print(f"       Threat Type: {mal_url['threat_type']}")
                    print(f"       Threat Entry Type: {mal_url['threat_entry_type']}")
                    print(f"       Platform: {mal_url['platform_type']}")
                    print(f"       Cache Duration: {mal_url['cache_duration']}")
                    print()
        else:
            print(f"  Error: {result.error_message}")
        
        print()
        print("Detector Info:")
        info = detector.get_detector_info()
        for key, value in info.items():
            if key not in ['threat_categories', 'threat_types']:
                print(f"  {key}: {value}")
            
    except ValueError as e:
        print(f"Error: {e}")
        print("Please ensure you have valid Google Safe Browsing API keys in your .env file:")
        print("GOOGLE_SAFEBROWSING_API_KEY=your_first_api_key")
        print("GOOGLE_SAFEBROWSING_API_KEY2=your_second_api_key")
        print("GOOGLE_SAFEBROWSING_API_KEY3=your_third_api_key")
        print("GOOGLE_SAFEBROWSING_API_KEY4=your_fourth_api_key") 