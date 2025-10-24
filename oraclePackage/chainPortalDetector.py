import requests
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


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


class ChainPortalDetector:
    """
    ChainPortal detector for Web3 scams and malicious URLs
    
    ChainPortal provides 24/7 monitoring for Web3 scams across social platforms
    and maintains a blocklist that warns users about scam URLs and wallet addresses.
    
    API works with or without authentication - anonymous requests are supported.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize ChainPortal detector
        
        Args:
            api_key: Optional ChainPortal API key. If not provided, uses anonymous requests.
        """
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ChainPortalDetector/1.0'
        })
        self.base_url = "https://app.chainpatrol.io/api/v2"
    
    def check_url(self, url: str) -> DetectionResult:
        """
        Check a single URL against ChainPatrol's database
        
        Args:
            url: The URL to check
            
        Returns:
            DetectionResult with threat assessment
        """
        return self.check_urls([url])
    
    def check_urls(self, urls: List[str]) -> DetectionResult:
        """
        Check multiple URLs against ChainPatrol's database
        
        Args:
            urls: List of URLs to check
            
        Returns:
            DetectionResult with threat assessment for all URLs
        """
        if not urls:
            return DetectionResult(
                detector_name="ChainPortal",
                threat_level=ThreatLevel.SAFE,
                confidence=0.0,
                details={"error": "No URLs provided"},
                urls_checked=[],
                success=False,
                error_message="No URLs provided"
            )
        
        malicious_urls = []
        checked_urls = []
        errors = []
        
        for url in urls:
            try:
                # Prepare headers - API key is optional
                headers = {"Content-Type": "application/json"}
                if self.api_key:
                    headers["X-API-KEY"] = self.api_key
                
                # Prepare JSON payload
                payload = {"content": url}
                
                # Make API request (POST with JSON body)
                response = self.session.post(
                    f"{self.base_url}/asset/check",
                    headers=headers,
                    json=payload,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Check individual sources for blocked status
                    sources = data.get('sources', [])
                    blocked_sources = []
                    
                    for source in sources:
                        if source.get('status') == 'BLOCKED':
                            blocked_sources.append({
                                'source': source.get('source', 'Unknown'),
                                'status': source.get('status'),
                                'reason': source.get('reason', 'Listed as malicious'),
                                'category': source.get('category', 'Unknown')
                            })
                    
                    # If any source reports BLOCKED, consider URL malicious
                    if blocked_sources:
                        malicious_urls.append({
                            "url": url,
                            "overall_status": data.get('status', 'Unknown'),
                            "blocked_by": blocked_sources,
                            "blocked_sources": [src['source'] for src in blocked_sources],
                            "total_sources_checked": len(sources),
                            "detection_details": blocked_sources
                        })
                    
                    checked_urls.append(url)
                    
                elif response.status_code == 429:
                    # Rate limited - wait and retry once
                    time.sleep(1)
                    response = self.session.post(
                        f"{self.base_url}/asset/check",
                        headers=headers,
                        json=payload,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Check individual sources for blocked status (retry case)
                        sources = data.get('sources', [])
                        blocked_sources = []
                        
                        for source in sources:
                            if source.get('status') == 'BLOCKED':
                                blocked_sources.append({
                                    'source': source.get('source', 'Unknown'),
                                    'status': source.get('status'),
                                    'reason': source.get('reason', 'Listed as malicious'),
                                    'category': source.get('category', 'Unknown')
                                })
                        
                        if blocked_sources:
                            malicious_urls.append({
                                "url": url,
                                "overall_status": data.get('status', 'Unknown'),
                                "blocked_by": blocked_sources,
                                "blocked_sources": [src['source'] for src in blocked_sources],
                                "total_sources_checked": len(sources),
                                "detection_details": blocked_sources
                            })
                        
                        checked_urls.append(url)
                    else:
                        errors.append(f"Rate limited for {url}")
                        
                else:
                    errors.append(f"HTTP {response.status_code} for {url}")
                
                # Rate limiting to be respectful
                time.sleep(0.1)
                
            except requests.exceptions.Timeout:
                errors.append(f"Timeout for {url}")
            except requests.exceptions.RequestException as e:
                errors.append(f"Request error for {url}: {str(e)}")
            except Exception as e:
                errors.append(f"Unexpected error for {url}: {str(e)}")
        
        # Determine threat level based on findings
        if malicious_urls:
            threat_level = ThreatLevel.HIGH
            confidence = 0.85
        elif checked_urls:
            threat_level = ThreatLevel.SAFE
            confidence = 0.75
        else:
            threat_level = ThreatLevel.SAFE
            confidence = 0.0
        
        # Prepare detailed results
        details = {
            "malicious_urls": malicious_urls,
            "total_checked": len(checked_urls),
            "total_malicious": len(malicious_urls),
            "errors": errors,
            "api_key_used": bool(self.api_key)
        }
        
        success = len(checked_urls) > 0 or len(errors) == 0
        error_message = None if success else f"Failed to check URLs: {'; '.join(errors)}"
        
        return DetectionResult(
            detector_name="ChainPortal",
            threat_level=threat_level,
            confidence=confidence,
            details=details,
            urls_checked=checked_urls,
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
            "name": "ChainPortal",
            "description": "Web3 scam detection and brand protection platform",
            "website": "https://chainpatrol.io",
            "api_docs": "https://chainpatrol.io/docs/introduction",
            "api_endpoint": "https://app.chainpatrol.io/api/v2/asset/check",
            "requires_api_key": False,
            "supports_anonymous": True,
            "request_method": "POST",
            "auth_header": "X-API-KEY",
            "rate_limits": "Moderate - ~10 requests per second",
            "aggregates_sources": True,
            "known_sources": [
                "chainpatrol",
                "eth-phishing-detect", 
                "phishfort"
            ],
            "detection_logic": "URL flagged as malicious if ANY source reports BLOCKED status",
            "specializes_in": [
                "Web3 scams",
                "Cryptocurrency phishing",
                "NFT scams", 
                "DeFi protocol impersonation",
                "Wallet address verification"
            ]
        }


# Example usage and testing
if __name__ == "__main__":
    # Test with anonymous access (no API key)
    detector = ChainPortalDetector()
    
    # Test URLs
    test_urls = [
        # safe urls
        "https://google.com",  # Should be safe
        "https://chainpatrol.io",  # Should be safe
        # malicious urls
        "https://api.pump.fund/buy"  # Test URL for API verification
    ]
    
    print("ChainPortal Detector Test")
    print("=" * 50)
    
    # Test single URL
    result = detector.check_url("https://api.pump.fund/buy")
    print(f"Single URL Test:")
    print(f"  Threat Level: {result.threat_level.value}")
    print(f"  Confidence: {result.confidence:.2f}")
    print(f"  Success: {result.success}")
    print(f"  Details: {result.details}")
    print()
    
    # Test multiple URLs
    result = detector.check_urls(test_urls)
    print(f"Multiple URLs Test:")
    print(f"  Threat Level: {result.threat_level.value}")
    print(f"  Confidence: {result.confidence:.2f}")
    print(f"  URLs Checked: {len(result.urls_checked)}")
    print(f"  Malicious Found: {result.details['total_malicious']}")
    print(f"  Success: {result.success}")
    
    if result.details['malicious_urls']:
        print("  Malicious URLs found:")
        for mal_url in result.details['malicious_urls']:
            print(f"    - {mal_url['url']}")
            print(f"      Overall Status: {mal_url['overall_status']}")
            print(f"      Blocked by: {', '.join(mal_url['blocked_sources'])}")
            print(f"      Sources checked: {mal_url['total_sources_checked']}")
            for detail in mal_url['detection_details']:
                print(f"        • {detail['source']}: {detail['reason']}")
    
    print()
    print("Detector Info:")
    info = detector.get_detector_info()
    for key, value in info.items():
        print(f"  {key}: {value}") 