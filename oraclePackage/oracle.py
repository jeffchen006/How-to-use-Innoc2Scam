import asyncio
import time
import os
from typing import List, Dict, Any, Set, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
import logging
from urllib.parse import urlparse

# add the current directory to the path
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the three detectors
from chainPortalDetector import ChainPortalDetector, ThreatLevel
from seclookupDetector import SecLookupDetector
from googleSafeBrowsingDetector import GoogleSafeBrowsingDetector


@dataclass
class OracleResult:
    """Result from the malicious URL oracle"""
    is_malicious: bool
    detectors_triggered: List[str]  # Which detectors flagged it as malicious
    malicious_reasons: Dict[str, List[str]]  # Specific reasons from each detector
    detector_details: Dict[str, Any]  # Full details from each detector
    confidence: float  # Overall confidence (max of triggered detectors)
    urls_checked: List[str]
    total_detectors_run: int
    execution_time: float


class MaliciousURLOracle:
    """
    High-performance malicious URL oracle that combines multiple detection services.
    
    Combines ChainPortal, SecLookup, and Google Safe Browsing APIs to detect
    malicious URLs. Uses async processing for optimal performance when checking
    large numbers of URLs.
    
    Returns True (malicious) if ANY detector flags a URL as malicious.
    """
    
    def __init__(self, 
                 google_api_key: Optional[str] = None,
                 seclookup_api_key: Optional[str] = None,
                 chainpatrol_api_key: Optional[str] = None,
                 enable_caching: bool = True,
                 max_workers: int = 10):
        """
        Initialize the malicious URL oracle
        
        Args:
            google_api_key: Google Safe Browsing API key (if None, loads from env)
            seclookup_api_key: SecLookup API key (if None, loads from env)  
            chainpatrol_api_key: ChainPatrol API key (optional, can run without)
            enable_caching: Whether to cache results to avoid duplicate checks
            max_workers: Maximum number of concurrent threads for detector calls
        """
        # Load environment variables
        load_dotenv()
        
        # Get API keys from environment if not provided
        self.google_api_key = google_api_key or os.getenv('GOOGLE_SAFEBROWSING_API_KEY')
        self.seclookup_api_key = seclookup_api_key or os.getenv('SECLOOKUP_KEY')
        self.chainpatrol_api_key = chainpatrol_api_key or os.getenv('CHAINPATROL_API_KEY')
        
        # Initialize detectors
        self.detectors = {}
        self.detector_names = []
        
        try:
            if self.google_api_key:
                self.detectors['GoogleSafeBrowsing'] = GoogleSafeBrowsingDetector(self.google_api_key)
                self.detector_names.append('GoogleSafeBrowsing')
            else:
                logging.warning("Google Safe Browsing API key not found - detector disabled")
        except Exception as e:
            logging.error(f"Failed to initialize Google Safe Browsing detector: {e}")
        
        try:
            if self.seclookup_api_key:
                self.detectors['SecLookup'] = SecLookupDetector(self.seclookup_api_key)
                self.detector_names.append('SecLookup')
            else:
                logging.warning("SecLookup API key not found - detector disabled")
        except Exception as e:
            logging.error(f"Failed to initialize SecLookup detector: {e}")
        
        try:
            # ChainPatrol works without API key
            self.detectors['ChainPortal'] = ChainPortalDetector(self.chainpatrol_api_key)
            self.detector_names.append('ChainPortal')
        except Exception as e:
            logging.error(f"Failed to initialize ChainPortal detector: {e}")
        
        if not self.detectors:
            raise ValueError("No detectors could be initialized - check API keys")
        
        # Performance optimizations
        self.enable_caching = enable_caching
        self.cache = {} if enable_caching else None
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        logging.info(f"Oracle initialized with {len(self.detectors)} detectors: {', '.join(self.detector_names)}")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent caching"""
        try:
            # Remove trailing slashes, convert to lowercase
            return url.rstrip('/').lower()
        except:
            return url.lower()
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for domain-based caching"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return url.lower()
    
    async def check_url(self, url: str) -> OracleResult:
        """
        Check a single URL against all available detectors
        
        Args:
            url: The URL to check
            
        Returns:
            OracleResult with aggregated detection results
        """
        result = await self.check_urls([url])
        return result[url]
    
    async def check_urls(self, urls: List[str], batch_size: int = 100) -> Dict[str, OracleResult]:
        """
        Check multiple URLs against all available detectors with batching
        
        Args:
            urls: List of URLs to check
            batch_size: Number of URLs to process in each batch
            
        Returns:
            Dictionary mapping each URL to its OracleResult
        """
        if not urls:
            return {}
        
        start_time = time.time()
        results = {}
        
        # Remove duplicates while preserving order
        unique_urls = list(dict.fromkeys(urls))
        
        # Check cache first if enabled
        urls_to_check = []
        if self.enable_caching and self.cache:
            for url in unique_urls:
                normalized_url = self._normalize_url(url)
                if normalized_url in self.cache:
                    results[url] = self.cache[normalized_url]
                else:
                    urls_to_check.append(url)
        else:
            urls_to_check = unique_urls
        
        if not urls_to_check:
            # All URLs were cached
            return results
        
        # Process URLs in batches for better performance
        for i in range(0, len(urls_to_check), batch_size):
            batch = urls_to_check[i:i + batch_size]
            batch_results = await self._process_batch(batch)
            results.update(batch_results)
            
            # Cache results if enabled
            if self.enable_caching and self.cache:
                for url, result in batch_results.items():
                    normalized_url = self._normalize_url(url)
                    self.cache[normalized_url] = result
        
        # Fill in results for any duplicate URLs in original list
        final_results = {}
        for url in urls:
            # Find the result for this URL (might be under normalized form)
            if url in results:
                final_results[url] = results[url]
            else:
                # Look for normalized version
                normalized_url = self._normalize_url(url)
                for check_url, result in results.items():
                    if self._normalize_url(check_url) == normalized_url:
                        final_results[url] = result
                        break
        
        total_time = time.time() - start_time
        logging.info(f"Checked {len(urls)} URLs in {total_time:.2f}s ({len(urls)/total_time:.1f} URLs/sec)")
        
        return final_results
    
    async def _process_batch(self, urls: List[str]) -> Dict[str, OracleResult]:
        """Process a batch of URLs through all detectors in parallel"""
        batch_start = time.time()
        
        # Run all detectors in parallel for this batch
        detector_tasks = []
        for detector_name, detector in self.detectors.items():
            task = asyncio.create_task(
                self._run_detector_async(detector_name, detector, urls)
            )
            detector_tasks.append(task)
        
        # Wait for all detectors to complete
        detector_results = await asyncio.gather(*detector_tasks, return_exceptions=True)
        
        # Aggregate results for each URL
        batch_results = {}
        for url in urls:
            detectors_triggered = []
            malicious_reasons = {}
            detector_details = {}
            max_confidence = 0.0
            
            for i, (detector_name, detector) in enumerate(self.detectors.items()):
                try:
                    detector_result = detector_results[i]
                    if isinstance(detector_result, Exception):
                        logging.error(f"{detector_name} failed for batch: {detector_result}")
                        detector_details[detector_name] = {
                            "error": str(detector_result),
                            "success": False
                        }
                        continue
                    
                    # Check if this URL was flagged as malicious by this detector
                    is_malicious_by_detector, reasons = self._is_url_malicious_in_result(url, detector_result)
                    
                    if is_malicious_by_detector:
                        detectors_triggered.append(detector_name)
                        malicious_reasons[detector_name] = reasons
                        max_confidence = max(max_confidence, detector_result.confidence)
                    
                    # Store detector details
                    detector_details[detector_name] = {
                        "threat_level": detector_result.threat_level.value,
                        "confidence": detector_result.confidence,
                        "success": detector_result.success,
                        "details": detector_result.details,
                        "is_malicious": is_malicious_by_detector,
                        "reasons": reasons
                    }
                    
                except Exception as e:
                    logging.error(f"Error processing {detector_name} result for {url}: {e}")
                    detector_details[detector_name] = {
                        "error": str(e),
                        "success": False
                    }
            
            # Create result for this URL
            batch_results[url] = OracleResult(
                is_malicious=len(detectors_triggered) > 0,
                detectors_triggered=detectors_triggered,
                malicious_reasons=malicious_reasons,
                detector_details=detector_details,
                confidence=max_confidence,
                urls_checked=[url],
                total_detectors_run=len(self.detectors),
                execution_time=time.time() - batch_start
            )
        
        return batch_results
    
    async def _run_detector_async(self, detector_name: str, detector, urls: List[str]):
        """Run a detector asynchronously using thread pool"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor,
            detector.check_urls,
            urls
        )
    
    def _is_url_malicious_in_result(self, url: str, detector_result) -> Tuple[bool, List[str]]:
        """Check if a specific URL is flagged as malicious and extract reasons"""
        try:
            reasons = []
            is_malicious = False
            
            # NOTE: Removed incorrect threat level check that was causing false positives
            # The threat_level is for the overall batch, not individual URLs
            # Individual URL maliciousness should only be determined by specific detection
            
            # Check specific URL in details for different detector types
            details = detector_result.details
            
            # Google Safe Browsing format
            if 'malicious_urls' in details:
                for mal_url_info in details['malicious_urls']:
                    if isinstance(mal_url_info, dict) and mal_url_info.get('url') == url:
                        is_malicious = True
                        threat_type = mal_url_info.get('threat_type', 'Unknown threat')
                        platform = mal_url_info.get('platform_type', 'Unknown platform')
                        reasons.append(f"Google Safe Browsing: {threat_type} on {platform}")
                        
                        # Add more specific details if available
                        if mal_url_info.get('threat_entry_type'):
                            reasons.append(f"Entry type: {mal_url_info.get('threat_entry_type')}")
            
            # SecLookup format
            if 'malicious_domains' in details:
                url_domain = self._extract_domain(url)
                for mal_domain_info in details['malicious_domains']:
                    if isinstance(mal_domain_info, dict):
                        if mal_domain_info.get('domain') == url_domain and mal_domain_info.get('is_malicious'):
                            is_malicious = True
                            reference = mal_domain_info.get('reference', 'No reference provided')
                            reasons.append(f"SecLookup: Domain flagged as malicious")
                            if reference and reference != 'No reference provided':
                                reasons.append(f"Reference: {reference}")
            
            # ChainPatrol format  
            if 'malicious_urls' in details:
                for mal_url_info in details['malicious_urls']:
                    if isinstance(mal_url_info, dict) and mal_url_info.get('url') == url:
                        is_malicious = True
                        blocked_sources = mal_url_info.get('blocked_sources', [])
                        detection_details = mal_url_info.get('detection_details', [])
                        
                        if blocked_sources:
                            reasons.append(f"ChainPatrol: Blocked by {len(blocked_sources)} sources: {', '.join(blocked_sources)}")
                        
                        # Add specific reasons from each source
                        for detail in detection_details:
                            if isinstance(detail, dict):
                                source = detail.get('source', 'Unknown')
                                reason = detail.get('reason', 'Listed as malicious')
                                category = detail.get('category', '')
                                reason_text = f"{source}: {reason}"
                                if category and category != 'Unknown':
                                    reason_text += f" (Category: {category})"
                                reasons.append(reason_text)
            
            return is_malicious, reasons
            
        except Exception as e:
            logging.error(f"Error checking if URL {url} is malicious: {e}")
            return False, [f"Error analyzing result: {str(e)}"]
    
    def get_oracle_info(self) -> Dict[str, Any]:
        """Get information about the oracle and its detectors"""
        detector_info = {}
        for name, detector in self.detectors.items():
            try:
                detector_info[name] = detector.get_detector_info()
            except Exception as e:
                detector_info[name] = {"error": str(e)}
        
        return {
            "oracle_name": "MaliciousURLOracle",
            "description": "Multi-detector malicious URL oracle for high-performance threat detection",
            "total_detectors": len(self.detectors),
            "active_detectors": self.detector_names,
            "caching_enabled": self.enable_caching,
            "max_workers": self.max_workers,
            "cache_size": len(self.cache) if self.cache else 0,
            "detection_logic": "URL flagged as malicious if ANY detector reports it as malicious",
            "supported_threat_levels": [level.value for level in ThreatLevel],
            "detector_details": detector_info,
            "performance_features": [
                "Async processing",
                "Parallel detector execution", 
                "Result caching",
                "Batch processing",
                "Thread pool optimization"
            ]
        }
    
    def clear_cache(self):
        """Clear the result cache"""
        if self.cache:
            self.cache.clear()
            logging.info("Oracle cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "cache_enabled": self.enable_caching,
            "cache_size": len(self.cache) if self.cache else 0,
            "cache_entries": list(self.cache.keys()) if self.cache else []
        }
    
    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)


# Example usage and testing
async def main():
    """Example usage of the MaliciousURLOracle"""
    
    # Initialize oracle (API keys loaded from environment)
    oracle = MaliciousURLOracle()
    
    # Test URLs - mix of safe and potentially malicious
    test_urls = [
        "https://google.com/",
        "https://github.com/",
        "https://api.pump.fund/buy/",
        "https://docs.solanaapis.net",
        "http://testsafebrowsing.appspot.com/s/malware.html",
        "http://testsafebrowsing.appspot.com/s/phishing.html",
    ]
    
    print("Malicious URL Oracle Test")
    print("=" * 50)
    
    # Single URL test
    print("\nSingle URL Test:")
    url = "https://api.pump.fund/buy/"
    url = "https://www.shein.com/fashion-trend-workshop"
    result = await oracle.check_url(url)
    print(f"URL: {url}")
    print(f"Is Malicious: {result.is_malicious}")
    print(f"Triggered Detectors: {result.detectors_triggered}")
    print(f"Confidence: {result.confidence:.2f}")
    print(f"Execution Time: {result.execution_time:.3f}s")
    
    if result.is_malicious and result.malicious_reasons:
        print("Malicious Reasons:")
        for detector, reasons in result.malicious_reasons.items():
            print(f"  {detector}:")
            for reason in reasons:
                print(f"    • {reason}")
    
    # Multiple URLs test
    print(f"\nBatch Test ({len(test_urls)} URLs):")
    start_time = time.time()
    results = await oracle.check_urls(test_urls)
    total_time = time.time() - start_time
    
    print(f"Total Time: {total_time:.3f}s ({len(test_urls)/total_time:.1f} URLs/sec)")
    print(f"Results:")
    
    for url, result in results.items():
        print(f"  📍 {url}")
        print(f"    🚨 Malicious: {result.is_malicious}")
        if result.detectors_triggered:
            print(f"    🔍 Triggered: {', '.join(result.detectors_triggered)}")
            print(f"    📊 Confidence: {result.confidence:.2f}")
            
            # Show detailed reasons
            if result.malicious_reasons:
                print(f"    ⚠️  Reasons:")
                for detector, reasons in result.malicious_reasons.items():
                    print(f"      🔹 {detector}:")
                    for reason in reasons:
                        print(f"         • {reason}")
        print()
    
    # Oracle info
    print("Oracle Information:")
    info = oracle.get_oracle_info()
    print(f"  Active Detectors: {', '.join(info['active_detectors'])}")
    print(f"  Cache Size: {info['cache_size']}")
    print(f"  Detection Logic: {info['detection_logic']}")


if __name__ == "__main__":
    asyncio.run(main())
