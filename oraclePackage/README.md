# Malicious URL Oracle

This package combines several external threat-intelligence feeds to decide whether a URL looks malicious. It bundles three detectors:

- `GoogleSafeBrowsingDetector` (requires at least one Google Safe Browsing API key)
- `SecLookupDetector` (requires a SecLookup API key)
- `ChainPortalDetector` (works anonymously, but accepts an optional ChainPatrol key)

The `MaliciousURLOracle` class lives in `oracle.py` and orchestrates the detectors asynchronously. It caches results, handles batching, and exposes helpers for single-URL and bulk checks.


## Environment Variables

Create a `.env` file in the project root (or export the variables) so the oracle can authenticate with each service:

```
# Google Safe Browsing (at least one key is required)
GOOGLE_SAFEBROWSING_API_KEY=your_primary_key
# Optional extras enable key rotation
GOOGLE_SAFEBROWSING_API_KEY2=optional_secondary_key
GOOGLE_SAFEBROWSING_API_KEY3=optional_third_key
GOOGLE_SAFEBROWSING_API_KEY4=optional_fourth_key

# SecLookup (required to enable the SecLookup detector)
SECLOOKUP_KEY=your_seclookup_api_key

# ChainPatrol / ChainPortal (optional, enables authenticated requests)
CHAINPATROL_API_KEY=optional_chainpatrol_key
```

Only the Google Safe Browsing and SecLookup keys are mandatory. The oracle disables any detector whose credentials are missing.

## Quick Start

From the repository root, run the built-in demo to confirm your keys are wired correctly:

```bash
python3 oraclePackage/oracle.py
```

You should see output similar to the following (timings may vary slightly):

```
Malicious URL Oracle Test
==================================================

Single URL Test:
URL: https://www.shein.com/fashion-trend-workshop
Is Malicious: False
Triggered Detectors: []
Confidence: 0.00
Execution Time: 0.552s

Batch Test (6 URLs):
Total Time: 2.275s (2.6 URLs/sec)
Results:
  📍 https://google.com/
    🚨 Malicious: False

  📍 https://github.com/
    🚨 Malicious: False

  📍 https://api.pump.fund/buy/
    🚨 Malicious: True
    🔍 Triggered: ChainPortal
    📊 Confidence: 0.85
    ⚠️  Reasons:
      🔹 ChainPortal:
         • Google Safe Browsing: Unknown threat on Unknown platform
         • ChainPatrol: Blocked by 1 sources: eth-phishing-detect
         • eth-phishing-detect: Listed as malicious

  📍 https://docs.solanaapis.net
    🚨 Malicious: True
    🔍 Triggered: SecLookup, ChainPortal
    📊 Confidence: 0.90
    ⚠️  Reasons:
      🔹 SecLookup:
         • SecLookup: Domain flagged as malicious
         • Reference: https://www.virustotal.com/gui/url/aHR0cHM6Ly9kb2NzLnNvbGFuYWFwaXMubmV0
      🔹 ChainPortal:
         • Google Safe Browsing: Unknown threat on Unknown platform
         • ChainPatrol: Blocked by 1 sources: eth-phishing-detect
         • eth-phishing-detect: Listed as malicious

  📍 http://testsafebrowsing.appspot.com/s/malware.html
    🚨 Malicious: False

  📍 http://testsafebrowsing.appspot.com/s/phishing.html
    🚨 Malicious: False

Oracle Information:
  Active Detectors: GoogleSafeBrowsing, SecLookup, ChainPortal
  Cache Size: 0
  Detection Logic: URL flagged as malicious if ANY detector reports it as malicious
```
