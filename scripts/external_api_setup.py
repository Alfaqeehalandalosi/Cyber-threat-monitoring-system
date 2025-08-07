#!/usr/bin/env python3
# =============================================================================
# EXTERNAL API SETUP SCRIPT
# =============================================================================
"""
External API configuration for the Cyber Threat Monitoring System.
This script helps configure external threat intelligence APIs and services.
"""

import os
import sys
import requests
import json
from pathlib import Path
from typing import Dict, List, Optional

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctms.core.config import settings
from ctms.core.logger import configure_logging, get_logger

logger = get_logger(__name__)


class ExternalAPIManager:
    """Manages external API configurations and testing."""
    
    def __init__(self):
        self.env_file = Path(".env")
        self.api_configs = {
            "virustotal": {
                "name": "VirusTotal",
                "url": "https://www.virustotal.com/gui/join-us",
                "api_url": "https://www.virustotal.com/vtapi/v2",
                "free_tier": True,
                "rate_limit": "4 requests/minute (free)",
                "description": "Malware analysis and file reputation"
            },
            "shodan": {
                "name": "Shodan",
                "url": "https://account.shodan.io/register",
                "api_url": "https://api.shodan.io",
                "free_tier": True,
                "rate_limit": "1 request/second (free)",
                "description": "Internet-wide vulnerability scanning"
            },
            "abuseipdb": {
                "name": "AbuseIPDB",
                "url": "https://www.abuseipdb.com/api",
                "api_url": "https://api.abuseipdb.com/api/v2",
                "free_tier": True,
                "rate_limit": "1000 requests/day (free)",
                "description": "IP reputation and blacklist checking"
            },
            "threatcrowd": {
                "name": "ThreatCrowd",
                "url": "https://www.threatcrowd.org/",
                "api_url": "https://www.threatcrowd.org/searchApi/v2",
                "free_tier": True,
                "rate_limit": "Unlimited (public API)",
                "description": "Threat intelligence and malware search"
            },
            "urlhaus": {
                "name": "URLhaus",
                "url": "https://urlhaus.abuse.ch/api/",
                "api_url": "https://urlhaus.abuse.ch/api/v1",
                "free_tier": True,
                "rate_limit": "Unlimited (public API)",
                "description": "Malicious URL database"
            },
            "malwarebazaar": {
                "name": "MalwareBazaar",
                "url": "https://bazaar.abuse.ch/api/",
                "api_url": "https://mb-api.abuse.ch/api/v1",
                "free_tier": True,
                "rate_limit": "Unlimited (public API)",
                "description": "Malware sample database"
            }
        }
    
    def read_env_file(self) -> Dict[str, str]:
        """Read the current .env file."""
        env_vars = {}
        if self.env_file.exists():
            with open(self.env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        env_vars[key.strip()] = value.strip()
        return env_vars
    
    def update_env_file(self, updates: Dict[str, str]) -> bool:
        """Update the .env file with new API keys."""
        try:
            # Read current content
            lines = []
            if self.env_file.exists():
                with open(self.env_file, 'r') as f:
                    lines = f.readlines()
            
            # Update values
            updated_lines = []
            updated_keys = set()
            
            for line in lines:
                if line.strip() and not line.strip().startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    if key in updates:
                        updated_lines.append(f"{key}={updates[key]}\n")
                        updated_keys.add(key)
                    else:
                        updated_lines.append(line)
                else:
                    updated_lines.append(line)
            
            # Add any new keys that weren't in the file
            for key, value in updates.items():
                if key not in updated_keys:
                    updated_lines.append(f"{key}={value}\n")
            
            # Write back to file
            with open(self.env_file, 'w') as f:
                f.writelines(updated_lines)
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to update .env file: {e}")
            return False
    
    def test_virustotal_api(self, api_key: str) -> Dict[str, any]:
        """Test VirusTotal API connection."""
        try:
            logger.info("🔍 Testing VirusTotal API...")
            
            # Test with a known safe domain
            test_domain = "google.com"
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                "apikey": api_key,
                "domain": test_domain
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                logger.info("✅ VirusTotal API connection successful")
                return {
                    "status": "success",
                    "response_code": response.status_code,
                    "domain": test_domain,
                    "positives": data.get("positives", 0),
                    "total": data.get("total", 0)
                }
            else:
                logger.error(f"❌ VirusTotal API failed: {response.status_code}")
                return {
                    "status": "error",
                    "response_code": response.status_code,
                    "error": response.text
                }
                
        except Exception as e:
            logger.error(f"❌ VirusTotal API test error: {e}")
            return {"status": "error", "error": str(e)}
    
    def test_shodan_api(self, api_key: str) -> Dict[str, any]:
        """Test Shodan API connection."""
        try:
            logger.info("🔍 Testing Shodan API...")
            
            # Test with a simple query
            url = "https://api.shodan.io/api-info"
            params = {"key": api_key}
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                logger.info("✅ Shodan API connection successful")
                return {
                    "status": "success",
                    "response_code": response.status_code,
                    "plan": data.get("plan", "unknown"),
                    "credits": data.get("credits", 0)
                }
            else:
                logger.error(f"❌ Shodan API failed: {response.status_code}")
                return {
                    "status": "error",
                    "response_code": response.status_code,
                    "error": response.text
                }
                
        except Exception as e:
            logger.error(f"❌ Shodan API test error: {e}")
            return {"status": "error", "error": str(e)}
    
    def test_abuseipdb_api(self, api_key: str) -> Dict[str, any]:
        """Test AbuseIPDB API connection."""
        try:
            logger.info("🔍 Testing AbuseIPDB API...")
            
            # Test with a known safe IP
            test_ip = "8.8.8.8"
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": test_ip,
                "maxAgeInDays": "90"
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                logger.info("✅ AbuseIPDB API connection successful")
                return {
                    "status": "success",
                    "response_code": response.status_code,
                    "ip": test_ip,
                    "abuse_confidence": data.get("data", {}).get("abuseConfidenceScore", 0)
                }
            else:
                logger.error(f"❌ AbuseIPDB API failed: {response.status_code}")
                return {
                    "status": "error",
                    "response_code": response.status_code,
                    "error": response.text
                }
                
        except Exception as e:
            logger.error(f"❌ AbuseIPDB API test error: {e}")
            return {"status": "error", "error": str(e)}
    
    def test_public_apis(self) -> Dict[str, any]:
        """Test public APIs that don't require keys."""
        results = {}
        
        # Test ThreatCrowd
        try:
            logger.info("🔍 Testing ThreatCrowd API...")
            url = "https://www.threatcrowd.org/searchApi/v2/domain/report/"
            params = {"domain": "google.com"}
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                logger.info("✅ ThreatCrowd API working")
                results["threatcrowd"] = {
                    "status": "success",
                    "response_code": response.status_code
                }
            else:
                logger.warning(f"⚠️ ThreatCrowd API failed: {response.status_code}")
                results["threatcrowd"] = {
                    "status": "error",
                    "response_code": response.status_code
                }
        except Exception as e:
            logger.warning(f"⚠️ ThreatCrowd API error: {e}")
            results["threatcrowd"] = {"status": "error", "error": str(e)}
        
        # Test URLhaus
        try:
            logger.info("🔍 Testing URLhaus API...")
            url = "https://urlhaus.abuse.ch/api/v1/payload/"
            data = {
                "query": "get_recent",
                "selector": "time"
            }
            
            response = requests.post(url, data=data, timeout=10)
            
            if response.status_code == 200:
                logger.info("✅ URLhaus API working")
                results["urlhaus"] = {
                    "status": "success",
                    "response_code": response.status_code
                }
            else:
                logger.warning(f"⚠️ URLhaus API failed: {response.status_code}")
                results["urlhaus"] = {
                    "status": "error",
                    "response_code": response.status_code
                }
        except Exception as e:
            logger.warning(f"⚠️ URLhaus API error: {e}")
            results["urlhaus"] = {"status": "error", "error": str(e)}
        
        return results
    
    def display_api_instructions(self):
        """Display instructions for setting up external APIs."""
        logger.info("\n🌐 External API Setup Instructions")
        logger.info("=" * 50)
        
        for api_id, config in self.api_configs.items():
            logger.info(f"\n🔑 {config['name']}:")
            logger.info(f"   Description: {config['description']}")
            logger.info(f"   Sign up: {config['url']}")
            logger.info(f"   API URL: {config['api_url']}")
            logger.info(f"   Free tier: {'Yes' if config['free_tier'] else 'No'}")
            logger.info(f"   Rate limit: {config['rate_limit']}")
            
            if api_id in ["virustotal", "shodan", "abuseipdb"]:
                logger.info(f"   Environment variable: {api_id.upper()}_API_KEY")
    
    def interactive_setup(self):
        """Interactive API key setup."""
        logger.info("\n🔧 Interactive API Setup")
        logger.info("=" * 30)
        
        env_vars = self.read_env_file()
        updates = {}
        
        # VirusTotal
        if not env_vars.get("VIRUSTOTAL_API_KEY"):
            logger.info("\n🔑 VirusTotal API Key:")
            logger.info("   Get your free API key from: https://www.virustotal.com/gui/join-us")
            api_key = input("   Enter your VirusTotal API key (or press Enter to skip): ").strip()
            if api_key:
                updates["VIRUSTOTAL_API_KEY"] = api_key
                # Test the API key
                test_result = self.test_virustotal_api(api_key)
                if test_result["status"] == "success":
                    logger.info("✅ VirusTotal API key is valid")
                else:
                    logger.warning("⚠️ VirusTotal API key test failed")
        
        # Shodan
        if not env_vars.get("SHODAN_API_KEY"):
            logger.info("\n🔑 Shodan API Key:")
            logger.info("   Get your API key from: https://account.shodan.io/register")
            api_key = input("   Enter your Shodan API key (or press Enter to skip): ").strip()
            if api_key:
                updates["SHODAN_API_KEY"] = api_key
                # Test the API key
                test_result = self.test_shodan_api(api_key)
                if test_result["status"] == "success":
                    logger.info("✅ Shodan API key is valid")
                else:
                    logger.warning("⚠️ Shodan API key test failed")
        
        # AbuseIPDB
        if not env_vars.get("ABUSEIPDB_API_KEY"):
            logger.info("\n🔑 AbuseIPDB API Key:")
            logger.info("   Get your API key from: https://www.abuseipdb.com/api")
            api_key = input("   Enter your AbuseIPDB API key (or press Enter to skip): ").strip()
            if api_key:
                updates["ABUSEIPDB_API_KEY"] = api_key
                # Test the API key
                test_result = self.test_abuseipdb_api(api_key)
                if test_result["status"] == "success":
                    logger.info("✅ AbuseIPDB API key is valid")
                else:
                    logger.warning("⚠️ AbuseIPDB API key test failed")
        
        # Update .env file if there are changes
        if updates:
            if self.update_env_file(updates):
                logger.info("✅ API keys updated in .env file")
            else:
                logger.error("❌ Failed to update API keys")
        
        return updates
    
    def run_api_tests(self) -> Dict[str, any]:
        """Run comprehensive API tests."""
        logger.info("🧪 Running API tests...")
        
        env_vars = self.read_env_file()
        test_results = {}
        
        # Test APIs with keys
        if env_vars.get("VIRUSTOTAL_API_KEY"):
            test_results["virustotal"] = self.test_virustotal_api(env_vars["VIRUSTOTAL_API_KEY"])
        
        if env_vars.get("SHODAN_API_KEY"):
            test_results["shodan"] = self.test_shodan_api(env_vars["SHODAN_API_KEY"])
        
        if env_vars.get("ABUSEIPDB_API_KEY"):
            test_results["abuseipdb"] = self.test_abuseipdb_api(env_vars["ABUSEIPDB_API_KEY"])
        
        # Test public APIs
        public_results = self.test_public_apis()
        test_results.update(public_results)
        
        return test_results


def main():
    """Main external API setup function."""
    logger.info("🌐 Starting External API Setup")
    
    # Configure logging
    configure_logging()
    
    manager = ExternalAPIManager()
    
    # Step 1: Display instructions
    manager.display_api_instructions()
    
    # Step 2: Interactive setup
    logger.info("\n" + "="*50)
    updates = manager.interactive_setup()
    
    # Step 3: Run API tests
    logger.info("\n🧪 Testing API connections...")
    test_results = manager.run_api_tests()
    
    # Display test results
    logger.info("\n📊 API Test Results:")
    for api_name, result in test_results.items():
        status_icon = "✅" if result.get("status") == "success" else "❌"
        logger.info(f"  {status_icon} {api_name}: {result.get('status', 'unknown')}")
    
    # Summary
    successful_apis = sum(1 for result in test_results.values() if result.get("status") == "success")
    total_apis = len(test_results)
    
    logger.info(f"\n📈 Summary: {successful_apis}/{total_apis} APIs working")
    
    if successful_apis > 0:
        logger.info("🎉 External API setup completed successfully!")
        logger.info("\n📋 NEXT STEPS:")
        logger.info("1. Start the API: python scripts/start_api.py")
        logger.info("2. Test the system: python scripts/debug_api.py")
        logger.info("3. Initialize sources: python scripts/init_default_sources.py")
        return 0
    else:
        logger.warning("⚠️ No APIs are working - you can still use the system with limited functionality")
        return 0


if __name__ == "__main__":
    sys.exit(main())