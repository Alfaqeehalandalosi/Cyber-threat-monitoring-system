#!/usr/bin/env python3
# =============================================================================
# SECURITY SETUP SCRIPT
# =============================================================================
"""
Comprehensive security setup for the Cyber Threat Monitoring System.
This script generates secure keys, validates configuration, and sets up security requirements.
"""

import os
import sys
import secrets
import string
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Optional

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctms.core.config import settings
from ctms.core.logger import configure_logging, get_logger

logger = get_logger(__name__)


class SecurityValidator:
    """Security configuration validator and generator."""
    
    def __init__(self):
        self.env_file = Path(".env")
        self.env_backup = Path(".env.backup")
        self.security_issues = []
        self.warnings = []
        
    def generate_secure_key(self, length: int = 64) -> str:
        """Generate a cryptographically secure key."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def generate_jwt_secret(self) -> str:
        """Generate a secure JWT secret key."""
        return secrets.token_urlsafe(64)
    
    def validate_password_strength(self, password: str) -> Dict[str, bool]:
        """Validate password strength."""
        checks = {
            "length": len(password) >= 12,
            "uppercase": any(c.isupper() for c in password),
            "lowercase": any(c.islower() for c in password),
            "digit": any(c.isdigit() for c in password),
            "special": any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        }
        return checks
    
    def generate_strong_password(self) -> str:
        """Generate a strong password."""
        # Ensure at least one of each character type
        password = (
            secrets.choice(string.ascii_uppercase) +
            secrets.choice(string.ascii_lowercase) +
            secrets.choice(string.digits) +
            secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
        )
        
        # Fill the rest with random characters
        password += ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?") 
                           for _ in range(8))
        
        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        return ''.join(password_list)
    
    def backup_env_file(self) -> bool:
        """Create a backup of the current .env file."""
        try:
            if self.env_file.exists():
                import shutil
                shutil.copy2(self.env_file, self.env_backup)
                logger.info(f"✅ Created backup: {self.env_backup}")
                return True
            return False
        except Exception as e:
            logger.error(f"❌ Failed to backup .env file: {e}")
            return False
    
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
        """Update the .env file with new values."""
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
    
    def validate_current_config(self) -> Dict[str, List[str]]:
        """Validate the current configuration for security issues."""
        issues = {"critical": [], "warning": [], "info": []}
        
        env_vars = self.read_env_file()
        
        # Check for default secret keys
        if env_vars.get("SECRET_KEY") == "your-super-secret-key-here-change-this-in-production":
            issues["critical"].append("SECRET_KEY is still using the default value")
        
        if env_vars.get("JWT_SECRET_KEY") == "your-jwt-secret-key-change-this":
            issues["critical"].append("JWT_SECRET_KEY is still using the default value")
        
        # Check for weak passwords in database URLs
        mongodb_url = env_vars.get("MONGODB_URL", "")
        if "secure_mongo_password" in mongodb_url:
            issues["warning"].append("MongoDB password is still using default value")
        
        # Check for empty API keys
        if not env_vars.get("VIRUSTOTAL_API_KEY"):
            issues["info"].append("VirusTotal API key is not configured")
        
        if not env_vars.get("SHODAN_API_KEY"):
            issues["info"].append("Shodan API key is not configured")
        
        # Check for debug mode in production
        if env_vars.get("DEBUG", "false").lower() == "true":
            issues["warning"].append("Debug mode is enabled")
        
        return issues
    
    def generate_secure_config(self) -> Dict[str, str]:
        """Generate secure configuration values."""
        secure_config = {
            "SECRET_KEY": self.generate_secure_key(64),
            "JWT_SECRET_KEY": self.generate_jwt_secret(),
            "MONGODB_PASSWORD": self.generate_strong_password(),
            "REDIS_PASSWORD": self.generate_strong_password(),
            "ELASTICSEARCH_PASSWORD": self.generate_strong_password()
        }
        
        # Update MongoDB URL with new password
        current_env = self.read_env_file()
        mongodb_url = current_env.get("MONGODB_URL", "")
        if "secure_mongo_password" in mongodb_url:
            new_mongodb_url = mongodb_url.replace("secure_mongo_password", secure_config["MONGODB_PASSWORD"])
            secure_config["MONGODB_URL"] = new_mongodb_url
        
        return secure_config
    
    def setup_external_apis(self) -> Dict[str, str]:
        """Setup external API configurations."""
        api_configs = {}
        
        # VirusTotal API
        logger.info("🔑 VirusTotal API Setup:")
        logger.info("   Get your free API key from: https://www.virustotal.com/gui/join-us")
        logger.info("   Or use the public API (limited rate)")
        
        # Shodan API
        logger.info("🔑 Shodan API Setup:")
        logger.info("   Get your API key from: https://account.shodan.io/register")
        logger.info("   Free tier available with limited queries")
        
        # ThreatCrowd (no key needed)
        logger.info("🔑 ThreatCrowd API:")
        logger.info("   No API key required - public API")
        
        # AbuseIPDB
        logger.info("🔑 AbuseIPDB API:")
        logger.info("   Get your API key from: https://www.abuseipdb.com/api")
        
        return api_configs
    
    def create_docker_secrets(self) -> bool:
        """Create Docker secrets for production deployment."""
        try:
            secrets_dir = Path("docker/secrets")
            secrets_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate secrets
            secrets_data = {
                "mongodb_password": self.generate_strong_password(),
                "redis_password": self.generate_strong_password(),
                "elasticsearch_password": self.generate_strong_password(),
                "jwt_secret": self.generate_jwt_secret(),
                "app_secret": self.generate_secure_key(64)
            }
            
            # Write secrets to files
            for secret_name, secret_value in secrets_data.items():
                secret_file = secrets_dir / secret_name
                with open(secret_file, 'w') as f:
                    f.write(secret_value)
                os.chmod(secret_file, 0o600)  # Secure permissions
            
            logger.info(f"✅ Created Docker secrets in {secrets_dir}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create Docker secrets: {e}")
            return False
    
    def validate_network_security(self) -> List[str]:
        """Validate network security configuration."""
        issues = []
        
        # Check if API is exposed on 0.0.0.0
        current_env = self.read_env_file()
        if current_env.get("API_HOST") == "0.0.0.0":
            issues.append("API is configured to listen on all interfaces (0.0.0.0)")
        
        # Check for HTTPS configuration
        if not current_env.get("USE_HTTPS"):
            issues.append("HTTPS is not configured - consider enabling for production")
        
        return issues
    
    def run_security_audit(self) -> Dict[str, any]:
        """Run a comprehensive security audit."""
        logger.info("🔍 Running security audit...")
        
        audit_results = {
            "timestamp": __import__("datetime").datetime.now().isoformat(),
            "issues": self.validate_current_config(),
            "network_security": self.validate_network_security(),
            "recommendations": []
        }
        
        # Generate recommendations
        if audit_results["issues"]["critical"]:
            audit_results["recommendations"].append("Generate new secret keys immediately")
        
        if audit_results["issues"]["warning"]:
            audit_results["recommendations"].append("Update default passwords")
        
        if not audit_results["network_security"]:
            audit_results["recommendations"].append("Configure HTTPS for production")
        
        return audit_results


def main():
    """Main security setup function."""
    logger.info("🔐 Starting Cyber Threat Monitoring System Security Setup")
    
    # Configure logging
    configure_logging()
    
    validator = SecurityValidator()
    
    # Step 1: Backup current configuration
    logger.info("\n📋 Step 1: Creating backup...")
    validator.backup_env_file()
    
    # Step 2: Run security audit
    logger.info("\n🔍 Step 2: Running security audit...")
    audit_results = validator.run_security_audit()
    
    # Display audit results
    for severity, issues in audit_results["issues"].items():
        if issues:
            logger.info(f"\n{severity.upper()} ISSUES:")
            for issue in issues:
                logger.info(f"  • {issue}")
    
    if audit_results["network_security"]:
        logger.info(f"\nNETWORK SECURITY ISSUES:")
        for issue in audit_results["network_security"]:
            logger.info(f"  • {issue}")
    
    # Step 3: Generate secure configuration
    logger.info("\n🔑 Step 3: Generating secure configuration...")
    secure_config = validator.generate_secure_config()
    
    # Step 4: Update .env file
    logger.info("\n📝 Step 4: Updating configuration...")
    if validator.update_env_file(secure_config):
        logger.info("✅ Configuration updated successfully")
    else:
        logger.error("❌ Failed to update configuration")
        return 1
    
    # Step 5: Setup external APIs
    logger.info("\n🌐 Step 5: External API Configuration...")
    validator.setup_external_apis()
    
    # Step 6: Create Docker secrets
    logger.info("\n🐳 Step 6: Creating Docker secrets...")
    validator.create_docker_secrets()
    
    # Step 7: Final validation
    logger.info("\n✅ Step 7: Final validation...")
    final_audit = validator.run_security_audit()
    
    if not final_audit["issues"]["critical"]:
        logger.info("🎉 Security setup completed successfully!")
        logger.info("\n📋 NEXT STEPS:")
        logger.info("1. Configure external API keys in .env file")
        logger.info("2. Start database services: docker-compose up -d")
        logger.info("3. Test the system: python scripts/debug_api.py")
        logger.info("4. Start the API: python scripts/start_api.py")
        return 0
    else:
        logger.error("❌ Security issues remain - please address them")
        return 1


if __name__ == "__main__":
    sys.exit(main())