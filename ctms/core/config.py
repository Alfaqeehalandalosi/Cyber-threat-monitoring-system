# =============================================================================
# CORE CONFIGURATION MODULE
# =============================================================================
"""
Centralized configuration management for the Cyber Threat Monitoring System.
Uses Pydantic for validation and type safety.
"""

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


# =============================================================================
# MAIN CONFIGURATION CLASS
# =============================================================================
class Settings(BaseSettings):
    """
    Main configuration class for the CTMS application.
    Automatically loads from environment variables and .env file.
    """
    
    # =============================================================================
    # APPLICATION SETTINGS
    # =============================================================================
    app_name: str = Field(default="Cyber Threat Monitoring System", description="Application name")
    app_version: str = Field(default="1.0.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode flag")
    secret_key: str = Field(description="Secret key for encryption")
    
    # =============================================================================
    # DATABASE CONFIGURATION
    # =============================================================================
    # MongoDB Settings
    mongodb_url: str = Field(description="MongoDB connection URL")
    mongodb_database: str = Field(default="threat_monitoring", description="MongoDB database name")
    
    # Elasticsearch Settings
    elasticsearch_url: str = Field(default="http://localhost:9200", description="Elasticsearch URL")
    elasticsearch_index_prefix: str = Field(default="ctms", description="Elasticsearch index prefix")
    
    # Redis Settings
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")
    
    # =============================================================================
    # TOR PROXY CONFIGURATION
    # =============================================================================
    tor_proxy_host: str = Field(default="localhost", description="TOR proxy host")
    tor_proxy_port: int = Field(default=9050, description="TOR SOCKS proxy port")
    tor_http_proxy_port: int = Field(default=8118, description="TOR HTTP proxy port")
    use_tor_proxy: bool = Field(default=True, description="Enable TOR proxy usage")
    
    # =============================================================================
    # API CONFIGURATION
    # =============================================================================
    api_host: str = Field(default="0.0.0.0", description="API server host")
    api_port: int = Field(default=8000, description="API server port")
    api_workers: int = Field(default=4, description="Number of API workers")
    
    # =============================================================================
    # DASHBOARD CONFIGURATION
    # =============================================================================
    dashboard_host: str = Field(default="0.0.0.0", description="Dashboard host")
    dashboard_port: int = Field(default=8501, description="Dashboard port")
    
    # =============================================================================
    # SECURITY SETTINGS
    # =============================================================================
    # JWT Token Settings
    jwt_secret_key: str = Field(description="JWT secret key")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expire_minutes: int = Field(default=30, description="JWT expiration minutes")
    
    # API Rate Limiting
    rate_limit_per_minute: int = Field(default=60, description="API rate limit per minute")
    
    # =============================================================================
    # SCRAPING CONFIGURATION
    # =============================================================================
    user_agent: str = Field(
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        description="User agent for scraping"
    )
    scraping_delay: float = Field(default=2.0, description="Delay between scraping requests")
    scraping_randomize_delay: float = Field(default=0.5, description="Random delay variation")
    concurrent_requests: int = Field(default=8, description="Maximum concurrent requests")
    
    # =============================================================================
    # LOGGING CONFIGURATION
    # =============================================================================
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: str = Field(default="logs/ctms.log", description="Log file path")
    log_rotation: str = Field(default="10 MB", description="Log rotation size")
    log_retention: str = Field(default="30 days", description="Log retention period")
    
    # =============================================================================
    # ALERT CONFIGURATION
    # =============================================================================
    # Email Settings
    smtp_server: Optional[str] = Field(default=None, description="SMTP server")
    smtp_port: int = Field(default=587, description="SMTP port")
    smtp_username: Optional[str] = Field(default=None, description="SMTP username")
    smtp_password: Optional[str] = Field(default=None, description="SMTP password")
    alert_from_email: Optional[str] = Field(default=None, description="Alert sender email")
    
    # Slack Integration
    slack_webhook_url: Optional[str] = Field(default=None, description="Slack webhook URL")
    
    # =============================================================================
    # EXTERNAL APIS
    # =============================================================================
    virustotal_api_key: Optional[str] = Field(default=None, description="VirusTotal API key")
    shodan_api_key: Optional[str] = Field(default=None, description="Shodan API key")
    threatcrowd_enabled: bool = Field(default=True, description="Enable ThreatCrowd API")
    
    # =============================================================================
    # DEMO MODE CONFIGURATION
    # =============================================================================
    demo_mode: bool = Field(default=False, description="Enable demo mode without database")
    
    # =============================================================================
    # PYDANTIC CONFIGURATION
    # =============================================================================
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# =============================================================================
# GLOBAL SETTINGS INSTANCE
# =============================================================================
# Create a single instance to be imported throughout the application
settings = Settings()


# =============================================================================
# CONFIGURATION VALIDATION
# =============================================================================
def validate_config() -> bool:
    """
    Validate critical configuration settings.
    
    Returns:
        bool: True if configuration is valid, False otherwise
    """
    try:
        # Check required settings
        required_fields = ["secret_key", "mongodb_url", "jwt_secret_key"]
        for field in required_fields:
            if not getattr(settings, field, None):
                print(f"❌ Missing required configuration: {field}")
                return False
        
        print("✅ Configuration validation passed")
        return True
        
    except Exception as e:
        print(f"❌ Configuration validation failed: {e}")
        return False


# =============================================================================
# CONFIGURATION UTILITIES
# =============================================================================
def get_database_url() -> str:
    """Get the formatted database URL."""
    return settings.mongodb_url


def get_elasticsearch_url() -> str:
    """Get the Elasticsearch URL."""
    return settings.elasticsearch_url


def get_tor_proxy_config() -> dict:
    """Get TOR proxy configuration."""
    return {
        "host": settings.tor_proxy_host,
        "port": settings.tor_proxy_port,
        "http_port": settings.tor_http_proxy_port,
        "enabled": settings.use_tor_proxy,
    }


def is_debug_mode() -> bool:
    """Check if debug mode is enabled."""
    return settings.debug