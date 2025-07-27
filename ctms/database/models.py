# =============================================================================
# DATABASE MODELS MODULE
# =============================================================================
"""
Data models for the Cyber Threat Monitoring System.
Defines schemas for threats, indicators, sources, and alerts.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


# =============================================================================
# ENUMERATIONS
# =============================================================================
class ThreatType(str, Enum):
    """Types of cyber threats."""
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    EXPLOIT = "exploit"
    RANSOMWARE = "ransomware"
    APT = "apt"
    SUSPICIOUS_DOMAIN = "suspicious_domain"
    IOC = "ioc"
    VULNERABILITY = "vulnerability"
    FRAUD = "fraud"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IndicatorType(str, Enum):
    """Types of indicators of compromise."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    USER_AGENT = "user_agent"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"
    FILE_PATH = "file_path"


class SourceType(str, Enum):
    """Types of threat intelligence sources."""
    DARK_WEB = "dark_web"
    SURFACE_WEB = "surface_web"
    THREAT_FEED = "threat_feed"
    HONEYPOT = "honeypot"
    INTERNAL = "internal"
    EXTERNAL_API = "external_api"


class AlertStatus(str, Enum):
    """Alert status types."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# =============================================================================
# BASE MODEL CLASSES
# =============================================================================
class BaseDocument(BaseModel):
    """Base document model with common fields."""
    
    id: Optional[str] = Field(None, alias="_id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        populate_by_name = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# =============================================================================
# THREAT INTELLIGENCE MODELS
# =============================================================================
class IndicatorOfCompromise(BaseDocument):
    """Indicator of Compromise (IOC) model."""
    
    # Core IOC fields
    type: IndicatorType = Field(description="Type of indicator")
    value: str = Field(description="Indicator value")
    description: Optional[str] = Field(None, description="Human-readable description")
    
    # Threat association
    threat_types: List[ThreatType] = Field(default_factory=list, description="Associated threat types")
    confidence: float = Field(ge=0, le=1, description="Confidence score (0-1)")
    severity: SeverityLevel = Field(description="Severity level")
    
    # Source information
    source: str = Field(description="Source of the indicator")
    source_type: SourceType = Field(description="Type of source")
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    
    # Additional metadata
    tags: List[str] = Field(default_factory=list, description="Classification tags")
    ttl: Optional[int] = Field(None, description="Time to live in days")
    false_positive: bool = Field(default=False, description="False positive flag")
    
    # External references
    references: List[str] = Field(default_factory=list, description="External reference URLs")
    related_indicators: List[str] = Field(default_factory=list, description="Related IOC IDs")


class ThreatIntelligence(BaseDocument):
    """Threat intelligence document model."""
    
    # Core threat fields
    title: str = Field(description="Threat title/name")
    description: str = Field(description="Detailed description")
    threat_type: ThreatType = Field(description="Type of threat")
    severity: SeverityLevel = Field(description="Severity level")
    
    # Intelligence details
    iocs: List[str] = Field(default_factory=list, description="Associated IOC IDs")
    ttps: List[str] = Field(default_factory=list, description="Tactics, Techniques, Procedures")
    campaign: Optional[str] = Field(None, description="Campaign name if applicable")
    attribution: Optional[str] = Field(None, description="Attributed threat actor")
    
    # Source and collection
    source: str = Field(description="Intelligence source")
    source_type: SourceType = Field(description="Type of source")
    collection_method: str = Field(description="How the intelligence was collected")
    
    # Temporal information
    first_observed: datetime = Field(default_factory=datetime.utcnow)
    last_observed: datetime = Field(default_factory=datetime.utcnow)
    
    # Analysis and scoring
    confidence: float = Field(ge=0, le=1, description="Confidence score (0-1)")
    risk_score: float = Field(ge=0, le=10, description="Risk score (0-10)")
    tags: List[str] = Field(default_factory=list, description="Classification tags")
    
    # External data
    external_references: List[str] = Field(default_factory=list, description="External URLs")
    mitre_attack_ids: List[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    
    # Processing metadata
    processed: bool = Field(default=False, description="Processing status")
    nlp_entities: Dict[str, Any] = Field(default_factory=dict, description="Extracted NLP entities")


# =============================================================================
# SCRAPING AND COLLECTION MODELS
# =============================================================================
class ScrapingSource(BaseDocument):
    """Web scraping source configuration."""
    
    # Source identification
    name: str = Field(description="Source name")
    url: str = Field(description="Base URL")
    source_type: SourceType = Field(description="Type of source")
    
    # Scraping configuration
    enabled: bool = Field(default=True, description="Enable/disable scraping")
    scraping_interval: int = Field(default=3600, description="Scraping interval in seconds")
    last_scraped: Optional[datetime] = Field(None, description="Last scraping time")
    
    # TOR and proxy settings
    use_tor: bool = Field(default=True, description="Use TOR proxy")
    custom_headers: Dict[str, str] = Field(default_factory=dict, description="Custom HTTP headers")
    
    # Parsing configuration
    content_selectors: Dict[str, str] = Field(default_factory=dict, description="CSS selectors for content")
    url_patterns: List[str] = Field(default_factory=list, description="URL pattern regexes")
    
    # Quality and filtering
    min_content_length: int = Field(default=100, description="Minimum content length")
    blacklist_keywords: List[str] = Field(default_factory=list, description="Blacklist keywords")
    
    # Metadata
    description: Optional[str] = Field(None, description="Source description")
    tags: List[str] = Field(default_factory=list, description="Source tags")
    success_rate: float = Field(default=0.0, description="Scraping success rate")


class ScrapedContent(BaseDocument):
    """Scraped content document."""
    
    # Source information
    source_id: str = Field(description="Source configuration ID")
    source_url: str = Field(description="Source URL")
    scraped_url: str = Field(description="Actual scraped URL")
    
    # Content data
    title: Optional[str] = Field(None, description="Page title")
    content: str = Field(description="Scraped content")
    content_hash: str = Field(description="Content hash for deduplication")
    
    # Scraping metadata
    scraping_timestamp: datetime = Field(default_factory=datetime.utcnow)
    response_status: int = Field(description="HTTP response status")
    content_length: int = Field(description="Content length in bytes")
    
    # Processing status
    processed: bool = Field(default=False, description="NLP processing status")
    threat_score: Optional[float] = Field(None, description="Calculated threat score")
    extracted_iocs: List[str] = Field(default_factory=list, description="Extracted IOC IDs")
    
    # Quality metrics
    language: Optional[str] = Field(None, description="Detected language")
    relevance_score: Optional[float] = Field(None, description="Content relevance score")


# =============================================================================
# ALERT AND NOTIFICATION MODELS
# =============================================================================
class Alert(BaseDocument):
    """Security alert model."""
    
    # Alert identification
    title: str = Field(description="Alert title")
    description: str = Field(description="Alert description")
    alert_type: str = Field(description="Type of alert")
    severity: SeverityLevel = Field(description="Alert severity")
    
    # Status and workflow
    status: AlertStatus = Field(default=AlertStatus.NEW, description="Alert status")
    assigned_to: Optional[str] = Field(None, description="Assigned analyst")
    acknowledged_at: Optional[datetime] = Field(None, description="Acknowledgment timestamp")
    resolved_at: Optional[datetime] = Field(None, description="Resolution timestamp")
    
    # Source data
    source_type: str = Field(description="Source that triggered alert")
    source_data: Dict[str, Any] = Field(default_factory=dict, description="Source data")
    related_iocs: List[str] = Field(default_factory=list, description="Related IOC IDs")
    related_threats: List[str] = Field(default_factory=list, description="Related threat IDs")
    
    # Alert metadata
    confidence: float = Field(ge=0, le=1, description="Alert confidence")
    risk_score: float = Field(ge=0, le=10, description="Risk score")
    tags: List[str] = Field(default_factory=list, description="Alert tags")
    
    # Response and remediation
    response_actions: List[str] = Field(default_factory=list, description="Recommended actions")
    remediation_steps: List[str] = Field(default_factory=list, description="Remediation steps")
    false_positive: bool = Field(default=False, description="False positive flag")
    
    # Notification tracking
    notifications_sent: List[str] = Field(default_factory=list, description="Sent notification channels")
    escalated: bool = Field(default=False, description="Escalation flag")


# =============================================================================
# ANALYSIS AND ENRICHMENT MODELS
# =============================================================================
class NLPAnalysis(BaseDocument):
    """NLP analysis results model."""
    
    # Source reference
    content_id: str = Field(description="Source content ID")
    content_type: str = Field(description="Type of analyzed content")
    
    # Extracted entities
    entities: Dict[str, List[Dict[str, Any]]] = Field(
        default_factory=dict, 
        description="Extracted named entities"
    )
    keywords: List[str] = Field(default_factory=list, description="Extracted keywords")
    topics: List[Dict[str, float]] = Field(default_factory=list, description="Topic analysis")
    
    # Sentiment and classification
    sentiment: Dict[str, float] = Field(default_factory=dict, description="Sentiment analysis")
    threat_indicators: List[Dict[str, Any]] = Field(
        default_factory=list, 
        description="Detected threat indicators"
    )
    classification: Dict[str, float] = Field(
        default_factory=dict, 
        description="Content classification scores"
    )
    
    # Language and structure
    language: str = Field(description="Detected language")
    readability_score: Optional[float] = Field(None, description="Content readability")
    
    # Processing metadata
    model_version: str = Field(description="NLP model version used")
    processing_time: float = Field(description="Processing time in seconds")
    confidence: float = Field(ge=0, le=1, description="Analysis confidence")


# =============================================================================
# SYSTEM MONITORING MODELS
# =============================================================================
class SystemMetrics(BaseDocument):
    """System performance and health metrics."""
    
    # Component identification
    component: str = Field(description="System component name")
    hostname: str = Field(description="Host machine name")
    
    # Performance metrics
    cpu_usage: float = Field(ge=0, le=100, description="CPU usage percentage")
    memory_usage: float = Field(ge=0, le=100, description="Memory usage percentage")
    disk_usage: float = Field(ge=0, le=100, description="Disk usage percentage")
    
    # Application metrics
    active_connections: int = Field(ge=0, description="Active connections count")
    requests_per_minute: float = Field(ge=0, description="Requests per minute")
    error_rate: float = Field(ge=0, le=100, description="Error rate percentage")
    response_time: float = Field(ge=0, description="Average response time in ms")
    
    # Database metrics
    database_connections: int = Field(ge=0, description="Database connections")
    query_response_time: float = Field(ge=0, description="Database query response time")
    
    # Custom metrics
    custom_metrics: Dict[str, float] = Field(
        default_factory=dict, 
        description="Custom application metrics"
    )
    
    # Status flags
    healthy: bool = Field(default=True, description="Component health status")
    alerts_triggered: List[str] = Field(default_factory=list, description="Triggered alerts")


# =============================================================================
# USER AND AUTHENTICATION MODELS
# =============================================================================
class User(BaseDocument):
    """User account model."""
    
    # Basic information
    username: str = Field(description="Unique username")
    email: str = Field(description="User email address")
    full_name: str = Field(description="Full name")
    
    # Authentication
    hashed_password: str = Field(description="Hashed password")
    is_active: bool = Field(default=True, description="Account active status")
    is_admin: bool = Field(default=False, description="Admin privileges")
    
    # Security settings
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")
    failed_login_attempts: int = Field(default=0, description="Failed login count")
    account_locked: bool = Field(default=False, description="Account lock status")
    
    # Permissions and roles
    roles: List[str] = Field(default_factory=list, description="User roles")
    permissions: List[str] = Field(default_factory=list, description="User permissions")
    
    # Preferences
    email_notifications: bool = Field(default=True, description="Email notification preference")
    dashboard_config: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Dashboard configuration"
    )


# =============================================================================
# MODEL REGISTRY
# =============================================================================
# Registry of all models for easy access
MODEL_REGISTRY = {
    "ioc": IndicatorOfCompromise,
    "threat": ThreatIntelligence,
    "scraping_source": ScrapingSource,
    "scraped_content": ScrapedContent,
    "alert": Alert,
    "nlp_analysis": NLPAnalysis,
    "system_metrics": SystemMetrics,
    "user": User,
}


# =============================================================================
# MODEL UTILITIES
# =============================================================================
def get_model(model_name: str) -> BaseModel:
    """
    Get a model class by name.
    
    Args:
        model_name: Name of the model
        
    Returns:
        BaseModel: Model class
        
    Raises:
        KeyError: If model not found
    """
    if model_name not in MODEL_REGISTRY:
        raise KeyError(f"Model '{model_name}' not found in registry")
    
    return MODEL_REGISTRY[model_name]


def list_models() -> List[str]:
    """
    Get a list of all available model names.
    
    Returns:
        List[str]: List of model names
    """
    return list(MODEL_REGISTRY.keys())