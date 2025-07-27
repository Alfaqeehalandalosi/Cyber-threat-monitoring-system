# =============================================================================
# CYBER THREAT MONITORING SYSTEM - CONNECTOR FRAMEWORK
# =============================================================================
# OpenCTI-inspired connector architecture for threat intelligence integration

from enum import Enum
from typing import Dict, Any, Optional


class ConnectorType(str, Enum):
    """Connector types based on OpenCTI architecture"""
    EXTERNAL_IMPORT = "EXTERNAL_IMPORT"
    INTERNAL_ENRICHMENT = "INTERNAL_ENRICHMENT"
    INTERNAL_EXPORT_FILE = "INTERNAL_EXPORT_FILE"
    INTERNAL_IMPORT_FILE = "INTERNAL_IMPORT_FILE"
    STREAM = "STREAM"


class ConnectorScope(str, Enum):
    """Connector scopes for different data types"""
    # STIX Domain Objects
    INDICATOR = "Indicator"
    MALWARE = "Malware"
    THREAT_ACTOR = "Threat-Actor"
    ATTACK_PATTERN = "Attack-Pattern"
    INTRUSION_SET = "Intrusion-Set"
    CAMPAIGN = "Campaign"
    REPORT = "Report"
    
    # File Types
    APPLICATION_JSON = "application/json"
    APPLICATION_PDF = "application/pdf"
    TEXT_PLAIN = "text/plain"
    TEXT_CSV = "text/csv"
    
    # Generic
    ALL = "*"


# Base connector registry
CONNECTOR_REGISTRY: Dict[str, Any] = {}


def register_connector(connector_class):
    """Register a connector class"""
    CONNECTOR_REGISTRY[connector_class.__name__] = connector_class
    return connector_class


def get_connector(name: str) -> Optional[type]:
    """Get connector class by name"""
    return CONNECTOR_REGISTRY.get(name)


def list_connectors() -> Dict[str, Any]:
    """List all registered connectors"""
    return CONNECTOR_REGISTRY.copy()