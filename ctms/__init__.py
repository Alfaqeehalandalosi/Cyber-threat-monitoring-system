# =============================================================================
# CYBER THREAT MONITORING SYSTEM - MAIN PACKAGE
# =============================================================================
"""
Cyber Threat Monitoring System (CTMS)

A comprehensive platform for collecting, analyzing, and monitoring
cyber threats using advanced scraping, NLP, and machine learning techniques.

Author: Security Engineering Team
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Security Engineering Team"
__description__ = "Cyber Threat Monitoring System"

# =============================================================================
# PACKAGE IMPORTS
# =============================================================================
from ctms.core.config import settings
from ctms.core.logger import get_logger

# Initialize the main logger
logger = get_logger(__name__)

# =============================================================================
# PACKAGE METADATA
# =============================================================================
__all__ = [
    "settings",
    "logger",
    "__version__",
    "__author__",
    "__description__",
]