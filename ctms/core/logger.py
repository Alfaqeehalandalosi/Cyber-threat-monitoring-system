# =============================================================================
# CORE LOGGING MODULE
# =============================================================================
"""
Centralized logging configuration for the Cyber Threat Monitoring System.
Uses Loguru for enhanced logging capabilities with rotation and structured output.
"""

import sys
from pathlib import Path
from typing import Optional
from loguru import logger as loguru_logger


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================
class LoggerManager:
    """
    Manages logging configuration and provides structured logging capabilities.
    """
    
    def __init__(self):
        """Initialize the logger manager."""
        self._configured = False
        self._log_file: Optional[str] = None
    
    def configure(
        self,
        log_level: str = "INFO",
        log_file: str = "logs/ctms.log",
        rotation: str = "10 MB",
        retention: str = "30 days",
        format_string: Optional[str] = None
    ) -> None:
        """
        Configure the logging system.
        
        Args:
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file
            rotation: Log rotation configuration
            retention: Log retention configuration
            format_string: Custom log format string
        """
        if self._configured:
            return
        
        # Remove default handler
        loguru_logger.remove()
        
        # =============================================================================
        # CONSOLE HANDLER - Structured output with colors
        # =============================================================================
        console_format = (
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        )
        
        loguru_logger.add(
            sys.stdout,
            format=console_format,
            level=log_level,
            colorize=True,
            backtrace=True,
            diagnose=True
        )
        
        # =============================================================================
        # FILE HANDLER - Detailed logs with rotation
        # =============================================================================
        # Ensure log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_format = (
            "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
            "{level: <8} | "
            "{name}:{function}:{line} | "
            "{extra[request_id]:{request_id}} | "
            "{message}"
        )
        
        if format_string:
            file_format = format_string
        
        loguru_logger.add(
            log_file,
            format=file_format,
            level=log_level,
            rotation=rotation,
            retention=retention,
            backtrace=True,
            diagnose=True,
            enqueue=True  # Thread-safe logging
        )
        
        self._configured = True
        self._log_file = log_file
        
        # Log configuration success
        loguru_logger.info(
            f"✅ Logging configured - Level: {log_level}, File: {log_file}"
        )
    
    def get_logger(self, name: str) -> "Logger":
        """
        Get a logger instance for a specific module.
        
        Args:
            name: Logger name (usually __name__)
            
        Returns:
            Logger: Configured logger instance
        """
        return Logger(name)


# =============================================================================
# CUSTOM LOGGER CLASS
# =============================================================================
class Logger:
    """
    Custom logger wrapper providing additional functionality.
    """
    
    def __init__(self, name: str):
        """
        Initialize logger instance.
        
        Args:
            name: Logger name
        """
        self.name = name
        self._logger = loguru_logger.bind(name=name)
    
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message."""
        self._logger.debug(message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message."""
        self._logger.info(message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message."""
        self._logger.warning(message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        """Log error message."""
        self._logger.error(message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message."""
        self._logger.critical(message, **kwargs)
    
    def exception(self, message: str, **kwargs) -> None:
        """Log exception with traceback."""
        self._logger.exception(message, **kwargs)
    
    # =============================================================================
    # SECURITY LOGGING METHODS
    # =============================================================================
    def security_event(self, event_type: str, details: dict, **kwargs) -> None:
        """
        Log security-related events with structured data.
        
        Args:
            event_type: Type of security event
            details: Event details dictionary
        """
        self._logger.warning(
            f"🔒 SECURITY EVENT: {event_type}",
            extra={"security_event": event_type, "details": details, **kwargs}
        )
    
    def threat_detected(self, threat_type: str, source: str, details: dict, **kwargs) -> None:
        """
        Log detected threats with structured data.
        
        Args:
            threat_type: Type of threat detected
            source: Source of the threat
            details: Threat details dictionary
        """
        self._logger.error(
            f"⚠️ THREAT DETECTED: {threat_type} from {source}",
            extra={"threat_type": threat_type, "source": source, "details": details, **kwargs}
        )
    
    def scraping_activity(self, url: str, status: str, details: dict = None, **kwargs) -> None:
        """
        Log scraping activities.
        
        Args:
            url: Target URL
            status: Scraping status
            details: Additional details
        """
        self._logger.info(
            f"🕷️ SCRAPING: {status} - {url}",
            extra={"url": url, "status": status, "details": details or {}, **kwargs}
        )
    
    def api_request(self, method: str, endpoint: str, status_code: int, **kwargs) -> None:
        """
        Log API requests.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            status_code: Response status code
        """
        self._logger.info(
            f"🌐 API: {method} {endpoint} - {status_code}",
            extra={"method": method, "endpoint": endpoint, "status_code": status_code, **kwargs}
        )


# =============================================================================
# GLOBAL LOGGER MANAGER
# =============================================================================
_logger_manager = LoggerManager()


# =============================================================================
# PUBLIC API
# =============================================================================
def configure_logging(
    log_level: str = "INFO",
    log_file: str = "logs/ctms.log",
    rotation: str = "10 MB",
    retention: str = "30 days"
) -> None:
    """
    Configure the global logging system.
    
    Args:
        log_level: Logging level
        log_file: Path to log file
        rotation: Log rotation configuration
        retention: Log retention configuration
    """
    _logger_manager.configure(log_level, log_file, rotation, retention)


def get_logger(name: str) -> Logger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger: Configured logger instance
    """
    return _logger_manager.get_logger(name)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================
def log_startup(component: str, version: str = "1.0.0") -> None:
    """
    Log component startup information.
    
    Args:
        component: Component name
        version: Component version
    """
    logger = get_logger("startup")
    logger.info(f"🚀 Starting {component} v{version}")


def log_shutdown(component: str) -> None:
    """
    Log component shutdown information.
    
    Args:
        component: Component name
    """
    logger = get_logger("shutdown")
    logger.info(f"🛑 Shutting down {component}")


def log_performance(operation: str, duration: float, **kwargs) -> None:
    """
    Log performance metrics.
    
    Args:
        operation: Operation name
        duration: Operation duration in seconds
    """
    logger = get_logger("performance")
    logger.info(
        f"⏱️ PERFORMANCE: {operation} completed in {duration:.2f}s",
        extra={"operation": operation, "duration": duration, **kwargs}
    )


# =============================================================================
# AUTO-CONFIGURATION
# =============================================================================
# Try to auto-configure logging with default settings
try:
    from ctms.core.config import settings
    configure_logging(
        log_level=settings.log_level,
        log_file=settings.log_file,
        rotation=settings.log_rotation,
        retention=settings.log_retention
    )
except ImportError:
    # Fallback to default configuration if settings not available
    configure_logging()