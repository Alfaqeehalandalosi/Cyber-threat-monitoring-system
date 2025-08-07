#!/usr/bin/env python3
# =============================================================================
# API STARTUP SCRIPT
# =============================================================================
"""
Startup script for the Cyber Threat Monitoring System API.
This script properly initializes all components before starting the API.
"""

import asyncio
import sys
import os
import uvicorn

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctms.core.config import settings
from ctms.core.logger import configure_logging, get_logger
from ctms.database.connection import initialize_databases, close_databases

logger = get_logger(__name__)


async def initialize_system():
    """Initialize the system components."""
    try:
        logger.info("🚀 Initializing Cyber Threat Monitoring System...")
        
        # Configure logging
        configure_logging(
            log_level=settings.log_level,
            log_file=settings.log_file,
            rotation=settings.log_rotation,
            retention=settings.log_retention
        )
        
        # Initialize databases
        await initialize_databases()
        logger.info("✅ Database initialization completed")
        
        # Initialize default sources if needed
        try:
            from scripts.init_default_sources import initialize_default_sources
            await initialize_default_sources()
        except Exception as e:
            logger.warning(f"⚠️ Failed to initialize default sources: {e}")
        
        logger.info("✅ System initialization completed")
        
    except Exception as e:
        logger.error(f"❌ System initialization failed: {e}")
        raise


async def shutdown_system():
    """Shutdown the system components."""
    try:
        logger.info("🛑 Shutting down system...")
        await close_databases()
        logger.info("✅ System shutdown completed")
    except Exception as e:
        logger.error(f"❌ System shutdown failed: {e}")


def main():
    """Main startup function."""
    try:
        # Initialize system
        asyncio.run(initialize_system())
        
        # Start the API server
        logger.info("🌐 Starting API server...")
        uvicorn.run(
            "ctms.api.main:app",
            host=settings.api_host,
            port=settings.api_port,
            reload=settings.debug,
            log_level="info"
        )
        
    except KeyboardInterrupt:
        logger.info("🛑 Received shutdown signal")
        asyncio.run(shutdown_system())
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        asyncio.run(shutdown_system())
        sys.exit(1)


if __name__ == "__main__":
    main()