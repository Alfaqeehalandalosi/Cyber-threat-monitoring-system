#!/usr/bin/env python3
# =============================================================================
# INFRASTRUCTURE SETUP SCRIPT
# =============================================================================
"""
Infrastructure setup for the Cyber Threat Monitoring System.
This script handles database services, Docker configuration, and system dependencies.
"""

import os
import sys
import subprocess
import time
import requests
from pathlib import Path
from typing import Dict, List, Optional

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctms.core.config import settings
from ctms.core.logger import configure_logging, get_logger

logger = get_logger(__name__)


class InfrastructureManager:
    """Manages infrastructure setup and health checks."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.docker_compose_file = self.project_root / "docker-compose.yml"
        self.services = {
            "mongodb": {"port": 27017, "health_url": None},
            "elasticsearch": {"port": 9200, "health_url": "http://localhost:9200/_cluster/health"},
            "redis": {"port": 6379, "health_url": None},
            "tor-proxy": {"port": 8118, "health_url": None}
        }
    
    def check_docker_availability(self) -> bool:
        """Check if Docker is available and running."""
        try:
            result = subprocess.run(
                ["docker", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"✅ Docker available: {result.stdout.strip()}")
                return True
            else:
                logger.error("❌ Docker is not available")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.error("❌ Docker is not installed or not running")
            return False
    
    def check_docker_compose_availability(self) -> bool:
        """Check if Docker Compose is available."""
        try:
            result = subprocess.run(
                ["docker-compose", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"✅ Docker Compose available: {result.stdout.strip()}")
                return True
            else:
                # Try new docker compose command
                result = subprocess.run(
                    ["docker", "compose", "version"], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                if result.returncode == 0:
                    logger.info(f"✅ Docker Compose available: {result.stdout.strip()}")
                    return True
                else:
                    logger.error("❌ Docker Compose is not available")
                    return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.error("❌ Docker Compose is not installed")
            return False
    
    def start_docker_services(self) -> bool:
        """Start all Docker services."""
        try:
            logger.info("🚀 Starting Docker services...")
            
            # Change to project directory
            os.chdir(self.project_root)
            
            # Start services in detached mode
            result = subprocess.run(
                ["docker-compose", "up", "-d"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                logger.info("✅ Docker services started successfully")
                return True
            else:
                logger.error(f"❌ Failed to start Docker services: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("❌ Timeout starting Docker services")
            return False
        except Exception as e:
            logger.error(f"❌ Error starting Docker services: {e}")
            return False
    
    def check_service_health(self, service_name: str, max_attempts: int = 30) -> bool:
        """Check if a service is healthy."""
        service_config = self.services.get(service_name)
        if not service_config:
            logger.error(f"❌ Unknown service: {service_name}")
            return False
        
        logger.info(f"🔍 Checking {service_name} health...")
        
        # Check if port is open
        port = service_config["port"]
        for attempt in range(max_attempts):
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                
                if result == 0:
                    logger.info(f"✅ {service_name} is running on port {port}")
                    
                    # Additional health check for services with health URLs
                    if service_config["health_url"]:
                        try:
                            response = requests.get(service_config["health_url"], timeout=10)
                            if response.status_code == 200:
                                logger.info(f"✅ {service_name} health check passed")
                                return True
                            else:
                                logger.warning(f"⚠️ {service_name} health check failed: {response.status_code}")
                        except Exception as e:
                            logger.warning(f"⚠️ {service_name} health check error: {e}")
                    
                    return True
                else:
                    if attempt < max_attempts - 1:
                        logger.info(f"   Attempt {attempt + 1}/{max_attempts} - waiting for {service_name}...")
                        time.sleep(2)
                    else:
                        logger.error(f"❌ {service_name} failed to start after {max_attempts} attempts")
                        return False
                        
            except Exception as e:
                logger.error(f"❌ Error checking {service_name}: {e}")
                return False
        
        return False
    
    def wait_for_services(self, timeout: int = 120) -> Dict[str, bool]:
        """Wait for all services to be ready."""
        logger.info(f"⏳ Waiting for services to be ready (timeout: {timeout}s)...")
        
        service_status = {}
        start_time = time.time()
        
        for service_name in self.services.keys():
            if time.time() - start_time > timeout:
                logger.error(f"❌ Timeout waiting for services")
                break
            
            service_status[service_name] = self.check_service_health(service_name)
        
        return service_status
    
    def create_database_indexes(self) -> bool:
        """Create database indexes for optimal performance."""
        try:
            logger.info("📊 Creating database indexes...")
            
            # Import database connection
            from ctms.database.connection import initialize_databases, get_database
            
            # Initialize databases
            import asyncio
            asyncio.run(initialize_databases())
            
            # Get database connection
            db = asyncio.run(get_database())
            
            # Create indexes for each collection
            indexes = {
                "iocs": [
                    ("type", 1),
                    ("severity", 1),
                    ("created_at", -1),
                    ("value", 1)
                ],
                "threats": [
                    ("threat_type", 1),
                    ("severity", 1),
                    ("created_at", -1),
                    ("title", "text")
                ],
                "alerts": [
                    ("status", 1),
                    ("severity", 1),
                    ("created_at", -1)
                ],
                "scraping_sources": [
                    ("enabled", 1),
                    ("source_type", 1),
                    ("name", 1)
                ],
                "scraped_content": [
                    ("source_id", 1),
                    ("scraping_timestamp", -1),
                    ("processed", 1)
                ]
            }
            
            for collection_name, index_list in indexes.items():
                collection = getattr(db, collection_name)
                for field, direction in index_list:
                    try:
                        collection.create_index(field, direction)
                        logger.info(f"✅ Created index on {collection_name}.{field}")
                    except Exception as e:
                        logger.warning(f"⚠️ Failed to create index on {collection_name}.{field}: {e}")
            
            logger.info("✅ Database indexes created successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create database indexes: {e}")
            return False
    
    def setup_elasticsearch_indices(self) -> bool:
        """Setup Elasticsearch indices for search functionality."""
        try:
            logger.info("🔍 Setting up Elasticsearch indices...")
            
            import asyncio
            from ctms.database.connection import get_elasticsearch
            
            es = asyncio.run(get_elasticsearch())
            
            # Define index mappings
            indices = {
                "ctms_iocs": {
                    "mappings": {
                        "properties": {
                            "value": {"type": "text"},
                            "type": {"type": "keyword"},
                            "severity": {"type": "keyword"},
                            "description": {"type": "text"},
                            "tags": {"type": "keyword"}
                        }
                    }
                },
                "ctms_threats": {
                    "mappings": {
                        "properties": {
                            "title": {"type": "text"},
                            "description": {"type": "text"},
                            "threat_type": {"type": "keyword"},
                            "severity": {"type": "keyword"},
                            "tags": {"type": "keyword"}
                        }
                    }
                },
                "ctms_content": {
                    "mappings": {
                        "properties": {
                            "title": {"type": "text"},
                            "content": {"type": "text"},
                            "source_url": {"type": "keyword"},
                            "tags": {"type": "keyword"}
                        }
                    }
                }
            }
            
            for index_name, mapping in indices.items():
                try:
                    # Check if index exists
                    if not es.indices.exists(index=index_name):
                        es.indices.create(index=index_name, body=mapping)
                        logger.info(f"✅ Created Elasticsearch index: {index_name}")
                    else:
                        logger.info(f"ℹ️ Elasticsearch index already exists: {index_name}")
                except Exception as e:
                    logger.warning(f"⚠️ Failed to create Elasticsearch index {index_name}: {e}")
            
            logger.info("✅ Elasticsearch indices setup completed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to setup Elasticsearch indices: {e}")
            return False
    
    def install_system_dependencies(self) -> bool:
        """Install system dependencies if needed."""
        try:
            logger.info("📦 Checking system dependencies...")
            
            # Check if required packages are available
            required_packages = ["python3", "pip", "docker"]
            missing_packages = []
            
            for package in required_packages:
                try:
                    subprocess.run([package, "--version"], capture_output=True, check=True)
                except (subprocess.CalledProcessError, FileNotFoundError):
                    missing_packages.append(package)
            
            if missing_packages:
                logger.warning(f"⚠️ Missing packages: {missing_packages}")
                logger.info("Please install missing packages manually")
                return False
            else:
                logger.info("✅ All system dependencies are available")
                return True
                
        except Exception as e:
            logger.error(f"❌ Error checking system dependencies: {e}")
            return False
    
    def create_logs_directory(self) -> bool:
        """Create logs directory with proper permissions."""
        try:
            logs_dir = self.project_root / "logs"
            logs_dir.mkdir(exist_ok=True)
            
            # Set proper permissions
            os.chmod(logs_dir, 0o755)
            
            logger.info("✅ Logs directory created")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create logs directory: {e}")
            return False
    
    def run_infrastructure_health_check(self) -> Dict[str, any]:
        """Run a comprehensive infrastructure health check."""
        logger.info("🏥 Running infrastructure health check...")
        
        health_results = {
            "docker_available": self.check_docker_availability(),
            "docker_compose_available": self.check_docker_compose_availability(),
            "system_dependencies": self.install_system_dependencies(),
            "logs_directory": self.create_logs_directory(),
            "services_status": {}
        }
        
        # Check service status if Docker is available
        if health_results["docker_available"] and health_results["docker_compose_available"]:
            health_results["services_status"] = self.wait_for_services()
        
        return health_results


def main():
    """Main infrastructure setup function."""
    logger.info("🏗️ Starting Cyber Threat Monitoring System Infrastructure Setup")
    
    # Configure logging
    configure_logging()
    
    manager = InfrastructureManager()
    
    # Step 1: Health check
    logger.info("\n🔍 Step 1: Infrastructure health check...")
    health_results = manager.run_infrastructure_health_check()
    
    # Display health results
    logger.info("\n📊 Health Check Results:")
    for check, status in health_results.items():
        if check != "services_status":
            status_icon = "✅" if status else "❌"
            logger.info(f"  {status_icon} {check}: {status}")
    
    if health_results["services_status"]:
        logger.info("\n🐳 Docker Services Status:")
        for service, status in health_results["services_status"].items():
            status_icon = "✅" if status else "❌"
            logger.info(f"  {status_icon} {service}: {status}")
    
    # Step 2: Start services if needed
    if health_results["docker_available"] and health_results["docker_compose_available"]:
        logger.info("\n🚀 Step 2: Starting Docker services...")
        if manager.start_docker_services():
            logger.info("✅ Docker services started")
            
            # Step 3: Wait for services
            logger.info("\n⏳ Step 3: Waiting for services to be ready...")
            service_status = manager.wait_for_services()
            
            all_services_ready = all(service_status.values())
            if all_services_ready:
                logger.info("✅ All services are ready")
                
                # Step 4: Setup databases
                logger.info("\n📊 Step 4: Setting up databases...")
                if manager.create_database_indexes():
                    logger.info("✅ Database indexes created")
                
                if manager.setup_elasticsearch_indices():
                    logger.info("✅ Elasticsearch indices setup")
                
                logger.info("\n🎉 Infrastructure setup completed successfully!")
                logger.info("\n📋 NEXT STEPS:")
                logger.info("1. Run security setup: python scripts/security_setup.py")
                logger.info("2. Test the system: python scripts/debug_api.py")
                logger.info("3. Start the API: python scripts/start_api.py")
                logger.info("4. Initialize default sources: python scripts/init_default_sources.py")
                return 0
            else:
                logger.error("❌ Some services failed to start")
                return 1
        else:
            logger.error("❌ Failed to start Docker services")
            return 1
    else:
        logger.error("❌ Docker is not available - please install Docker and Docker Compose")
        return 1


if __name__ == "__main__":
    sys.exit(main())