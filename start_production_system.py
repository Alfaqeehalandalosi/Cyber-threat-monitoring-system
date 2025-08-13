#!/usr/bin/env python3
"""
Production Startup Script for Hacker-Grade Threat Intelligence System
Starts both the data collector service and API server
"""

import asyncio
import subprocess
import sys
import time
import signal
import logging
import os
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ctms/logs/production.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ProductionSystem:
    """Production system manager"""
    
    def __init__(self):
        self.collector_process = None
        self.api_process = None
        self.running = True
        
        # Ensure directories exist
        os.makedirs('ctms/logs', exist_ok=True)
        os.makedirs('ctms/data', exist_ok=True)
        os.makedirs('ctms/models', exist_ok=True)
        os.makedirs('ctms/cache', exist_ok=True)
        os.makedirs('config', exist_ok=True)
    
    def print_banner(self):
        """Print production system banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    🛡️ Hacker-Grade Threat Intelligence System              ║
║                                                              ║
║    PRODUCTION MODE - Advanced Threat Monitoring             ║
║    Educational purposes only - Defensive security research  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def start_data_collector(self):
        """Start the data collector service"""
        logger.info("🚀 Starting data collector service...")
        
        try:
            self.collector_process = subprocess.Popen([
                sys.executable, "data_collector_service.py"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait a moment for startup
            time.sleep(3)
            
            if self.collector_process.poll() is None:
                logger.info("✅ Data collector service started successfully")
                return True
            else:
                logger.error("❌ Data collector service failed to start")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error starting data collector: {e}")
            return False
    
    def start_api_server(self):
        """Start the API server"""
        logger.info("🚀 Starting API server...")
        
        try:
            self.api_process = subprocess.Popen([
                sys.executable, "-m", "uvicorn", "ctms.main:app",
                "--host", "localhost",
                "--port", "8000",
                "--reload"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait a moment for startup
            time.sleep(5)
            
            if self.api_process.poll() is None:
                logger.info("✅ API server started successfully")
                return True
            else:
                logger.error("❌ API server failed to start")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error starting API server: {e}")
            return False
    
    def start_dashboard(self):
        """Start the Streamlit dashboard"""
        logger.info("🚀 Starting dashboard...")
        
        try:
            dashboard_process = subprocess.Popen([
                sys.executable, "-m", "streamlit", "run", "hacker_grade_dashboard.py",
                "--server.port", "8501",
                "--server.headless", "true"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait a moment for startup
            time.sleep(8)
            
            if dashboard_process.poll() is None:
                logger.info("✅ Dashboard started successfully")
                return True
            else:
                logger.error("❌ Dashboard failed to start")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error starting dashboard: {e}")
            return False
    
    def check_services(self):
        """Check if all services are running"""
        services_ok = True
        
        # Check data collector
        if self.collector_process and self.collector_process.poll() is not None:
            logger.error("❌ Data collector service is not running")
            services_ok = False
        
        # Check API server
        if self.api_process and self.api_process.poll() is not None:
            logger.error("❌ API server is not running")
            services_ok = False
        
        return services_ok
    
    def stop_services(self):
        """Stop all services"""
        logger.info("🛑 Stopping production services...")
        
        if self.collector_process:
            logger.info("🛑 Stopping data collector...")
            self.collector_process.terminate()
            try:
                self.collector_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.collector_process.kill()
        
        if self.api_process:
            logger.info("🛑 Stopping API server...")
            self.api_process.terminate()
            try:
                self.api_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.api_process.kill()
        
        logger.info("✅ All services stopped")
    
    def run_production_system(self):
        """Run the complete production system"""
        self.print_banner()
        
        logger.info("🔧 Starting Hacker-Grade Threat Intelligence System (Production Mode)")
        
        # Start data collector
        if not self.start_data_collector():
            logger.error("❌ Failed to start data collector. Exiting.")
            return False
        
        # Start API server
        if not self.start_api_server():
            logger.error("❌ Failed to start API server. Exiting.")
            self.stop_services()
            return False
        
        # Start dashboard
        if not self.start_dashboard():
            logger.warning("⚠️ Failed to start dashboard. Continuing with API and collector.")
        
        # Print success message
        print("\n" + "=" * 60)
        print("🎉 Hacker-Grade Threat Intelligence System Started Successfully!")
        print("=" * 60)
        print("📡 API Server: http://localhost:8000")
        print("📊 Dashboard: http://localhost:8501")
        print("📚 Documentation: http://localhost:8000/docs")
        print("🔍 Health Check: http://localhost:8000/health")
        print("🛡️ Hacker-Grade API: http://localhost:8000/api/v1/hacker-grade/health")
        print("=" * 60)
        print("📚 Educational purposes only - Defensive security research")
        print("⚠️  Ensure compliance with applicable laws and regulations")
        print("=" * 60)
        print("Press Ctrl+C to stop the system")
        print("=" * 60)
        
        # Monitor services
        try:
            while self.running:
                if not self.check_services():
                    logger.error("❌ One or more services are not running")
                    break
                
                time.sleep(30)  # Check every 30 seconds
                
        except KeyboardInterrupt:
            logger.info("🛑 Received shutdown signal")
        finally:
            self.stop_services()
        
        return True

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"🛑 Received signal {signum}")
    sys.exit(0)

def main():
    """Main function"""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and run production system
    system = ProductionSystem()
    success = system.run_production_system()
    
    if success:
        logger.info("✅ Production system completed successfully")
        sys.exit(0)
    else:
        logger.error("❌ Production system failed to start")
        sys.exit(1)

if __name__ == "__main__":
    main()