#!/usr/bin/env python3
"""
Hacker-Grade Threat Intelligence System Runner
Comprehensive system startup and monitoring for academic cybersecurity research
Educational purposes only - Defensive security research
"""

import os
import sys
import asyncio
import subprocess
import time
import signal
import logging
from datetime import datetime
from pathlib import Path
import threading
import requests
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ctms/logs/system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class HackerGradeSystemRunner:
    """Hacker-Grade Threat Intelligence System Runner"""
    
    def __init__(self):
        self.api_process = None
        self.dashboard_process = None
        self.running = False
        self.api_url = "http://localhost:8000"
        self.dashboard_url = "http://localhost:8501"
        
        # Load environment variables
        load_dotenv()
        
        # Get configuration
        self.api_host = os.getenv("API_HOST", "localhost")
        self.api_port = int(os.getenv("API_PORT", 8000))
        self.dashboard_port = int(os.getenv("DASHBOARD_PORT", 8501))
        
    def print_banner(self):
        """Print system banner"""
        banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    🛡️ Hacker-Grade Threat Intelligence System              ║
    ║                                                              ║
    ║    Advanced Threat Monitoring & Analysis                    ║
    ║    Educational purposes only - Defensive security research  ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
    def check_dependencies(self):
        """Check if all required dependencies are installed"""
        logger.info("🔍 Checking system dependencies...")

        required_packages = [
            ('fastapi', 'fastapi'),
            ('uvicorn', 'uvicorn'),
            ('streamlit', 'streamlit'),
            ('aiohttp', 'aiohttp'),
            ('requests', 'requests'),
            ('pandas', 'pandas'),
            ('numpy', 'numpy'),
            ('sklearn', 'scikit-learn'),  # Fixed import name
            ('bs4', 'beautifulsoup4'),    # Fixed import name
            ('lxml', 'lxml')
        ]

        missing_packages = []
        for import_name, package_name in required_packages:
            try:
                __import__(import_name)
                logger.info(f"   ✅ {package_name}")
            except ImportError:
                missing_packages.append(package_name)
                logger.error(f"   ❌ {package_name} - Missing")

        if missing_packages:
            logger.error(f"❌ Missing packages: {', '.join(missing_packages)}")
            logger.error("Please install missing packages using: pip install -r requirements.txt")
            return False

        logger.info("✅ All dependencies are installed")
        return True
    
    def check_directories(self):
        """Check and create necessary directories"""
        logger.info("📁 Checking directories...")
        
        directories = [
            'ctms/logs',
            'ctms/models',
            'ctms/data',
            'ctms/cache',
            'config'
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            logger.info(f"   ✅ {directory}")
        
        return True
    
    def start_api_server(self):
        """Start the FastAPI server"""
        logger.info("🚀 Starting API server...")
        
        try:
            # Start API server
            self.api_process = subprocess.Popen([
                sys.executable, "-m", "uvicorn", "ctms.main:app",
                "--host", self.api_host,
                "--port", str(self.api_port),
                "--reload"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for API to start
            time.sleep(5)
            
            # Check if API is running
            if self.check_api_health():
                logger.info(f"✅ API server started successfully on {self.api_url}")
                return True
            else:
                logger.error("❌ API server failed to start")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error starting API server: {e}")
            return False
    
    def start_dashboard(self):
        """Start the Streamlit dashboard"""
        logger.info("📊 Starting dashboard...")
        
        try:
            # Start dashboard
            self.dashboard_process = subprocess.Popen([
                sys.executable, "-m", "streamlit", "run", "hacker_grade_dashboard.py",
                "--server.port", str(self.dashboard_port),
                "--server.headless", "true"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for dashboard to start
            time.sleep(8)
            
            # Check if dashboard is running
            if self.check_dashboard_health():
                logger.info(f"✅ Dashboard started successfully on {self.dashboard_url}")
                return True
            else:
                logger.error("❌ Dashboard failed to start")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error starting dashboard: {e}")
            return False
    
    def check_api_health(self):
        """Check API health"""
        try:
            response = requests.get(f"{self.api_url}/health", timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def check_dashboard_health(self):
        """Check dashboard health"""
        try:
            response = requests.get(self.dashboard_url, timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def monitor_system(self):
        """Monitor system health"""
        logger.info("🔍 Starting system monitoring...")
        
        while self.running:
            try:
                # Check API health
                api_healthy = self.check_api_health()
                if not api_healthy:
                    logger.warning("⚠️ API server is not responding")
                
                # Check dashboard health
                dashboard_healthy = self.check_dashboard_health()
                if not dashboard_healthy:
                    logger.warning("⚠️ Dashboard is not responding")
                
                # Log status
                status = "🟢" if api_healthy and dashboard_healthy else "🟡"
                logger.info(f"{status} System Status - API: {'🟢' if api_healthy else '🔴'}, Dashboard: {'🟢' if dashboard_healthy else '🔴'}")
                
                # Wait before next check
                time.sleep(30)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"❌ Monitoring error: {e}")
                time.sleep(30)
    
    def start_monitoring(self):
        """Start monitoring in background thread"""
        monitor_thread = threading.Thread(target=self.monitor_system, daemon=True)
        monitor_thread.start()
        return monitor_thread
    
    def stop_system(self):
        """Stop the system"""
        logger.info("🛑 Stopping Hacker-Grade Threat Intelligence System...")
        
        self.running = False
        
        # Stop dashboard
        if self.dashboard_process:
            logger.info("🛑 Stopping dashboard...")
            self.dashboard_process.terminate()
            try:
                self.dashboard_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.dashboard_process.kill()
        
        # Stop API server
        if self.api_process:
            logger.info("🛑 Stopping API server...")
            self.api_process.terminate()
            try:
                self.api_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.api_process.kill()
        
        logger.info("✅ System stopped successfully")
    
    def run_system(self):
        """Run the complete system"""
        self.print_banner()
        
        # Check dependencies
        if not self.check_dependencies():
            logger.error("❌ System startup failed due to missing dependencies")
            return False
        
        # Check directories
        if not self.check_directories():
            logger.error("❌ System startup failed due to directory issues")
            return False
        
        # Start API server
        if not self.start_api_server():
            logger.error("❌ Failed to start API server")
            return False
        
        # Start dashboard
        if not self.start_dashboard():
            logger.error("❌ Failed to start dashboard")
            return False
        
        # Start monitoring
        self.running = True
        monitor_thread = self.start_monitoring()
        
        # Print success message
        print("\n" + "=" * 60)
        print("🎉 Hacker-Grade Threat Intelligence System Started Successfully!")
        print("=" * 60)
        print(f"📡 API Server: {self.api_url}")
        print(f"📊 Dashboard: {self.dashboard_url}")
        print(f"📚 Documentation: {self.api_url}/docs")
        print(f"🔍 Health Check: {self.api_url}/health")
        print("=" * 60)
        print("📚 Educational purposes only - Defensive security research")
        print("⚠️  Ensure compliance with applicable laws and regulations")
        print("=" * 60)
        print("Press Ctrl+C to stop the system")
        print("=" * 60)
        
        try:
            # Keep the main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("🛑 Received shutdown signal")
        finally:
            self.stop_system()
        
        return True

def signal_handler(signum, frame):
    """Handle system signals"""
    logger.info(f"🛑 Received signal {signum}")
    sys.exit(0)

def main():
    """Main function"""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and run system
    runner = HackerGradeSystemRunner()
    success = runner.run_system()
    
    if success:
        logger.info("✅ System completed successfully")
        sys.exit(0)
    else:
        logger.error("❌ System failed to start")
        sys.exit(1)

if __name__ == "__main__":
    main()