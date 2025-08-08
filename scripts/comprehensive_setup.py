#!/usr/bin/env python3
# =============================================================================
# COMPREHENSIVE SETUP SCRIPT
# =============================================================================
"""
Comprehensive setup for the Cyber Threat Monitoring System.
This script orchestrates all setup steps: security, infrastructure, and APIs.
"""

import os
import sys
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctms.core.logger import configure_logging, get_logger

logger = get_logger(__name__)


class ComprehensiveSetup:
    """Orchestrates the complete setup process."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.setup_steps = [
            ("Security Setup", "security_setup.py"),
            ("Infrastructure Setup", "infrastructure_setup.py"),
            ("External API Setup", "external_api_setup.py"),
            ("Default Sources Setup", "init_default_sources.py"),
            ("System Test", "debug_api.py")
        ]
    
    def run_script(self, script_name: str, description: str) -> bool:
        """Run a setup script."""
        try:
            logger.info(f"\n{'='*60}")
            logger.info(f"🚀 {description}")
            logger.info(f"{'='*60}")
            
            script_path = self.project_root / "scripts" / script_name
            
            if not script_path.exists():
                logger.error(f"❌ Script not found: {script_path}")
                return False
            
            # Run the script
            result = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=self.project_root,
                capture_output=False,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                logger.info(f"✅ {description} completed successfully")
                return True
            else:
                logger.error(f"❌ {description} failed with return code {result.returncode}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"❌ {description} timed out")
            return False
        except Exception as e:
            logger.error(f"❌ {description} error: {e}")
            return False
    
    def check_prerequisites(self) -> bool:
        """Check if all prerequisites are met."""
        logger.info("🔍 Checking prerequisites...")
        
        # Check if .env file exists
        env_file = self.project_root / ".env"
        if not env_file.exists():
            logger.error("❌ .env file not found")
            logger.info("   Please run: cp .env.example .env")
            return False
        
        # Check if Python dependencies are installed
        try:
            import fastapi
            import uvicorn
            import motor
            import elasticsearch
            logger.info("✅ Python dependencies are installed")
        except ImportError as e:
            logger.error(f"❌ Missing Python dependency: {e}")
            logger.info("   Please run: pip install -r requirements.txt")
            return False
        
        # Check if Docker is available
        try:
            result = subprocess.run(
                ["docker", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                logger.info("✅ Docker is available")
            else:
                logger.warning("⚠️ Docker is not available - some features may not work")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("⚠️ Docker is not available - some features may not work")
        
        logger.info("✅ Prerequisites check completed")
        return True
    
    def create_backup(self) -> bool:
        """Create a backup of current configuration."""
        try:
            logger.info("📋 Creating backup...")
            
            backup_dir = self.project_root / "backups"
            backup_dir.mkdir(exist_ok=True)
            
            import shutil
            from datetime import datetime
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"setup_backup_{timestamp}"
            backup_path = backup_dir / backup_name
            
            # Create backup of .env file
            env_file = self.project_root / ".env"
            if env_file.exists():
                backup_env = backup_path / ".env"
                backup_env.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(env_file, backup_env)
                logger.info(f"✅ Backup created: {backup_path}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"❌ Failed to create backup: {e}")
            return False
    
    def run_setup(self, skip_steps: List[str] = None) -> Dict[str, bool]:
        """Run the complete setup process."""
        if skip_steps is None:
            skip_steps = []
        
        logger.info("🎯 Starting Comprehensive Setup")
        logger.info("=" * 60)
        
        # Step 0: Check prerequisites
        if not self.check_prerequisites():
            return {"prerequisites": False}
        
        # Step 1: Create backup
        self.create_backup()
        
        # Step 2: Run setup steps
        results = {}
        
        for description, script_name in self.setup_steps:
            if script_name in skip_steps:
                logger.info(f"⏭️ Skipping {description}")
                results[description] = True
                continue
            
            success = self.run_script(script_name, description)
            results[description] = success
            
            if not success:
                logger.error(f"❌ Setup failed at: {description}")
                logger.info("You can retry individual steps manually:")
                logger.info(f"   python scripts/{script_name}")
                break
            
            # Small delay between steps
            time.sleep(2)
        
        return results
    
    def generate_summary_report(self, results: Dict[str, bool]) -> str:
        """Generate a summary report of the setup."""
        report = []
        report.append("\n" + "="*60)
        report.append("📊 SETUP SUMMARY REPORT")
        report.append("="*60)
        
        successful_steps = sum(1 for success in results.values() if success)
        total_steps = len(results)
        
        for step, success in results.items():
            status_icon = "✅" if success else "❌"
            report.append(f"  {status_icon} {step}")
        
        report.append(f"\n📈 Overall: {successful_steps}/{total_steps} steps completed")
        
        if successful_steps == total_steps:
            report.append("\n🎉 All setup steps completed successfully!")
            report.append("\n📋 NEXT STEPS:")
            report.append("1. Start the API: python scripts/start_api.py")
            report.append("2. Access the dashboard: http://localhost:8501")
            report.append("3. Access the API docs: http://localhost:8001/docs")
            report.append("4. Test the API: curl -X GET http://localhost:8001/health")
        else:
            report.append("\n⚠️ Some setup steps failed. Please check the logs above.")
            report.append("You can retry individual steps manually.")
        
        return "\n".join(report)
    
    def display_help(self):
        """Display help information."""
        logger.info("🔧 Comprehensive Setup Help")
        logger.info("=" * 40)
        logger.info("This script runs all setup steps in the correct order:")
        logger.info("")
        for i, (description, script_name) in enumerate(self.setup_steps, 1):
            logger.info(f"{i}. {description} ({script_name})")
        logger.info("")
        logger.info("Options:")
        logger.info("  --skip-security     Skip security setup")
        logger.info("  --skip-infrastructure Skip infrastructure setup")
        logger.info("  --skip-apis         Skip external API setup")
        logger.info("  --skip-sources      Skip default sources setup")
        logger.info("  --skip-test         Skip system test")
        logger.info("  --help              Show this help")


def main():
    """Main setup function."""
    # Configure logging
    configure_logging()
    
    # Parse command line arguments
    skip_steps = []
    if "--skip-security" in sys.argv:
        skip_steps.append("security_setup.py")
    if "--skip-infrastructure" in sys.argv:
        skip_steps.append("infrastructure_setup.py")
    if "--skip-apis" in sys.argv:
        skip_steps.append("external_api_setup.py")
    if "--skip-sources" in sys.argv:
        skip_steps.append("init_default_sources.py")
    if "--skip-test" in sys.argv:
        skip_steps.append("debug_api.py")
    if "--help" in sys.argv:
        setup = ComprehensiveSetup()
        setup.display_help()
        return 0
    
    # Run setup
    setup = ComprehensiveSetup()
    results = setup.run_setup(skip_steps)
    
    # Generate and display summary
    summary = setup.generate_summary_report(results)
    logger.info(summary)
    
    # Return success if all steps passed
    if all(results.values()):
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())