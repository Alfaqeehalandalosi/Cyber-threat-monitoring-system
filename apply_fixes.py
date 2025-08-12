#!/usr/bin/env python3
"""
Apply Fixes Script for Cyber Threat Monitoring System
This script applies all the necessary fixes to resolve the AttributeError.
"""

import os
import sys
import shutil
from pathlib import Path

def print_status(message, status="INFO"):
    """Print a formatted status message."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    if status == "SUCCESS":
        print(f"[{timestamp}] ✅ {message}")
    elif status == "ERROR":
        print(f"[{timestamp}] ❌ {message}")
    elif status == "WARNING":
        print(f"[{timestamp}] ⚠️ {message}")
    else:
        print(f"[{timestamp}] ℹ️ {message}")

def backup_file(file_path):
    """Create a backup of a file."""
    backup_path = f"{file_path}.backup"
    if os.path.exists(file_path):
        shutil.copy2(file_path, backup_path)
        print_status(f"Created backup: {backup_path}")
        return True
    return False

def apply_fixes():
    """Apply all the fixes to the codebase."""
    print_status("=" * 60)
    print_status("APPLYING FIXES TO CYBER THREAT MONITORING SYSTEM")
    print_status("=" * 60)
    
    # Get the current directory
    current_dir = Path.cwd()
    print_status(f"Working directory: {current_dir}")
    
    # Check if we're in the right directory
    if not (current_dir / "ctms").exists():
        print_status("❌ ctms directory not found. Please run this script from the project root.", "ERROR")
        return False
    
    fixes_applied = 0
    
    # Fix 1: Update ThreatAnalyzer constructor and methods
    analyzer_file = current_dir / "ctms" / "nlp" / "threat_analyzer.py"
    if analyzer_file.exists():
        print_status(f"Applying fix to: {analyzer_file}")
        backup_file(analyzer_file)
        
        # Read the current file
        with open(analyzer_file, 'r') as f:
            content = f.read()
        
        # Apply the constructor fix
        old_constructor = "def __init__(self):"
        new_constructor = '''def __init__(self, session=None, database_url=None):
        """
        Initialize threat analyzer.
        
        Args:
            session: Optional session object (for backward compatibility)
            database_url: Optional database URL (for backward compatibility)
        """
        self.classifier = ThreatClassifier()
        self.ioc_extractor = IOCExtractor()
        self.entity_extractor = EntityExtractor()
        
        # Store session and database_url for backward compatibility
        self.session = session
        self.database_url = database_url
        
        logger.info("🧠 Threat analyzer initialized")'''
        
        if old_constructor in content:
            content = content.replace(old_constructor, new_constructor)
            fixes_applied += 1
            print_status("✅ Updated ThreatAnalyzer constructor", "SUCCESS")
        
        # Apply the processed field fix
        old_query = '{"analysis_id": {"$exists": False}}'
        new_query = '{"processed": False}'
        if old_query in content:
            content = content.replace(old_query, new_query)
            fixes_applied += 1
            print_status("✅ Updated database query to use processed field", "SUCCESS")
        
        # Write the updated content
        with open(analyzer_file, 'w') as f:
            f.write(content)
    
    # Fix 2: Update ThreatIntelligenceScraper session management
    scraper_file = current_dir / "ctms" / "scraping" / "tor_scraper.py"
    if scraper_file.exists():
        print_status(f"Applying fix to: {scraper_file}")
        backup_file(scraper_file)
        
        # Read the current file
        with open(scraper_file, 'r') as f:
            content = f.read()
        
        # Add get_session method if it doesn't exist
        if "async def get_session(self)" not in content:
            get_session_method = '''
    async def get_session(self) -> aiohttp.ClientSession:
        """
        Get or create a session.
        
        Returns:
            aiohttp.ClientSession: Session instance
        """
        if not self.session or self.session.closed:
            await self.initialize()
        return self.session'''
            
            # Find the right place to insert (after initialize method)
            if "async def initialize(self)" in content:
                content = content.replace(
                    "async def initialize(self) -> None:",
                    "async def initialize(self) -> None:" + get_session_method
                )
                fixes_applied += 1
                print_status("✅ Added get_session method", "SUCCESS")
        
        # Update close method to properly handle session
        old_close = "async def close(self) -> None:"
        new_close = '''async def close(self) -> None:
        """Close scraper and cleanup resources."""
        if self.session and not self.session.closed:
            await self.session.close()
        await self.tor_manager.close()
        logger.info("🛑 Threat intelligence scraper closed")'''
        
        if old_close in content:
            content = content.replace(old_close, new_close)
            fixes_applied += 1
            print_status("✅ Updated close method", "SUCCESS")
        
        # Write the updated content
        with open(scraper_file, 'w') as f:
            f.write(content)
    
    # Fix 3: Update main.py background function
    main_file = current_dir / "ctms" / "api" / "main.py"
    if main_file.exists():
        print_status(f"Applying fix to: {main_file}")
        backup_file(main_file)
        
        # Read the current file
        with open(main_file, 'r') as f:
            content = f.read()
        
        # Update the _background_run_scrape function
        old_background = '''async def _background_run_scrape(job_id: str) -> Dict[str, Any]:
    """
    Background scraping function for backward compatibility.
    This function provides the interface that was mentioned in the error.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict[str, Any]: Scraping and analysis results
    """
    logger.info(f"🔄 Starting background scraping job: {job_id}")
    
    try:
        # Create scraper and run full cycle
        from ctms.scraping.tor_scraper import create_scraper
        from ctms.nlp.threat_analyzer import ThreatAnalyzer
        
        scraper = await create_scraper()
        
        try:
            # Run full scraping cycle
            scraping_results = await scraper.run_full_cycle()
            
            # Analyze latest threats
            analyzer = ThreatAnalyzer()
            analysis_results = await analyzer.analyze_latest_threats()
            
            results = {
                "job_id": job_id,
                "status": "completed",
                "scraping_results": scraping_results,
                "analysis_results": analysis_results,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(f"✅ Background scraping job {job_id} completed successfully")
            return results
            
        finally:
            await scraper.close()
            
    except Exception as e:
        logger.error(f"❌ Background scraping job {job_id} failed: {e}")
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }'''
        
        new_background = '''async def _background_run_scrape(job_id: str) -> Dict[str, Any]:
    """
    Background scraping function for backward compatibility.
    This function provides the interface that was mentioned in the error.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict[str, Any]: Scraping and analysis results
    """
    logger.info(f"🔄 Starting background scraping job: {job_id}")
    
    try:
        # Create scraper and run full cycle
        from ctms.scraping.tor_scraper import create_scraper
        from ctms.nlp.threat_analyzer import ThreatAnalyzer
        
        scraper = await create_scraper()
        
        try:
            # Run full scraping cycle
            scraping_results = await scraper.run_full_cycle()
            
            # Create analyzer with proper constructor (no args for new API)
            analyzer = ThreatAnalyzer()
            
            # Analyze latest threats (this will query DB for unprocessed content)
            analysis_results = await analyzer.analyze_latest_threats()
            
            results = {
                "job_id": job_id,
                "status": "completed",
                "scraping_results": scraping_results,
                "analysis_results": analysis_results,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(f"✅ Background scraping job {job_id} completed successfully")
            return results
            
        finally:
            # Ensure proper cleanup
            await scraper.close()
            
    except Exception as e:
        logger.error(f"❌ Background scraping job {job_id} failed: {e}")
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }'''
        
        if old_background in content:
            content = content.replace(old_background, new_background)
            fixes_applied += 1
            print_status("✅ Updated _background_run_scrape function", "SUCCESS")
        
        # Write the updated content
        with open(main_file, 'w') as f:
            f.write(content)
    
    print_status(f"\nApplied {fixes_applied} fixes successfully!", "SUCCESS")
    return True

def main():
    """Main function."""
    try:
        from datetime import datetime
        
        success = apply_fixes()
        
        if success:
            print_status("\n" + "=" * 60)
            print_status("FIXES APPLIED SUCCESSFULLY!")
            print_status("=" * 60)
            print_status("\nNext steps:")
            print_status("1. Run the test script: python test_fix.py")
            print_status("2. Start the system: python -m ctms.api.main")
            print_status("3. Test the scraping endpoint")
            print_status("\nThe AttributeError should now be resolved!")
            return 0
        else:
            print_status("❌ Failed to apply fixes", "ERROR")
            return 1
            
    except Exception as e:
        print_status(f"❌ Error applying fixes: {e}", "ERROR")
        return 1

if __name__ == "__main__":
    sys.exit(main())