#!/usr/bin/env python3
"""
Simple API server test
"""

import sys
import os
import subprocess
import time

def test_api_server():
    """Test starting the API server"""
    print("🚀 Testing API server startup...")
    
    try:
        # Try to start the API server
        process = subprocess.Popen([
            sys.executable, "-m", "uvicorn", "ctms.main:app",
            "--host", "localhost",
            "--port", "8000",
            "--reload"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait a few seconds
        time.sleep(5)
        
        # Check if process is still running
        if process.poll() is None:
            print("✅ API server started successfully!")
            print("🌐 API available at: http://localhost:8000")
            print("📚 Documentation at: http://localhost:8000/docs")
            
            # Terminate the process
            process.terminate()
            process.wait()
            return True
        else:
            # Get the error output
            stdout, stderr = process.communicate()
            print("❌ API server failed to start")
            print("Error output:")
            print(stderr.decode())
            return False
            
    except Exception as e:
        print(f"❌ Error starting API server: {e}")
        return False

if __name__ == "__main__":
    print("🔍 API Server Startup Test")
    print("=" * 50)
    
    success = test_api_server()
    
    print("\n" + "=" * 50)
    if success:
        print("✅ API server works correctly!")
    else:
        print("❌ API server has issues that need to be fixed")