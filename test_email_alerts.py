#!/usr/bin/env python3
"""
Test Email Alerts Script
Tests the email alert functionality of the Hacker-Grade Threat Intelligence System
"""

import requests
import json
import time

def test_email_alerts():
    """Test email alert functionality"""
    
    # API configuration
    api_url = "http://localhost:8000"
    headers = {
        "Authorization": "Bearer demo_token_for_development_12345",
        "Content-Type": "application/json"
    }
    
    print("🧪 Testing Email Alerts...")
    print("=" * 50)
    
    # Test 1: Check API health
    print("1. Checking API health...")
    try:
        response = requests.get(f"{api_url}/api/v1/hacker-grade/health", headers=headers, timeout=10)
        if response.status_code == 200:
            print("✅ API is healthy")
        else:
            print(f"❌ API health check failed: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ API health check error: {e}")
        return
    
    # Test 2: Test email alerts
    print("\n2. Testing email alerts...")
    try:
        response = requests.post(f"{api_url}/api/v1/hacker-grade/alerts/test", headers=headers, timeout=10)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Email test successful: {result.get('message', 'Unknown')}")
            if result.get('demo_mode'):
                print("📝 Note: Running in demo mode - no actual emails sent")
        else:
            print(f"❌ Email test failed: {response.status_code}")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"❌ Email test error: {e}")
    
    # Test 3: Configure alerts
    print("\n3. Testing alert configuration...")
    try:
        config_data = {
            "email_recipients": ["test@example.com"],
            "webhook_url": "https://webhook.site/test",
            "threshold": 0.8,
            "enabled": True
        }
        
        response = requests.post(f"{api_url}/api/v1/hacker-grade/alerts/configure", 
                               headers=headers, json=config_data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Alert configuration successful: {result.get('message', 'Unknown')}")
        else:
            print(f"❌ Alert configuration failed: {response.status_code}")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"❌ Alert configuration error: {e}")
    
    print("\n" + "=" * 50)
    print("🎯 Email Alert Testing Complete!")
    print("\n📝 To configure real email alerts:")
    print("1. Edit ctms/api/hacker_grade_endpoints.py")
    print("2. Update ALERT_CONFIG with real SMTP credentials")
    print("3. Set real email recipients")
    print("4. Restart the API server")

if __name__ == "__main__":
    test_email_alerts()