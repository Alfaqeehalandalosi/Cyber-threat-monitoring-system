#!/usr/bin/env python3
"""
Test Threat Report Script
Test the threat report endpoint functionality
"""

import requests
import json

def test_threat_report():
    """Test threat report endpoint"""
    
    # API configuration
    api_url = "http://localhost:8000"
    headers = {
        "Authorization": "Bearer demo_token_for_development_12345",
        "Content-Type": "application/json"
    }
    
    print("📊 Testing Threat Report Endpoint...")
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
    
    # Test 2: Get threat report
    print("\n2. Testing threat report endpoint...")
    try:
        response = requests.get(f"{api_url}/api/v1/hacker-grade/threats/report", headers=headers, timeout=10)
        if response.status_code == 200:
            report = response.json()
            print("✅ Threat report generated successfully")
            print(f"📊 Report generated: {report.get('report_generated', 'Unknown')}")
            print(f"📰 Total threats: {report.get('total_threats', 0)}")
            
            # Show threat summary
            threat_summary = report.get('threat_summary', {})
            print(f"🚨 High severity: {threat_summary.get('high_severity', 0)}")
            print(f"⚠️  Medium severity: {threat_summary.get('medium_severity', 0)}")
            print(f"ℹ️  Low severity: {threat_summary.get('low_severity', 0)}")
            
            # Show source breakdown
            source_breakdown = report.get('source_breakdown', {})
            print(f"\n📋 Source breakdown:")
            for source, count in source_breakdown.items():
                print(f"   • {source}: {count}")
            
            # Show threat types
            threat_types = report.get('threat_types', {})
            print(f"\n🎯 Threat types:")
            for threat_type, count in threat_types.items():
                print(f"   • {threat_type}: {count}")
            
            # Show top threats
            top_threats = report.get('top_threats', [])
            print(f"\n🔥 Top threats ({len(top_threats)}):")
            for i, threat in enumerate(top_threats[:5], 1):
                print(f"   {i}. {threat.get('title', 'Unknown')[:50]}... (Score: {threat.get('score', 0)})")
            
            # Show indicators
            recent_indicators = report.get('recent_indicators', {})
            print(f"\n🔍 Recent indicators:")
            for indicator_type, values in recent_indicators.items():
                count = len(values)
                if count > 0:
                    print(f"   • {indicator_type}: {count} found")
                    for val in values[:3]:  # Show first 3
                        print(f"     - {val}")
                else:
                    print(f"   • {indicator_type}: None found")
            
            # Show insights
            insights = report.get('insights', {})
            print(f"\n💡 Insights:")
            print(f"   • Most active source: {insights.get('most_active_source', 'None')}")
            print(f"   • Most common threat type: {insights.get('most_common_threat_type', 'None')}")
            print(f"   • Total indicators: {insights.get('total_indicators', 0)}")
            print(f"   • Average threat score: {insights.get('avg_threat_score', 0)}")
            
        else:
            print(f"❌ Threat report failed: {response.status_code}")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"❌ Threat report error: {e}")
    
    print("\n" + "=" * 50)
    print("🎯 Threat Report Testing Complete!")

if __name__ == "__main__":
    test_threat_report()