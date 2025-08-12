#!/bin/bash

# Update Sources Configuration Script
# This script replaces the current sources with the expanded list

echo "🔄 Updating sources configuration with expanded cybersecurity feeds..."
echo "=================================================="

# Backup current configuration
echo "1. Creating backup of current configuration..."
cp ctms/config/real_sources.json ctms/config/real_sources_backup.json
echo "✅ Backup created: ctms/config/real_sources_backup.json"

# Replace with expanded configuration
echo "2. Replacing with expanded sources configuration..."
cp ctms/config/real_sources_expanded.json ctms/config/real_sources.json
echo "✅ Sources configuration updated"

# Count sources
echo "3. Counting sources..."
TOTAL_SOURCES=$(grep -c '"id":' ctms/config/real_sources.json)
ENABLED_SOURCES=$(grep -c '"enabled": true' ctms/config/real_sources.json)

echo "📊 Source Statistics:"
echo "   Total sources: $TOTAL_SOURCES"
echo "   Enabled sources: $ENABLED_SOURCES"

# Show source categories
echo "4. Source categories:"
echo "   📰 News sources: $(grep -c '"type": "news"' ctms/config/real_sources.json)"
echo "   🔬 Research sources: $(grep -c '"type": "research"' ctms/config/real_sources.json)"
echo "   🏢 Vendor blogs: $(grep -c '"type": "vendor"' ctms/config/real_sources.json)"
echo "   🛡️ Vulnerability feeds: $(grep -c '"type": "vulnerability"' ctms/config/real_sources.json)"
echo "   💥 Exploit feeds: $(grep -c '"type": "exploit"' ctms/config/real_sources.json)"
echo "   🏛️ Government sources: $(grep -c '"type": "government"' ctms/config/real_sources.json)"
echo "   📊 Threat intelligence: $(grep -c '"type": "threat_intelligence"' ctms/config/real_sources.json)"

# Show some example sources
echo "5. Example sources added:"
echo "   - Bleeping Computer"
echo "   - The Hacker News"
echo "   - Krebs on Security"
echo "   - Dark Reading"
echo "   - CVE Details"
echo "   - NVD (National Vulnerability Database)"
echo "   - Exploit-DB"
echo "   - MITRE ATT&CK"
echo "   - CISA Alerts"
echo "   - Malwarebytes Labs"
echo "   - ESET Security Blog"
echo "   - Cisco Talos"
echo "   - Microsoft Security Blog"
echo "   - Google Project Zero"
echo "   - And many more..."

echo ""
echo "🎉 Sources configuration updated successfully!"
echo "=================================================="
echo ""
echo "Next steps:"
echo "1. Restart your API server to load the new sources"
echo "2. Test the scraper with: python3 -c \"import asyncio; from ctms.scraping.real_web_scraper import get_real_threat_intelligence; data = asyncio.run(get_real_threat_intelligence()); print(f'Collected {data[\"total_articles\"]} articles from {data[\"sources_used\"]} sources')\""
echo "3. Check the dashboard for more diverse content"
echo ""
echo "Note: Some sources may take longer to scrape due to rate limiting and response times."