#!/bin/bash
# =============================================================================
# DOWNLOAD SETUP SCRIPTS
# =============================================================================
# This script downloads all the setup scripts to your local machine

echo "📥 Downloading setup scripts to your local machine..."

# Create scripts directory if it doesn't exist
mkdir -p scripts

# Download each script
echo "🔧 Downloading comprehensive_setup.py..."
curl -o scripts/comprehensive_setup.py "https://raw.githubusercontent.com/your-repo/Cyber-threat-monitoring-system/main/scripts/comprehensive_setup.py"

echo "🔧 Downloading security_setup.py..."
curl -o scripts/security_setup.py "https://raw.githubusercontent.com/your-repo/Cyber-threat-monitoring-system/main/scripts/security_setup.py"

echo "🔧 Downloading infrastructure_setup.py..."
curl -o scripts/infrastructure_setup.py "https://raw.githubusercontent.com/your-repo/Cyber-threat-monitoring-system/main/scripts/infrastructure_setup.py"

echo "🔧 Downloading external_api_setup.py..."
curl -o scripts/external_api_setup.py "https://raw.githubusercontent.com/your-repo/Cyber-threat-monitoring-system/main/scripts/external_api_setup.py"

echo "🔧 Downloading init_default_sources.py..."
curl -o scripts/init_default_sources.py "https://raw.githubusercontent.com/your-repo/Cyber-threat-monitoring-system/main/scripts/init_default_sources.py"

echo "🔧 Downloading debug_api.py..."
curl -o scripts/debug_api.py "https://raw.githubusercontent.com/your-repo/Cyber-threat-monitoring-system/main/scripts/debug_api.py"

echo "🔧 Downloading start_api.py..."
curl -o scripts/start_api.py "https://raw.githubusercontent.com/your-repo/Cyber-threat-monitoring-system/main/scripts/start_api.py"

# Make scripts executable
chmod +x scripts/*.py

echo "✅ All setup scripts downloaded successfully!"
echo "📋 You can now run: python scripts/comprehensive_setup.py"