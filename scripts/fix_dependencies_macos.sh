#!/bin/bash
# =============================================================================
# macOS Dependency Fix Script for CTMS
# =============================================================================

echo "🔧 Fixing Python dependencies for macOS..."

# Activate virtual environment
source venv/bin/activate

# Upgrade core tools
echo "📦 Upgrading pip and build tools..."
pip install --upgrade pip setuptools wheel

# Install cryptography separately with more flexibility
echo "🔐 Installing cryptography..."
pip install "cryptography>=40.0.0" --no-cache-dir

# Install other problematic packages individually
echo "🛠️ Installing core packages..."
pip install "pydantic>=2.0.0,<3.0.0"
pip install "fastapi>=0.100.0"
pip install "streamlit>=1.25.0"
pip install "spacy>=3.4.0,<4.0.0"

# Try to install remaining packages
echo "📚 Installing remaining packages..."
if [ -f "requirements-macos.txt" ]; then
    pip install -r requirements-macos.txt --no-deps
    pip install -r requirements-macos.txt
else
    # Install packages one by one to isolate issues
    cat requirements.txt | grep -v "^#" | grep -v "^$" | while read requirement; do
        echo "Installing: $requirement"
        pip install "$requirement" || echo "⚠️ Failed to install $requirement, skipping..."
    done
fi

# Install spaCy model
echo "🧠 Installing spaCy model..."
python -m spacy download en_core_web_sm

# Verify installation
echo "✅ Verifying installation..."
python -c "
try:
    import fastapi
    import streamlit
    import spacy
    import pydantic
    import cryptography
    print('✅ All core packages installed successfully!')
except ImportError as e:
    print(f'❌ Missing package: {e}')
"

echo "🎉 Dependency fix complete!"