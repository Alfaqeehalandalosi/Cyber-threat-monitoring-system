#!/usr/bin/env python3
"""
Simple script to fix security keys in .env file
"""

import secrets
import string
import os

def generate_secure_key(length=64):
    """Generate a secure key without special characters that cause shell issues."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_jwt_secret():
    """Generate a secure JWT secret."""
    return secrets.token_urlsafe(64)

def update_env_file():
    """Update the .env file with secure keys."""
    env_file = ".env"
    
    if not os.path.exists(env_file):
        print("❌ .env file not found. Please run: cp .env.example .env")
        return False
    
    # Read current content
    with open(env_file, 'r') as f:
        lines = f.readlines()
    
    # Generate secure keys
    secret_key = generate_secure_key(64)
    jwt_secret = generate_jwt_secret()
    
    print(f"Generated SECRET_KEY: {secret_key}")
    print(f"Generated JWT_SECRET_KEY: {jwt_secret}")
    
    # Update values
    updated_lines = []
    for line in lines:
        if line.startswith("SECRET_KEY=") and "your-super-secret-key" in line:
            updated_lines.append(f"SECRET_KEY={secret_key}\n")
        elif line.startswith("JWT_SECRET_KEY=") and "your-jwt-secret-key" in line:
            updated_lines.append(f"JWT_SECRET_KEY={jwt_secret}\n")
        else:
            updated_lines.append(line)
    
    # Write back to file
    with open(env_file, 'w') as f:
        f.writelines(updated_lines)
    
    print("✅ Updated .env file with secure keys")
    return True

if __name__ == "__main__":
    print("🔐 Fixing security keys...")
    if update_env_file():
        print("✅ Security keys updated successfully!")
    else:
        print("❌ Failed to update security keys")