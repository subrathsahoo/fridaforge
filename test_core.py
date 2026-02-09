#!/usr/bin/env python3
"""
FridaForge - Test Core Functionality
This script tests the core analysis pipeline step by step
"""

import sys
import hashlib
from pathlib import Path

def test_jadx():
    """Test JADX installation"""
    import subprocess
    try:
        result = subprocess.run(['jadx', '--version'], capture_output=True, text=True)
        print(f"✓ JADX installed: {result.stdout.strip()}")
        return True
    except:
        print("✗ JADX not found")
        return False

def test_apktool():
    """Test Apktool installation"""
    import subprocess
    try:
        result = subprocess.run(['apktool', '--version'], capture_output=True, text=True)
        print(f"✓ Apktool installed: {result.stdout.strip()}")
        return True
    except:
        print("✗ Apktool not found")
        return False

def test_openai():
    """Test OpenAI API key"""
    import os
    from dotenv import load_dotenv
    load_dotenv()
    
    api_key = os.environ.get('OPENAI_API_KEY')
    if api_key and api_key.startswith('sk-') and len(api_key) > 20:
        print(f"✓ OpenAI API key configured ({api_key[:15]}...)")
        return True
    else:
        print("✗ OpenAI API key not configured properly")
        print("  Add to .env: OPENAI_API_KEY=sk-your-key")
        return False

def test_mongodb():
    """Test MongoDB connection"""
    try:
        from pymongo import MongoClient
        client = MongoClient('mongodb://localhost:27017', serverSelectionTimeoutMS=2000)
        client.server_info()
        print("✓ MongoDB connection successful")
        return True
    except Exception as e:
        print(f"✗ MongoDB connection failed: {e}")
        return False

def calculate_hash(file_path):
    """Calculate APK hash"""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
            sha256.update(chunk)
    
    return md5.hexdigest(), sha256.hexdigest()

def main():
    print("╔═══════════════════════════════════════════════╗")
    print("║     ⚔️  FRIDAFORGE CORE TEST  ⚔️              ║")
    print("╚═══════════════════════════════════════════════╝")
    print()
    
    tests = [
        ("JADX", test_jadx),
        ("Apktool", test_apktool),
        ("OpenAI API", test_openai),
        ("MongoDB", test_mongodb),
    ]
    
    results = []
    for name, test_func in tests:
        print(f"Testing {name}...")
        results.append(test_func())
        print()
    
    if all(results):
        print("╔═══════════════════════════════════════════════╗")
        print("║        ✅ ALL CORE COMPONENTS READY! ✅        ║")
        print("╚═══════════════════════════════════════════════╝")
        print()
        print("FridaForge is ready to analyze APKs!")
        return 0
    else:
        print("╔═══════════════════════════════════════════════╗")
        print("║     ⚠️  SOME COMPONENTS NOT READY  ⚠️         ║")
        print("╚═══════════════════════════════════════════════╝")
        print()
        print("Please fix the issues above before using FridaForge.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
