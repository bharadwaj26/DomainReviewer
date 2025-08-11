#!/usr/bin/env python3
"""
Build script for Domain Reviewer Tool executable
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    print("Checking dependencies...")
    
    required_packages = [
        'requests', 'pandas', 'openpyxl', 'tqdm'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"✗ {package} - missing")
    
    # Check PyInstaller separately
    try:
        import PyInstaller
        print("✓ PyInstaller")
    except ImportError:
        missing_packages.append('PyInstaller')
        print("✗ PyInstaller - missing")
    
    if missing_packages:
        print(f"\nMissing packages: {', '.join(missing_packages)}")
        print("Please install missing packages using:")
        print("pip install -r requirements.txt")
        return False
    
    print("All dependencies are installed!")
    return True

def clean_build_dirs():
    """Clean previous build directories"""
    print("\nCleaning previous build directories...")
    
    dirs_to_clean = ['build', 'dist', '__pycache__']
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"✓ Removed {dir_name}/")
    
    # Clean .spec files (except our main one)
    for file in os.listdir('.'):
        if file.endswith('.spec') and file != 'domain_reviewer.spec':
            os.remove(file)
            print(f"✓ Removed {file}")

def build_executable():
    """Build the executable using PyInstaller"""
    print("\nBuilding executable...")
    
    try:
        # Run PyInstaller using python -m
        cmd = [
            sys.executable, '-m', 'PyInstaller',
            '--clean',
            '--noconfirm',
            'domain_reviewer.spec'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ Executable built successfully!")
            return True
        else:
            print("✗ Build failed!")
            print("Error output:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"✗ Build failed with exception: {e}")
        return False

def verify_executable():
    """Verify the executable was created"""
    print("\nVerifying executable...")
    
    exe_path = Path('dist/DomainReviewer.exe')
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"✓ Executable created: {exe_path}")
        print(f"  Size: {size_mb:.1f} MB")
        return True
    else:
        print("✗ Executable not found!")
        return False

def create_sample_files():
    """Create sample files for testing"""
    print("\nCreating sample files...")
    
    # Create sample domain list
    sample_domains = [
        "example.com",
        "google.com",
        "facebook.com",
        "github.com",
        "stackoverflow.com"
    ]
    
    with open('sample_domains.txt', 'w') as f:
        f.write('\n'.join(sample_domains))
    
    print("✓ Created sample_domains.txt")

def main():
    """Main build process"""
    print("=== Domain Reviewer Tool - Build Process ===\n")
    
    # Check dependencies
    if not check_dependencies():
        return False
    
    # Clean previous builds
    clean_build_dirs()
    
    # Build executable
    if not build_executable():
        return False
    
    # Verify executable
    if not verify_executable():
        return False
    
    # Create sample files
    create_sample_files()
    
    print("\n=== Build Complete! ===")
    print("Executable location: dist/DomainReviewer.exe")
    print("Sample domain file: sample_domains.txt")
    print("\nTo run the application:")
    print("1. Double-click DomainReviewer.exe")
    print("2. Enter your VirusTotal API key")
    print("3. Select account type (Personal/Enterprise)")
    print("4. Choose your domain list file")
    print("5. Click 'Start Review'")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 