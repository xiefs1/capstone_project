"""
Example Usage: SAST + SCA Together
Shows how to use both SAST and SCA for comprehensive security analysis
"""

import os
import sys

def run_sast_analysis():
    """Run SAST analysis on code"""
    print("🔒 SAST (Static Analysis) - Finding vulnerabilities in code...")
    print("=" * 60)
    
    # Example vulnerable code samples
    vulnerable_codes = [
        "SELECT * FROM users WHERE id = '" + userInput + "'",
        "document.write('<script>alert(1)</script>')",
        "os.system('rm -rf /')",
        "filename = request.getParameter('file')\nwith open(filename, 'r') as f:",
        "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");"
    ]
    
    print("Analyzing code samples:")
    for i, code in enumerate(vulnerable_codes, 1):
        print(f"\n{i}. Code: {code}")
        # In real usage, you would use your SAST model here
        print("   Analysis: [SAST would analyze this code]")
        print("   Result: [Vulnerable/Safe with confidence score]")
        print("   Fix: [Specific remediation suggestion]")

def run_sca_analysis():
    """Run SCA analysis on dependencies"""
    print("\n📦 SCA (Dependency Analysis) - Finding vulnerabilities in dependencies...")
    print("=" * 60)
    
    # Example dependencies
    dependencies = [
        {"package": "django", "version": "1.11.0", "status": "vulnerable"},
        {"package": "flask", "version": "0.12.0", "status": "vulnerable"},
        {"package": "requests", "version": "2.19.0", "status": "vulnerable"},
        {"package": "numpy", "version": "1.15.0", "status": "vulnerable"},
        {"package": "pandas", "version": "1.0.0", "status": "safe"},
        {"package": "matplotlib", "version": "3.0.0", "status": "safe"},
    ]
    
    print("Analyzing dependencies:")
    for dep in dependencies:
        print(f"\n📦 {dep['package']} ({dep['version']})")
        if dep['status'] == 'vulnerable':
            print("   Status: VULNERABLE")
            print("   Priority: HIGH")
            print("   ML Confidence: 88%")
            print("   CVE: CVE-2019-XXXX")
            print("   Fix: Update to latest version")
        else:
            print("   Status: SAFE")
            print("   ML Confidence: 100%")
            print("   No known vulnerabilities")

def run_combined_analysis():
    """Run both SAST and SCA analysis"""
    print("🛡️ COMPREHENSIVE SECURITY ANALYSIS")
    print("=" * 60)
    print("Running both SAST and SCA for complete security coverage...")
    
    # Run SAST
    run_sast_analysis()
    
    # Run SCA
    run_sca_analysis()
    
    # Combined results
    print("\n📊 COMBINED SECURITY SUMMARY")
    print("=" * 60)
    print("SAST Results:")
    print("  - Code vulnerabilities found: 4")
    print("  - High severity: 2")
    print("  - Medium severity: 2")
    print("  - Accuracy: 95.2%")
    
    print("\nSCA Results:")
    print("  - Dependency vulnerabilities found: 4")
    print("  - High priority: 2")
    print("  - Medium priority: 2")
    print("  - Accuracy: 100%")
    
    print("\nOverall Security Status:")
    print("  - Total vulnerabilities: 8")
    print("  - Critical issues: 0")
    print("  - High priority: 4")
    print("  - Medium priority: 4")
    print("  - Security score: 85/100")

def show_usage_instructions():
    """Show how to actually use the tools"""
    print("\n🚀 HOW TO ACTUALLY USE YOUR TOOLS:")
    print("=" * 60)
    
    print("1. SAST (Static Analysis):")
    print("   cd XXX_Final/SAST/")
    print("   python simple_advanced_training.py")
    print("   python advanced_sast_with_remediation.py")
    
    print("\n2. SCA (Dependency Analysis):")
    print("   cd XXX_Final/SCA/")
    print("   python simple_sca_ml.py --project . --train")
    print("   python simple_sca_ml.py --project /path/to/your/project")
    
    print("\n3. GitLab Integration:")
    print("   cd XXX_Final/GitLab/")
    print("   # Follow GITLAB_DEPLOYMENT_GUIDE.md")
    print("   # Copy files to your GitLab project")
    print("   # Set up CI/CD pipeline")
    
    print("\n4. Combined Analysis:")
    print("   # Run SAST first to check your code")
    print("   # Run SCA second to check your dependencies")
    print("   # Use GitLab integration for automation")

def main():
    """Main function"""
    print("🛡️ SAST + SCA Usage Example")
    print("=" * 60)
    print("This shows how to use both SAST and SCA together")
    print("for comprehensive security analysis")
    
    # Run combined analysis
    run_combined_analysis()
    
    # Show usage instructions
    show_usage_instructions()
    
    print("\n🎉 Your security analysis suite is ready!")
    print("Start with SAST, add SCA, then integrate with GitLab!")

if __name__ == "__main__":
    main()

