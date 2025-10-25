"""
SCA Comparison: Traditional vs ML-Enhanced
Shows the difference between traditional SCA and ML-enhanced SCA
"""

import os
import sys
import time
from sca_vulnerability_detector import SCAVulnerabilityDetector
from ml_enhanced_sca import MLEnhancedSCA

def compare_sca_approaches(project_path: str):
    """Compare traditional SCA vs ML-enhanced SCA"""
    
    print("🔍 SCA COMPARISON: Traditional vs ML-Enhanced")
    print("=" * 60)
    
    # Traditional SCA
    print("\n1️⃣ TRADITIONAL SCA (Rule-based)")
    print("-" * 40)
    start_time = time.time()
    
    traditional_sca = SCAVulnerabilityDetector()
    traditional_results = traditional_sca.scan_project(project_path)
    
    traditional_time = time.time() - start_time
    
    print(f"⏱️  Scan time: {traditional_time:.2f} seconds")
    print(f"📊 Vulnerabilities found: {traditional_results['total_vulnerabilities']}")
    print(f"📁 Files scanned: {traditional_results['total_files_scanned']}")
    print(f"📦 Dependencies: {traditional_results['total_dependencies']}")
    
    # ML-Enhanced SCA
    print("\n2️⃣ ML-ENHANCED SCA (Machine Learning)")
    print("-" * 40)
    start_time = time.time()
    
    ml_sca = MLEnhancedSCA()
    ml_results = ml_sca.scan_project_ml_enhanced(project_path)
    
    ml_time = time.time() - start_time
    
    print(f"⏱️  Scan time: {ml_time:.2f} seconds")
    print(f"📊 Vulnerabilities found: {ml_results['total_vulnerabilities']}")
    print(f"📁 Files scanned: {ml_results['total_files_scanned']}")
    print(f"📦 Dependencies: {ml_results['total_dependencies']}")
    print(f"🤖 ML predictions: {ml_results['ml_predictions']}")
    
    # Comparison
    print("\n3️⃣ COMPARISON SUMMARY")
    print("-" * 40)
    print(f"Traditional SCA:")
    print(f"  - Vulnerabilities: {traditional_results['total_vulnerabilities']}")
    print(f"  - Scan time: {traditional_time:.2f}s")
    print(f"  - Approach: Rule-based matching")
    print(f"  - Accuracy: High for known vulnerabilities")
    print(f"  - Coverage: Limited to known CVE database")
    
    print(f"\nML-Enhanced SCA:")
    print(f"  - Vulnerabilities: {ml_results['total_vulnerabilities']}")
    print(f"  - Scan time: {ml_time:.2f}s")
    print(f"  - Approach: Machine learning + rules")
    print(f"  - Accuracy: High + predictive capabilities")
    print(f"  - Coverage: Known + predicted vulnerabilities")
    
    # Key differences
    print(f"\n🎯 KEY DIFFERENCES:")
    print(f"  ✅ ML-Enhanced finds {ml_results['total_vulnerabilities'] - traditional_results['total_vulnerabilities']} more vulnerabilities")
    print(f"  ✅ ML-Enhanced provides priority scoring")
    print(f"  ✅ ML-Enhanced predicts unknown vulnerabilities")
    print(f"  ✅ ML-Enhanced provides confidence scores")
    print(f"  ✅ ML-Enhanced learns from patterns")
    
    return traditional_results, ml_results

def create_test_project():
    """Create a test project with various dependencies"""
    
    test_project = "test_sca_project"
    os.makedirs(test_project, exist_ok=True)
    
    # Python requirements.txt with vulnerable packages
    requirements_content = """django==1.11.0
flask==0.12.0
requests==2.19.0
numpy==1.15.0
pandas==1.0.0
matplotlib==3.0.0
"""
    
    with open(f"{test_project}/requirements.txt", "w") as f:
        f.write(requirements_content)
    
    # Java pom.xml with vulnerable packages
    pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter</artifactId>
            <version>2.0.0</version>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.9.0</version>
        </dependency>
    </dependencies>
</project>
"""
    
    with open(f"{test_project}/pom.xml", "w") as f:
        f.write(pom_content)
    
    # JavaScript package.json with vulnerable packages
    package_json_content = """{
    "dependencies": {
        "lodash": "4.17.0",
        "express": "4.16.0",
        "axios": "0.18.0",
        "react": "16.8.0"
    },
    "devDependencies": {
        "webpack": "4.0.0",
        "babel": "7.0.0"
    }
}
"""
    
    with open(f"{test_project}/package.json", "w") as f:
        f.write(package_json_content)
    
    print(f"✅ Test project created: {test_project}")
    return test_project

def main():
    """Main comparison function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SCA Comparison Tool')
    parser.add_argument('--project', '-p', help='Project directory to scan')
    parser.add_argument('--create-test', action='store_true', help='Create test project')
    
    args = parser.parse_args()
    
    if args.create_test:
        project_path = create_test_project()
    elif args.project:
        project_path = args.project
    else:
        print("Please specify --project or --create-test")
        sys.exit(1)
    
    if not os.path.exists(project_path):
        print(f"❌ Project path does not exist: {project_path}")
        sys.exit(1)
    
    # Run comparison
    traditional_results, ml_results = compare_sca_approaches(project_path)
    
    print("\n" + "=" * 60)
    print("🎉 COMPARISON COMPLETE!")
    print("=" * 60)
    print("\nRecommendation:")
    if ml_results['total_vulnerabilities'] > traditional_results['total_vulnerabilities']:
        print("✅ Use ML-Enhanced SCA for better coverage and predictive capabilities")
    else:
        print("✅ Both approaches found the same vulnerabilities - choose based on your needs")
    
    print("\nWhen to use each approach:")
    print("🔧 Traditional SCA:")
    print("  - When you need fast, reliable detection of known vulnerabilities")
    print("  - When you have limited computational resources")
    print("  - When you trust your CVE database completely")
    
    print("\n🤖 ML-Enhanced SCA:")
    print("  - When you want to catch unknown/predicted vulnerabilities")
    print("  - When you need priority scoring for remediation")
    print("  - When you want to learn from patterns in your codebase")
    print("  - When you have computational resources for ML inference")

if __name__ == "__main__":
    main()
