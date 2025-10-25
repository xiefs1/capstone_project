"""
Basic SCA Test - Test the ML-enhanced SCA model without Unicode
"""

import os
import sys
from ml_enhanced_sca import MLEnhancedSCA

def create_test_project():
    """Create a simple test project"""
    test_project = "test_sca_basic"
    os.makedirs(test_project, exist_ok=True)
    
    # Python requirements.txt with vulnerable packages
    requirements_content = """django==1.11.0
flask==0.12.0
requests==2.19.0
numpy==1.15.0
"""
    
    with open(f"{test_project}/requirements.txt", "w") as f:
        f.write(requirements_content)
    
    print(f"Test project created: {test_project}")
    return test_project

def test_ml_enhanced_sca():
    """Test the ML-enhanced SCA model"""
    print("Testing ML-Enhanced SCA Model")
    print("=" * 50)
    
    # Create test project
    project_path = create_test_project()
    
    # Initialize ML-enhanced SCA
    ml_sca = MLEnhancedSCA()
    
    # Train models
    print("Training ML models...")
    ml_sca.train_models()
    
    # Scan project
    print("Scanning project...")
    scan_results = ml_sca.scan_project_ml_enhanced(project_path)
    
    # Generate report
    ml_sca.generate_ml_enhanced_report(scan_results)
    
    # Save models
    ml_sca.save_models()
    
    print("\n" + "=" * 50)
    print("ML-Enhanced SCA Test Complete!")
    print("=" * 50)
    
    return scan_results

if __name__ == "__main__":
    test_ml_enhanced_sca()
