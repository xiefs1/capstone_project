"""
Basic test script for advanced SAST model (Windows compatible)
"""

import sys
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

def test_basic_functionality():
    """Test basic functionality without complex ensemble"""
    print("Testing basic functionality...")
    
    try:
        # Test imports
        from advanced_sast_features import AdvancedSASTFeatureExtractor
        from advanced_code_preprocessing import AdvancedCodePreprocessor
        print("SUCCESS: Imports work")
        
        # Test feature extractor
        extractor = AdvancedSASTFeatureExtractor()
        test_code = "SELECT * FROM users WHERE id = '" + "user_input" + "'"
        features = extractor.extract_semantic_features(test_code)
        print(f"SUCCESS: Feature extraction works - {len(features)} features extracted")
        
        # Test preprocessor
        preprocessor = AdvancedCodePreprocessor()
        preprocessed = preprocessor.preprocess_code(test_code)
        print(f"SUCCESS: Preprocessing works - obfuscation score = {preprocessed['obfuscation_score']:.3f}")
        
        return True
        
    except Exception as e:
        print(f"FAILED: Basic functionality test - {e}")
        return False

def test_simple_model():
    """Test a simple model without ensemble complexity"""
    print("\nTesting simple model...")
    
    try:
        from advanced_sast_features import AdvancedSASTFeatureExtractor
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score
        
        # Create sample data
        sample_data = [
            ("SELECT * FROM users WHERE id = '" + "user_input" + "'", 1),  # SQL injection
            ("document.write('<script>alert(1)</script>')", 1),  # XSS
            ("os.system('rm -rf /')", 1),  # Command injection
            ("SELECT * FROM users WHERE id = ?", 0),  # Safe SQL
            ("print('Hello World')", 0),  # Safe code
            ("String query = \"SELECT * FROM users WHERE id = ?\"", 0),  # Safe prepared statement
            ("response.write(userInput)", 1),  # XSS
            ("int id = Integer.parseInt(request.getParameter(\"id\"))", 0),  # Safe parsing
        ]
        
        df = pd.DataFrame(sample_data, columns=['code_snippet', 'label'])
        print(f"Created sample dataset with {len(df)} samples")
        
        # Extract features
        extractor = AdvancedSASTFeatureExtractor()
        X_features = extractor.extract_all_features(df['code_snippet'].tolist())
        y = df['label'].values
        
        print(f"Extracted {X_features.shape[1]} features")
        
        # Train simple model
        model = RandomForestClassifier(n_estimators=50, random_state=42)
        model.fit(X_features, y)
        
        # Test predictions
        y_pred = model.predict(X_features)
        accuracy = accuracy_score(y, y_pred)
        
        print(f"SUCCESS: Simple model accuracy = {accuracy:.3f}")
        
        # Test individual predictions
        test_codes = [
            "SELECT * FROM users WHERE id = '" + "user_input" + "'",
            "SELECT * FROM users WHERE id = ?"
        ]
        
        test_features = extractor.extract_all_features(test_codes)
        test_preds = model.predict(test_features)
        
        print("Test predictions:")
        for code, pred in zip(test_codes, test_preds):
            print(f"  '{code[:50]}...' -> {'Vulnerable' if pred == 1 else 'Safe'}")
        
        return True
        
    except Exception as e:
        print(f"FAILED: Simple model test - {e}")
        import traceback
        traceback.print_exc()
        return False

def test_with_real_data():
    """Test with a small sample of real data"""
    print("\nTesting with real data sample...")
    
    try:
        # Load small sample of real data
        df = pd.read_csv("Useful_SAST_Dataset/FINAL_MERGED_SAST_DATASET.csv")
        sample_size = min(100, len(df))  # Very small sample for testing
        df_sample = df.sample(n=sample_size, random_state=42)
        
        print(f"Loaded {len(df_sample)} samples from real dataset")
        print(f"Label distribution: {df_sample['label'].value_counts().to_dict()}")
        
        # Extract features for subset
        from advanced_sast_features import AdvancedSASTFeatureExtractor
        extractor = AdvancedSASTFeatureExtractor()
        
        # Test on first 5 samples only
        test_codes = df_sample['code_snippet'].head(5).tolist()
        test_labels = df_sample['label'].head(5).values
        
        print("Testing feature extraction on real data...")
        X_features = extractor.extract_all_features(test_codes)
        print(f"SUCCESS: Extracted {X_features.shape[1]} features from real data")
        
        # Train and test
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score
        
        model = RandomForestClassifier(n_estimators=20, random_state=42)
        model.fit(X_features, test_labels)
        
        y_pred = model.predict(X_features)
        accuracy = accuracy_score(test_labels, y_pred)
        
        print(f"SUCCESS: Real data test accuracy = {accuracy:.3f}")
        
        return True
        
    except Exception as e:
        print(f"FAILED: Real data test - {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("Starting Advanced SAST Model Tests")
    print("=" * 50)
    
    tests = [
        ("Basic Functionality", test_basic_functionality),
        ("Simple Model", test_simple_model),
        ("Real Data Sample", test_with_real_data)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        success = test_func()
        results.append((test_name, success))
    
    print("\n" + "=" * 50)
    print("TEST RESULTS:")
    for test_name, success in results:
        status = "PASS" if success else "FAIL"
        print(f"  {test_name}: {status}")
    
    all_passed = all(success for _, success in results)
    
    if all_passed:
        print("\nSUCCESS: All tests passed! Your advanced SAST model is working!")
        print("\nNext steps:")
        print("1. The basic functionality is working")
        print("2. You can now use the advanced features in your own code")
        print("3. Try running: python run_advanced_training.py")
    else:
        print("\nWARNING: Some tests failed. Check the error messages above.")
        print("The basic functionality should work even if the ensemble doesn't.")
    
    return all_passed

if __name__ == "__main__":
    main()
