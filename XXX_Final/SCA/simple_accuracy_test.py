"""
Simple SCA Accuracy Test
Tests ML-Enhanced SCA model for accuracy metrics
"""

import os
import sys
from simple_sca_ml import SimpleMLSCA

def test_ml_sca_accuracy():
    """Test ML-enhanced SCA accuracy with known packages"""
    
    print("ML-ENHANCED SCA ACCURACY TESTING")
    print("=" * 60)
    
    # Initialize ML SCA
    ml_sca = SimpleMLSCA()
    ml_sca.train_simple_model()
    
    # Test data with known vulnerabilities
    test_packages = [
        # Known vulnerable packages (should be detected)
        {'package': 'django', 'version': '1.11.0', 'expected': True, 'severity': 'high'},
        {'package': 'flask', 'version': '0.12.0', 'expected': True, 'severity': 'medium'},
        {'package': 'requests', 'version': '2.19.0', 'expected': True, 'severity': 'high'},
        {'package': 'numpy', 'version': '1.15.0', 'expected': True, 'severity': 'medium'},
        
        # Safe packages (should not be detected as vulnerable)
        {'package': 'pandas', 'version': '1.0.0', 'expected': False, 'severity': 'none'},
        {'package': 'matplotlib', 'version': '3.0.0', 'expected': False, 'severity': 'none'},
        {'package': 'scikit-learn', 'version': '1.0.0', 'expected': False, 'severity': 'none'},
        {'package': 'tensorflow', 'version': '2.0.0', 'expected': False, 'severity': 'none'},
    ]
    
    print("Testing ML-Enhanced SCA on known packages...")
    print("-" * 60)
    
    results = {
        'correct_predictions': 0,
        'total_predictions': 0,
        'detailed_results': [],
        'confidences': []
    }
    
    # Test each package
    for pkg in test_packages:
        ml_prediction = ml_sca.predict_vulnerability(pkg['package'], pkg['version'])
        is_vulnerable = ml_prediction['is_vulnerable']
        confidence = ml_prediction['confidence']
        
        correct = is_vulnerable == pkg['expected']
        results['correct_predictions'] += 1 if correct else 0
        results['total_predictions'] += 1
        results['confidences'].append(confidence)
        
        status = "✅ CORRECT" if correct else "❌ WRONG"
        print(f"{pkg['package']} ({pkg['version']}): {status}")
        print(f"  Expected: {pkg['expected']}, Predicted: {is_vulnerable}")
        print(f"  Confidence: {confidence:.2%}")
        print(f"  Severity: {pkg['severity']}")
        print()
        
        results['detailed_results'].append({
            'package': pkg['package'],
            'version': pkg['version'],
            'expected': pkg['expected'],
            'predicted': is_vulnerable,
            'correct': correct,
            'confidence': confidence
        })
    
    # Calculate metrics
    results['accuracy'] = results['correct_predictions'] / results['total_predictions']
    results['avg_confidence'] = sum(results['confidences']) / len(results['confidences'])
    
    # Calculate precision, recall, F1
    true_positives = sum(1 for r in results['detailed_results'] if r['expected'] and r['predicted'])
    false_positives = sum(1 for r in results['detailed_results'] if not r['expected'] and r['predicted'])
    false_negatives = sum(1 for r in results['detailed_results'] if r['expected'] and not r['predicted'])
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # Display results
    print("=" * 60)
    print("SCA ACCURACY RESULTS")
    print("=" * 60)
    print(f"Total Packages Tested: {results['total_predictions']}")
    print(f"Correct Predictions: {results['correct_predictions']}")
    print(f"Accuracy: {results['accuracy']:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall: {recall:.2%}")
    print(f"F1-Score: {f1_score:.2%}")
    print(f"Average ML Confidence: {results['avg_confidence']:.2%}")
    
    print(f"\nDetailed Breakdown:")
    print(f"True Positives: {true_positives}")
    print(f"False Positives: {false_positives}")
    print(f"False Negatives: {false_negatives}")
    
    # Confidence analysis
    high_confidence = sum(1 for c in results['confidences'] if c > 0.8)
    medium_confidence = sum(1 for c in results['confidences'] if 0.6 <= c <= 0.8)
    low_confidence = sum(1 for c in results['confidences'] if c < 0.6)
    
    print(f"\nConfidence Distribution:")
    print(f"High Confidence (>80%): {high_confidence}")
    print(f"Medium Confidence (60-80%): {medium_confidence}")
    print(f"Low Confidence (<60%): {low_confidence}")
    
    return results

if __name__ == "__main__":
    test_ml_sca_accuracy()

