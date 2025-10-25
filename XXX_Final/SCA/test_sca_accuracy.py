"""
SCA Accuracy Testing Script
Tests both Traditional and ML-Enhanced SCA models for accuracy metrics
"""

import os
import sys
import json
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.metrics import confusion_matrix, classification_report
from simple_sca_ml import SimpleMLSCA
from sca_vulnerability_detector import SCAVulnerabilityDetector

def test_sca_accuracy():
    """Test SCA accuracy with known vulnerable and safe packages"""
    
    print("SCA ACCURACY TESTING")
    print("=" * 60)
    
    # Test data with known vulnerabilities
    test_data = {
        'vulnerable_packages': [
            {'package': 'django', 'version': '1.11.0', 'expected': True, 'severity': 'high'},
            {'package': 'flask', 'version': '0.12.0', 'expected': True, 'severity': 'medium'},
            {'package': 'requests', 'version': '2.19.0', 'expected': True, 'severity': 'high'},
            {'package': 'numpy', 'version': '1.15.0', 'expected': True, 'severity': 'medium'},
        ],
        'safe_packages': [
            {'package': 'pandas', 'version': '1.0.0', 'expected': False, 'severity': 'none'},
            {'package': 'matplotlib', 'version': '3.0.0', 'expected': False, 'severity': 'none'},
            {'package': 'scikit-learn', 'version': '1.0.0', 'expected': False, 'severity': 'none'},
            {'package': 'tensorflow', 'version': '2.0.0', 'expected': False, 'severity': 'none'},
        ]
    }
    
    # Test Traditional SCA
    print("\n1. TRADITIONAL SCA (Rule-based) Testing:")
    print("-" * 40)
    
    traditional_sca = SCAVulnerabilityDetector()
    traditional_results = test_traditional_sca(traditional_sca, test_data)
    
    # Test ML-Enhanced SCA
    print("\n2. ML-ENHANCED SCA Testing:")
    print("-" * 40)
    
    ml_sca = SimpleMLSCA()
    ml_sca.train_simple_model()
    ml_results = test_ml_sca(ml_sca, test_data)
    
    # Generate confusion matrices
    print("\n3. CONFUSION MATRICES:")
    print("-" * 40)
    
    # Traditional SCA confusion matrix
    traditional_y_true = [r['expected'] for r in traditional_results['detailed_results']]
    traditional_y_pred = [r['predicted'] for r in traditional_results['detailed_results']]
    traditional_cm = confusion_matrix(traditional_y_true, traditional_y_pred)
    
    print("Traditional SCA Confusion Matrix:")
    print("                Predicted")
    print("                Safe  Vulnerable")
    print(f"Actual Safe    {traditional_cm[0,0]:4d}  {traditional_cm[0,1]:4d}")
    print(f"       Vulnerable {traditional_cm[1,0]:4d}  {traditional_cm[1,1]:4d}")
    
    # ML-Enhanced SCA confusion matrix
    ml_y_true = [r['expected'] for r in ml_results['detailed_results']]
    ml_y_pred = [r['predicted'] for r in ml_results['detailed_results']]
    ml_cm = confusion_matrix(ml_y_true, ml_y_pred)
    
    print("\nML-Enhanced SCA Confusion Matrix:")
    print("                Predicted")
    print("                Safe  Vulnerable")
    print(f"Actual Safe    {ml_cm[0,0]:4d}  {ml_cm[0,1]:4d}")
    print(f"       Vulnerable {ml_cm[1,0]:4d}  {ml_cm[1,1]:4d}")
    
    # Compare results
    print("\n4. COMPARISON SUMMARY:")
    print("-" * 40)
    print(f"Traditional SCA:")
    print(f"  Accuracy: {traditional_results['accuracy']:.2%}")
    print(f"  Precision: {traditional_results['precision']:.2%}")
    print(f"  Recall: {traditional_results['recall']:.2%}")
    print(f"  F1-Score: {traditional_results['f1_score']:.2%}")
    
    print(f"\nML-Enhanced SCA:")
    print(f"  Accuracy: {ml_results['accuracy']:.2%}")
    print(f"  Precision: {ml_results['precision']:.2%}")
    print(f"  Recall: {ml_results['recall']:.2%}")
    print(f"  F1-Score: {ml_results['f1_score']:.2%}")
    print(f"  Average ML Confidence: {ml_results['avg_confidence']:.2%}")
    
    # Performance comparison
    print(f"\n5. PERFORMANCE COMPARISON:")
    print("-" * 40)
    accuracy_improvement = ml_results['accuracy'] - traditional_results['accuracy']
    f1_improvement = ml_results['f1_score'] - traditional_results['f1_score']
    
    print(f"Accuracy Improvement: {accuracy_improvement:+.2%}")
    print(f"F1-Score Improvement: {f1_improvement:+.2%}")
    
    if accuracy_improvement > 0:
        print("✅ ML-Enhanced SCA performs better")
    elif accuracy_improvement < 0:
        print("❌ Traditional SCA performs better")
    else:
        print("🤝 Both approaches perform equally")
    
    # Detailed results
    print(f"\n6. DETAILED RESULTS:")
    print("-" * 40)
    print("Traditional SCA Results:")
    for result in traditional_results['detailed_results']:
        status = "✅ CORRECT" if result['correct'] else "❌ WRONG"
        print(f"  {result['package']} ({result['version']}): {status}")
        if not result['correct']:
            print(f"    Expected: {result['expected']}, Got: {result['predicted']}")
    
    print("\nML-Enhanced SCA Results:")
    for result in ml_results['detailed_results']:
        status = "✅ CORRECT" if result['correct'] else "❌ WRONG"
        print(f"  {result['package']} ({result['version']}): {status} (Confidence: {result['confidence']:.2%})")
        if not result['correct']:
            print(f"    Expected: {result['expected']}, Got: {result['predicted']}")
    
    # Save metrics to CSV
    save_metrics_to_csv(traditional_results, ml_results, traditional_cm, ml_cm)
    
    return traditional_results, ml_results

def test_traditional_sca(sca, test_data):
    """Test traditional SCA accuracy"""
    results = {
        'correct_predictions': 0,
        'total_predictions': 0,
        'detailed_results': []
    }
    
    # Test vulnerable packages
    for pkg in test_data['vulnerable_packages']:
        # Check if package is in vulnerable database
        is_vulnerable = False
        if pkg['package'].lower() in sca.vulnerable_packages:
            versions = sca.vulnerable_packages[pkg['package'].lower()]
            if pkg['version'] in versions:
                is_vulnerable = True
        
        correct = is_vulnerable == pkg['expected']
        results['correct_predictions'] += 1 if correct else 0
        results['total_predictions'] += 1
        
        results['detailed_results'].append({
            'package': pkg['package'],
            'version': pkg['version'],
            'expected': pkg['expected'],
            'predicted': is_vulnerable,
            'correct': correct,
            'confidence': 1.0 if is_vulnerable else 0.0
        })
    
    # Test safe packages
    for pkg in test_data['safe_packages']:
        # Check if package is in vulnerable database
        is_vulnerable = False
        if pkg['package'].lower() in sca.vulnerable_packages:
            versions = sca.vulnerable_packages[pkg['package'].lower()]
            if pkg['version'] in versions:
                is_vulnerable = True
        
        correct = is_vulnerable == pkg['expected']
        results['correct_predictions'] += 1 if correct else 0
        results['total_predictions'] += 1
        
        results['detailed_results'].append({
            'package': pkg['package'],
            'version': pkg['version'],
            'expected': pkg['expected'],
            'predicted': is_vulnerable,
            'correct': correct,
            'confidence': 1.0 if is_vulnerable else 0.0
        })
    
    # Calculate metrics
    results['accuracy'] = results['correct_predictions'] / results['total_predictions']
    
    # Calculate precision, recall, F1
    true_positives = sum(1 for r in results['detailed_results'] if r['expected'] and r['predicted'])
    false_positives = sum(1 for r in results['detailed_results'] if not r['expected'] and r['predicted'])
    false_negatives = sum(1 for r in results['detailed_results'] if r['expected'] and not r['predicted'])
    
    results['precision'] = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    results['recall'] = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    results['f1_score'] = 2 * (results['precision'] * results['recall']) / (results['precision'] + results['recall']) if (results['precision'] + results['recall']) > 0 else 0
    
    return results

def test_ml_sca(sca, test_data):
    """Test ML-enhanced SCA accuracy"""
    results = {
        'correct_predictions': 0,
        'total_predictions': 0,
        'detailed_results': [],
        'confidences': []
    }
    
    # Test vulnerable packages
    for pkg in test_data['vulnerable_packages']:
        ml_prediction = sca.predict_vulnerability(pkg['package'], pkg['version'])
        is_vulnerable = ml_prediction['is_vulnerable']
        confidence = ml_prediction['confidence']
        
        correct = is_vulnerable == pkg['expected']
        results['correct_predictions'] += 1 if correct else 0
        results['total_predictions'] += 1
        results['confidences'].append(confidence)
        
        results['detailed_results'].append({
            'package': pkg['package'],
            'version': pkg['version'],
            'expected': pkg['expected'],
            'predicted': is_vulnerable,
            'correct': correct,
            'confidence': confidence
        })
    
    # Test safe packages
    for pkg in test_data['safe_packages']:
        ml_prediction = sca.predict_vulnerability(pkg['package'], pkg['version'])
        is_vulnerable = ml_prediction['is_vulnerable']
        confidence = ml_prediction['confidence']
        
        correct = is_vulnerable == pkg['expected']
        results['correct_predictions'] += 1 if correct else 0
        results['total_predictions'] += 1
        results['confidences'].append(confidence)
        
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
    
    results['precision'] = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    results['recall'] = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    results['f1_score'] = 2 * (results['precision'] * results['recall']) / (results['precision'] + results['recall']) if (results['precision'] + results['recall']) > 0 else 0
    
    return results

def save_metrics_to_csv(traditional_results, ml_results, traditional_cm, ml_cm):
    """Save performance metrics to CSV file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create metrics summary
    metrics_data = {
        'Model': ['Traditional SCA', 'ML-Enhanced SCA'],
        'Accuracy': [traditional_results['accuracy'], ml_results['accuracy']],
        'Precision': [traditional_results['precision'], ml_results['precision']],
        'Recall': [traditional_results['recall'], ml_results['recall']],
        'F1_Score': [traditional_results['f1_score'], ml_results['f1_score']],
        'True_Positives': [traditional_cm[1,1], ml_cm[1,1]],
        'False_Positives': [traditional_cm[0,1], ml_cm[0,1]],
        'True_Negatives': [traditional_cm[0,0], ml_cm[0,0]],
        'False_Negatives': [traditional_cm[1,0], ml_cm[1,0]],
        'Total_Predictions': [traditional_results['total_predictions'], ml_results['total_predictions']],
        'Correct_Predictions': [traditional_results['correct_predictions'], ml_results['correct_predictions']]
    }
    
    # Add ML-specific metrics
    if 'avg_confidence' in ml_results:
        metrics_data['Average_Confidence'] = [0.0, ml_results['avg_confidence']]
    
    # Create DataFrame and save
    df_metrics = pd.DataFrame(metrics_data)
    metrics_file = f"sca_performance_metrics_{timestamp}.csv"
    df_metrics.to_csv(metrics_file, index=False)
    
    # Create detailed results CSV
    detailed_data = []
    
    # Traditional SCA results
    for result in traditional_results['detailed_results']:
        detailed_data.append({
            'Model': 'Traditional SCA',
            'Package': result['package'],
            'Version': result['version'],
            'Expected': result['expected'],
            'Predicted': result['predicted'],
            'Correct': result['correct'],
            'Confidence': result['confidence']
        })
    
    # ML-Enhanced SCA results
    for result in ml_results['detailed_results']:
        detailed_data.append({
            'Model': 'ML-Enhanced SCA',
            'Package': result['package'],
            'Version': result['version'],
            'Expected': result['expected'],
            'Predicted': result['predicted'],
            'Correct': result['correct'],
            'Confidence': result['confidence']
        })
    
    df_detailed = pd.DataFrame(detailed_data)
    detailed_file = f"sca_detailed_results_{timestamp}.csv"
    df_detailed.to_csv(detailed_file, index=False)
    
    print(f"\n📊 Performance metrics saved to: {metrics_file}")
    print(f"📊 Detailed results saved to: {detailed_file}")
    
    return metrics_file, detailed_file

if __name__ == "__main__":
    test_sca_accuracy()

