"""
GitLab SAST Scanner Integration
Automatically scans code for vulnerabilities in GitLab CI/CD pipeline
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd
import joblib

# Add the parent directory to path to import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from advanced_sast_features import AdvancedSASTFeatureExtractor
from advanced_code_preprocessing import AdvancedCodePreprocessor
from vulnerability_remediation import VulnerabilityRemediator

class GitLabSASTScanner:
    """
    GitLab SAST Scanner that integrates with CI/CD pipeline
    """
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.feature_extractor = None
        self.remediator = VulnerabilityRemediator()
        self.scan_results = []
        
        # Load model if path provided
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
    
    def load_model(self, model_path: str):
        """Load the trained SAST model"""
        try:
            model_data = joblib.load(model_path)
            self.model = model_data['model']
            self.feature_extractor = model_data['feature_extractor']
            print(f"✅ Model loaded from {model_path}")
        except Exception as e:
            print(f"❌ Failed to load model: {e}")
            print("Using basic pattern matching as fallback")
            self.model = None
            self.feature_extractor = None
    
    def scan_file(self, file_path: str, file_content: str) -> Dict[str, Any]:
        """Scan a single file for vulnerabilities"""
        result = {
            'file': file_path,
            'vulnerabilities': [],
            'total_vulnerabilities': 0,
            'severity_counts': {'High': 0, 'Medium': 0, 'Low': 0}
        }
        
        try:
            # If model is available, use advanced analysis
            if self.model and self.feature_extractor:
                # Extract features
                features = self.feature_extractor.extract_all_features([file_content])
                features = features.fillna(0)
                
                # Get prediction
                prediction = self.model.predict(features)[0]
                confidence = max(self.model.predict_proba(features)[0])
                
                if prediction == 1:  # Vulnerable
                    # Get remediation details
                    remediation = self.remediator.generate_remediation(file_content)
                    
                    if remediation:
                        vulnerability = {
                            'type': remediation.vulnerability_type,
                            'severity': remediation.severity,
                            'confidence': float(confidence),
                            'description': remediation.description,
                            'line': self._find_vulnerable_line(file_content),
                            'remediation': {
                                'fixed_code': remediation.fixed_code,
                                'explanation': remediation.explanation,
                                'best_practices': remediation.best_practices
                            }
                        }
                        result['vulnerabilities'].append(vulnerability)
                        result['severity_counts'][remediation.severity] += 1
            else:
                # Fallback to basic pattern matching
                vulnerabilities = self._basic_pattern_scan(file_content)
                for vuln in vulnerabilities:
                    result['vulnerabilities'].append(vuln)
                    result['severity_counts'][vuln['severity']] += 1
            
            result['total_vulnerabilities'] = len(result['vulnerabilities'])
            
        except Exception as e:
            print(f"❌ Error scanning {file_path}: {e}")
            result['error'] = str(e)
        
        return result
    
    def _basic_pattern_scan(self, content: str) -> List[Dict[str, Any]]:
        """Basic pattern-based vulnerability scanning as fallback"""
        vulnerabilities = []
        
        # SQL Injection patterns
        sql_patterns = [
            (r'SELECT.*\+.*["\']', 'SQL Injection', 'High'),
            (r'INSERT.*\+.*["\']', 'SQL Injection', 'High'),
            (r'UPDATE.*\+.*["\']', 'SQL Injection', 'High'),
            (r'DELETE.*\+.*["\']', 'SQL Injection', 'High'),
        ]
        
        # XSS patterns
        xss_patterns = [
            (r'innerHTML\s*=', 'XSS', 'Medium'),
            (r'document\.write\s*\(', 'XSS', 'Medium'),
            (r'Response\.Write\s*\(', 'XSS', 'Medium'),
        ]
        
        # Command Injection patterns
        cmd_patterns = [
            (r'os\.system\s*\(', 'Command Injection', 'High'),
            (r'subprocess\.(run|call|Popen)\s*\(', 'Command Injection', 'High'),
            (r'exec\s*\(', 'Command Injection', 'High'),
        ]
        
        all_patterns = sql_patterns + xss_patterns + cmd_patterns
        
        for pattern, vuln_type, severity in all_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                vulnerabilities.append({
                    'type': vuln_type,
                    'severity': severity,
                    'confidence': 0.7,  # Basic confidence
                    'description': f'Potential {vuln_type} vulnerability detected',
                    'line': 1,  # Basic line detection
                    'remediation': {
                        'fixed_code': f'// TODO: Fix {vuln_type} vulnerability',
                        'explanation': f'Review code for {vuln_type} patterns',
                        'best_practices': ['Validate and sanitize input', 'Use secure coding practices']
                    }
                })
        
        return vulnerabilities
    
    def _find_vulnerable_line(self, content: str) -> int:
        """Find the line number where vulnerability likely occurs"""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if any(keyword in line.lower() for keyword in ['select', 'insert', 'update', 'delete', 'innerhtml', 'document.write', 'os.system']):
                return i
        return 1
    
    def scan_directory(self, directory: str, extensions: List[str] = None) -> Dict[str, Any]:
        """Scan entire directory for vulnerabilities"""
        if extensions is None:
            extensions = ['.py', '.java', '.js', '.php', '.cs', '.cpp', '.c', '.h']
        
        scan_results = {
            'total_files': 0,
            'vulnerable_files': 0,
            'total_vulnerabilities': 0,
            'severity_counts': {'High': 0, 'Medium': 0, 'Low': 0},
            'files': []
        }
        
        print(f"🔍 Scanning directory: {directory}")
        
        for root, dirs, files in os.walk(directory):
            # Skip common directories to ignore
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.pytest_cache', 'venv', 'env']]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, directory)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        print(f"  📄 Scanning: {relative_path}")
                        result = self.scan_file(relative_path, content)
                        scan_results['files'].append(result)
                        scan_results['total_files'] += 1
                        
                        if result['total_vulnerabilities'] > 0:
                            scan_results['vulnerable_files'] += 1
                            scan_results['total_vulnerabilities'] += result['total_vulnerabilities']
                            
                            for severity, count in result['severity_counts'].items():
                                scan_results['severity_counts'][severity] += count
                    
                    except Exception as e:
                        print(f"  ❌ Error reading {relative_path}: {e}")
        
        return scan_results
    
    def generate_gitlab_report(self, scan_results: Dict[str, Any], output_file: str = "sast-report.json"):
        """Generate GitLab-compatible SAST report"""
        
        # Convert to GitLab SAST format
        gitlab_report = {
            "version": "15.0.0",
            "vulnerabilities": [],
            "remediations": []
        }
        
        for file_result in scan_results['files']:
            for vuln in file_result['vulnerabilities']:
                gitlab_vuln = {
                    "id": f"sast_{hash(file_result['file'] + vuln['type'])}",
                    "category": "sast",
                    "name": vuln['type'],
                    "message": vuln['description'],
                    "description": vuln['description'],
                    "severity": vuln['severity'].lower(),
                    "confidence": "High" if vuln['confidence'] > 0.8 else "Medium" if vuln['confidence'] > 0.6 else "Low",
                    "scanner": {
                        "id": "custom-sast-scanner",
                        "name": "Advanced SAST Scanner"
                    },
                    "location": {
                        "file": file_result['file'],
                        "start_line": vuln['line'],
                        "end_line": vuln['line']
                    },
                    "remediation": {
                        "summary": vuln['remediation']['explanation'],
                        "diff": vuln['remediation']['fixed_code']
                    }
                }
                gitlab_report["vulnerabilities"].append(gitlab_vuln)
        
        # Save report
        with open(output_file, 'w') as f:
            json.dump(gitlab_report, f, indent=2)
        
        print(f"📊 GitLab SAST report saved to: {output_file}")
        return output_file
    
    def generate_summary_report(self, scan_results: Dict[str, Any]):
        """Generate human-readable summary report"""
        print("\n" + "="*60)
        print("🔒 SAST SCAN SUMMARY")
        print("="*60)
        print(f"Total files scanned: {scan_results['total_files']}")
        print(f"Vulnerable files: {scan_results['vulnerable_files']}")
        print(f"Total vulnerabilities: {scan_results['total_vulnerabilities']}")
        print(f"\nSeverity breakdown:")
        print(f"  🔴 High: {scan_results['severity_counts']['High']}")
        print(f"  🟡 Medium: {scan_results['severity_counts']['Medium']}")
        print(f"  🟢 Low: {scan_results['severity_counts']['Low']}")
        
        if scan_results['vulnerable_files'] > 0:
            print(f"\n📋 Vulnerable files:")
            for file_result in scan_results['files']:
                if file_result['total_vulnerabilities'] > 0:
                    print(f"  📄 {file_result['file']} ({file_result['total_vulnerabilities']} vulnerabilities)")
                    for vuln in file_result['vulnerabilities']:
                        print(f"    - {vuln['type']} ({vuln['severity']}) - Line {vuln['line']}")
        
        print("="*60)


def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='GitLab SAST Scanner')
    parser.add_argument('--directory', '-d', required=True, help='Directory to scan')
    parser.add_argument('--model', '-m', help='Path to trained model file')
    parser.add_argument('--output', '-o', default='sast-report.json', help='Output file for GitLab report')
    parser.add_argument('--extensions', '-e', nargs='+', default=['.py', '.java', '.js', '.php', '.cs'], help='File extensions to scan')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = GitLabSASTScanner(args.model)
    
    # Scan directory
    scan_results = scanner.scan_directory(args.directory, args.extensions)
    
    # Generate reports
    scanner.generate_gitlab_report(scan_results, args.output)
    scanner.generate_summary_report(scan_results)
    
    # Exit with appropriate code
    if scan_results['total_vulnerabilities'] > 0:
        print(f"\n⚠️  Found {scan_results['total_vulnerabilities']} vulnerabilities!")
        sys.exit(1)  # Fail the pipeline if vulnerabilities found
    else:
        print("\n✅ No vulnerabilities found!")
        sys.exit(0)


if __name__ == "__main__":
    import re
    main()
