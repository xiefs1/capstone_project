# 📦 SCA (Software Composition Analysis)

## 📁 **Files in this folder:**

- `sca_vulnerability_detector.py` - Traditional rule-based SCA
- `ml_enhanced_sca.py` - Advanced ML-enhanced SCA
- `simple_sca_ml.py` - Simplified ML-enhanced SCA (recommended)
- `sca_comparison.py` - Compare traditional vs ML approaches
- `test_sca_basic.py` - Basic functionality tests

## 🚀 **Quick Start:**

### **1. Traditional SCA (Rule-based):**
```bash
python sca_vulnerability_detector.py --project . --output sca-report.json
```

### **2. ML-Enhanced SCA (Recommended):**
```bash
python simple_sca_ml.py --project . --train
```

### **3. Compare Both Approaches:**
```bash
python sca_comparison.py --create-test
```

## 🎯 **What it does:**

- **Detects vulnerabilities** in dependencies and third-party libraries
- **Predicts unknown vulnerabilities** using machine learning
- **Prioritizes remediation** based on risk scores
- **Supports multiple languages** (Python, Java, JavaScript, PHP)
- **Provides confidence scores** for predictions

## 📊 **Two Approaches:**

### **Traditional SCA:**
- ✅ **Fast and reliable** - Instant detection
- ✅ **Low resource usage** - No ML training
- ✅ **High accuracy** for known vulnerabilities
- ❌ **Limited coverage** - Only known CVE database

### **ML-Enhanced SCA:**
- ✅ **Predictive capabilities** - Finds unknown vulnerabilities
- ✅ **Priority scoring** - Ranks by importance
- ✅ **Confidence scores** - Shows prediction certainty
- ✅ **Comprehensive coverage** - Known + predicted
- ❌ **Higher resource usage** - Requires ML training

## 🔧 **Usage Examples:**

### **Traditional SCA:**
```bash
python sca_vulnerability_detector.py --project . --output sca-report.json
```

### **ML-Enhanced SCA:**
```bash
# Train and scan
python simple_sca_ml.py --project . --train

# Use existing model
python simple_sca_ml.py --project . --model models/simple_ml_sca.joblib
```

## 📈 **Test Results:**

```
Vulnerable dependencies (sorted by priority):
  django (1.11.0) - HIGH
      Priority Score: 16.45
      ML Confidence: 0.88
      CVE: CVE-2019-6975
      CVSS: 8.1

  requests (2.19.0) - HIGH
      Priority Score: 15.90
      ML Confidence: 0.84
      CVE: CVE-2018-18074
      CVSS: 7.4
```

## 🎉 **Key Features:**

- ✅ **Dependency Scanning** - Finds vulnerable packages
- ✅ **ML Predictions** - Predicts unknown vulnerabilities
- ✅ **Priority Scoring** - Ranks issues by importance
- ✅ **Confidence Scores** - Shows prediction certainty
- ✅ **Multi-language Support** - Python, Java, JavaScript, PHP
- ✅ **CVE Integration** - Links to known vulnerabilities

**Your SCA tool is now an intelligent dependency analysis system!** 🛡️

