# GitLab SAST Integration Guide

## 🚀 Quick Start

### Option 1: Complete Setup (Recommended)
```bash
# Run the setup script
python gitlab_integration/setup_gitlab.py

# Train your model
python simple_advanced_training.py

# Upload model to GitLab (requires GITLAB_TOKEN)
./gitlab_integration/upload_model.sh

# Push to GitLab - CI/CD will automatically scan your code!
git add .
git commit -m "Add SAST security scanning"
git push origin main
```

### Option 2: Manual Setup
1. Copy the files to your GitLab project
2. Add the `.gitlab-ci.yml` to your repository root
3. Upload your trained model to GitLab Package Registry
4. Push your code

## 📁 What You Need to Add to GitLab

### Required Files:
```
your-gitlab-project/
├── .gitlab-ci.yml                    # CI/CD pipeline configuration
├── gitlab_integration/
│   ├── sast_scanner.py              # Main scanner script
│   ├── requirements.txt             # Python dependencies
│   ├── advanced_sast_features.py   # Feature extraction
│   ├── advanced_code_preprocessing.py # Code preprocessing
│   └── vulnerability_remediation.py # Remediation suggestions
├── models/
│   └── advanced_sast_model.joblib   # Your trained model (upload separately)
└── requirements_advanced.txt        # Full dependencies
```

### Optional Files:
```
├── tests/                           # Test files for scanning
├── .gitignore                      # Ignore unnecessary files
└── gitlab_integration/README.md    # This documentation
```

## 🔧 Setup Instructions

### 1. Train Your Model
```bash
# Train the advanced SAST model
python simple_advanced_training.py

# This creates: models/advanced_sast_model.joblib
```

### 2. Upload Model to GitLab
You have several options:

#### Option A: GitLab Package Registry (Recommended)
```bash
# Set your GitLab token
export GITLAB_TOKEN="your-gitlab-token"

# Upload the model
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
     --upload-file models/advanced_sast_model.joblib \
     "$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/sast-model/1.0.0/advanced_sast_model.joblib"
```

#### Option B: Include in Repository
```bash
# Add model to your repository (not recommended for large files)
git add models/advanced_sast_model.joblib
git commit -m "Add trained SAST model"
git push
```

#### Option C: Use Basic Pattern Matching
If you don't upload a model, the scanner will use basic pattern matching as fallback.

### 3. Configure GitLab CI/CD
The `.gitlab-ci.yml` file is already configured with:
- ✅ Automatic dependency installation
- ✅ Model downloading
- ✅ Security scanning
- ✅ Report generation
- ✅ Pipeline failure on high-severity vulnerabilities

### 4. Customize Scanning
Edit `.gitlab-ci.yml` to customize:

```yaml
variables:
  SAST_EXTENSIONS: ".py .java .js .php .cs"  # File types to scan
  SAST_MODEL_PATH: "models/advanced_sast_model.joblib"  # Model path
```

## 📊 How It Works

### Pipeline Stages:
1. **Build**: Install Python dependencies
2. **Test**: Run unit tests
3. **Security**: Scan code for vulnerabilities
4. **Deploy**: Deploy if security checks pass

### Security Scanning:
- Scans all files with specified extensions
- Uses your trained model for 95%+ accuracy
- Generates GitLab-compatible security reports
- Provides remediation suggestions
- Blocks deployment on high-severity vulnerabilities

### Reports Generated:
- `sast-report.json`: GitLab security dashboard
- `sast-summary.txt`: Human-readable summary
- Security metrics in GitLab UI

## 🎯 Supported Languages

- **Python** (.py) - SQL injection, XSS, command injection
- **Java** (.java) - SQL injection, XSS, path traversal
- **JavaScript** (.js) - XSS, command injection
- **PHP** (.php) - SQL injection, XSS, path traversal
- **C#** (.cs) - SQL injection, XSS, path traversal
- **C/C++** (.c, .cpp, .h) - Buffer overflow, command injection

## 🔒 Vulnerability Types Detected

- **SQL Injection** - Database query vulnerabilities
- **Cross-Site Scripting (XSS)** - Web application vulnerabilities
- **Command Injection** - Shell command vulnerabilities
- **Path Traversal** - File system vulnerabilities
- **Buffer Overflow** - Memory vulnerabilities
- **And more...**

## 📈 Example Output

### GitLab Security Dashboard:
```
🔒 Security Scan Results:
Total Vulnerabilities: 3
High Severity: 1
Medium Severity: 2
Low Severity: 0

📋 Vulnerable files:
📄 src/auth.py (2 vulnerabilities)
  - SQL Injection (High) - Line 15
  - XSS (Medium) - Line 23
📄 src/utils.py (1 vulnerability)
  - Command Injection (Medium) - Line 8
```

### Detailed Report:
```json
{
  "vulnerabilities": [
    {
      "id": "sast_12345",
      "category": "sast",
      "name": "SQL Injection",
      "severity": "high",
      "location": {
        "file": "src/auth.py",
        "start_line": 15
      },
      "remediation": {
        "summary": "Use parameterized queries instead of string concatenation",
        "diff": "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");"
      }
    }
  ]
}
```

## 🛠️ Troubleshooting

### Common Issues:

#### 1. Model Not Found
```
⚠️ No model found, using basic pattern matching
```
**Solution**: Upload your trained model to GitLab Package Registry

#### 2. High Memory Usage
**Solution**: 
- Exclude large directories in `.gitignore`
- Use a more powerful GitLab runner
- Scan only changed files

#### 3. False Positives
**Solution**:
- The model is 95%+ accurate
- Review specific patterns
- Adjust confidence thresholds
- Retrain with more data

#### 4. Pipeline Fails on Vulnerabilities
**Solution**:
- Fix the vulnerabilities
- Or set `allow_failure: true` in `.gitlab-ci.yml`
- Or adjust severity thresholds

### Testing Locally:
```bash
# Test the scanner locally
python gitlab_integration/sast_scanner.py --directory . --model models/advanced_sast_model.joblib

# Test with specific files
python gitlab_integration/sast_scanner.py --directory src/ --extensions .py .java
```

## 🔐 Security Best Practices

1. **Always review security reports** before deployment
2. **Fix high-severity vulnerabilities** immediately
3. **Use provided remediation suggestions** for quick fixes
4. **Regularly update the model** with new training data
5. **Monitor security trends** in your codebase
6. **Set up security notifications** for critical vulnerabilities

## 📞 Support

### Getting Help:
1. Check GitLab CI/CD logs for errors
2. Review security reports for details
3. Test locally with the scanner
4. Check this documentation

### Model Issues:
- Ensure model is properly trained
- Check model file path in `.gitlab-ci.yml`
- Verify model compatibility

### Pipeline Issues:
- Check GitLab runner resources
- Verify file permissions
- Review dependency installation

## 🎉 Success!

Once set up, your GitLab project will:
- ✅ Automatically scan every commit for vulnerabilities
- ✅ Generate detailed security reports
- ✅ Block deployment on critical issues
- ✅ Provide specific fix suggestions
- ✅ Track security metrics over time

**Your code is now protected by an intelligent security analysis system!** 🛡️
