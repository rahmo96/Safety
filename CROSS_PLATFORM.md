# Cross-Platform Compatibility

## Overview

The Log Analysis Tool is **fully cross-platform** and works on:
- ✅ **Windows** (Windows 10/11)
- ✅ **Ubuntu Linux** (all versions)
- ✅ **Other Linux distributions**
- ✅ **macOS**

## Platform-Specific Considerations

### File Paths

The code uses **cross-platform** path handling:
- Uses `os.path.exists()` instead of platform-specific checks
- Uses relative paths (`'rules/'`) that work on all platforms
- No hardcoded path separators (`\` or `/`)
- Python's `os` module handles path differences automatically

### Module Imports

The plugin architecture uses Python's standard library:
- `importlib.import_module()` - Works on all platforms
- Module paths use dot notation (`'rules.brute_force_rule'`) - Cross-platform
- No platform-specific import mechanisms

### Directory Scanning

The dynamic rule discovery uses:
- `os.listdir()` - Cross-platform directory listing
- Works identically on Windows, Linux, and macOS

## Testing on Ubuntu

### Prerequisites

```bash
# Check Python version (3.6+ required)
python3 --version

# Or
python --version
```

### Running on Ubuntu

```bash
# Basic usage
python3 main.py example_apache.log

# With Ubuntu system logs
sudo python3 main.py /var/log/auth.log --format syslog

# Or copy log file first (recommended)
sudo cp /var/log/auth.log ./auth.log
python3 main.py auth.log --format syslog
```

### Plugin System on Ubuntu

The plugin architecture works identically on Ubuntu:

```bash
# Rules are automatically discovered
$ python3 main.py example_apache.log
Parsing log file: example_apache.log
Successfully parsed 23 log entries
Analyzing logs for security events...
Loaded rule: brute_force (BruteForceRule)
Loaded rule: path_traversal (PathTraversalRule)
Loaded rule: unusual_traffic (UnusualTrafficRule)
Successfully loaded 3 security rule(s)
...
```

### Adding Rules on Ubuntu

Creating new rules works the same way:

```bash
# Create new rule file
nano rules/my_rule.py

# The rule is automatically discovered on next run
python3 main.py access.log
```

## File Permissions (Ubuntu)

### Reading System Logs

Ubuntu system logs require elevated permissions:

```bash
# Option 1: Use sudo
sudo python3 main.py /var/log/auth.log

# Option 2: Copy log file (recommended)
sudo cp /var/log/auth.log ./auth.log
python3 main.py auth.log

# Option 3: Change ownership (if you own the system)
sudo chown $USER:$USER /var/log/auth.log
python3 main.py /var/log/auth.log
```

### Rules Directory

The `rules/` directory should have standard permissions:

```bash
# Check permissions
ls -la rules/

# Should show:
# drwxr-xr-x rules/
# -rw-r--r-- rules/*.py
```

## Line Endings

The code handles different line endings automatically:
- Windows: `\r\n` (CRLF)
- Linux/Unix: `\n` (LF)
- Python's file reading handles both

## Case Sensitivity

**Important for Ubuntu/Linux:**

Linux file systems are **case-sensitive**, unlike Windows:
- ✅ `rules/brute_force_rule.py` - Correct
- ❌ `rules/Brute_Force_Rule.py` - Different file on Linux

**Best Practice:** Use lowercase with underscores for rule files.

## Module Import Paths

The plugin system uses Python's import mechanism which works identically:

**Windows:**
```python
importlib.import_module('rules.brute_force_rule')
```

**Ubuntu:**
```python
importlib.import_module('rules.brute_force_rule')  # Same!
```

## Verification

### Test on Ubuntu

```bash
# 1. Clone/download the project
cd ~/projects/Safety

# 2. Verify structure
ls -la
ls -la rules/

# 3. Run test
python3 main.py example_apache.log --format apache

# 4. Verify rules load
# Should see: "Successfully loaded 3 security rule(s)"
```

### Expected Output (Ubuntu)

```
Parsing log file: example_apache.log
Successfully parsed 23 log entries
Analyzing logs for security events...
Loaded rule: brute_force (BruteForceRule)
Loaded rule: path_traversal (PathTraversalRule)
Loaded rule: unusual_traffic (UnusualTrafficRule)
Successfully loaded 3 security rule(s)
Detected 5 security events
Generating report...
...
```

## Troubleshooting on Ubuntu

### Issue: Rules Not Loading

**Problem:** Rules directory not found

**Solution:**
```bash
# Verify rules directory exists
ls -d rules/

# Check current directory
pwd

# Run from project root
cd /path/to/Safety
python3 main.py access.log
```

### Issue: Import Errors

**Problem:** Module import fails

**Solution:**
```bash
# Verify Python can find modules
python3 -c "import sys; print(sys.path)"

# Run from project root
python3 main.py access.log
```

### Issue: Permission Denied

**Problem:** Cannot read log file

**Solution:**
```bash
# Check file permissions
ls -l /var/log/auth.log

# Use sudo or copy file
sudo python3 main.py /var/log/auth.log
# OR
sudo cp /var/log/auth.log ./auth.log
python3 main.py auth.log
```

## Python Version

Works with:
- Python 3.6+
- Python 3.7+
- Python 3.8+
- Python 3.9+
- Python 3.10+
- Python 3.11+
- Python 3.12+

**Ubuntu Default:**
```bash
# Check version
python3 --version

# Most Ubuntu versions come with Python 3.8+
```

## Summary

✅ **Fully compatible with Ubuntu**  
✅ **No platform-specific code**  
✅ **Uses only standard library**  
✅ **Cross-platform file handling**  
✅ **Identical behavior on all platforms**

The refactored plugin architecture maintains full cross-platform compatibility!
