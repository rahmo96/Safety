# Test Log Files

This directory contains test log files for various log formats supported by the Log Analysis Tool.

## Test Files

### `test_apache_common.log`
- **Format**: Apache Common Log Format
- **Content**: 18 entries
- **Security Events**:
  - 4 failed login attempts to `/admin` (401/403 status codes)
  - 3 unauthorized access attempts to sensitive paths (`/wp-admin`, `/.env`, `/etc/passwd`)
  - 10+ requests from single IP (unusual traffic pattern)

### `test_apache_combined.log`
- **Format**: Apache Combined Log Format (with Referer and User-Agent)
- **Content**: 15 entries
- **Security Events**:
  - 6 failed login attempts (brute force)
  - 3 unauthorized access attempts to sensitive paths
  - IPv6 address included
  - Suspicious user agent (`sqlmap/1.7`)

### `test_syslog.log`
- **Format**: Traditional Syslog
- **Content**: 12 entries
- **Security Events**:
  - 6 failed SSH password attempts (brute force)
  - 3 failed sudo authentication attempts

### `test_ubuntu_auth.log`
- **Format**: Ubuntu syslog format (auth.log style)
- **Content**: 10 entries
- **Security Events**:
  - 6 failed SSH login attempts for invalid user `admin`
  - 1 authentication failure

### `test_kernel.log`
- **Format**: Ubuntu kernel log format
- **Content**: 7 entries
- **Security Events**:
  - 5 firewall blocked connections from same IP

### `test_systemd.log`
- **Format**: Systemd journal format (ISO 8601 timestamps)
- **Content**: 11 entries
- **Security Events**: None (normal system activity)
- **Features**: 
  - Service names with dots (e.g., `apt.systemd.daily[10533]`)
  - Various systemd services

### `test_mixed_security.log`
- **Format**: Mixed Apache and Syslog formats
- **Content**: 37 entries
- **Security Events**:
  - 6 failed login attempts (Apache)
  - 6 failed SSH login attempts (Syslog)
  - 5 unauthorized access attempts to sensitive paths
  - 20 POST requests from single IPv6 address (unusual traffic)

## Usage Examples

```bash
# Test Apache Common format
python main.py logs/test_apache_common.log --format apache

# Test Syslog format
python main.py logs/test_syslog.log --format syslog

# Test Systemd format
python main.py logs/test_systemd.log --format systemd

# Test with auto-detection
python main.py logs/test_mixed_security.log --format auto

# Generate JSON report
python main.py logs/test_apache_combined.log --format apache --output report.json --output-format json

# Test with custom thresholds
python main.py logs/test_syslog.log --format syslog --failed-threshold 3
```

## Expected Results

- **test_apache_common.log**: Should detect brute force (4+ failed logins) and unauthorized access attempts
- **test_apache_combined.log**: Should detect brute force, path traversal, and suspicious user agent
- **test_syslog.log**: Should detect brute force from SSH failed passwords
- **test_ubuntu_auth.log**: Should detect brute force from invalid user attempts
- **test_kernel.log**: Should detect repeated firewall blocks (if rule exists)
- **test_systemd.log**: Should parse correctly but may not detect security events (normal activity)
- **test_mixed_security.log**: Should detect multiple event types including brute force, path traversal, and unusual traffic
