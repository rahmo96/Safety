# Log Analysis Tool for Security Events

A Python-based security log analysis tool that parses system logs, detects security threats, and generates comprehensive reports. Features a **plugin-based architecture** following SOLID principles.

## Features

- **Multi-Format Log Parsing**: Supports Apache (Common/Combined), Syslog, Systemd journal, and Windows Event Viewer CSV formats
- **Plugin Architecture**: Extensible rule system - add new detection rules without modifying core code
- **Security Event Detection**:
  - Failed login attempts (Brute force detection)
  - Unauthorized access attempts to sensitive paths
  - Unusual traffic volume or patterns
- **Report Generation**: Creates structured reports in JSON, CSV, or text format
- **CLI Interface**: Simple command-line interface with comprehensive options
- **Cross-Platform**: Works on Windows, Linux (Ubuntu), and macOS
- **Memory Efficient**: Efficient processing for large log files

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

## Installation

1. Clone or download this repository
2. Ensure Python 3.6+ is installed:
   ```bash
   python --version
   # or
   python3 --version
   ```

## Quick Start

```bash
# Analyze a log file
python main.py access.log

# Generate JSON report
python main.py access.log --output report.json --output-format json
```

## Usage

### Basic Usage

```bash
python main.py <log_file> [options]
```

### Command-Line Options

```
positional arguments:
  log_file              Path to the log file to analyze

optional arguments:
  --format {auto,syslog,systemd,apache}
                        Log format type (default: auto-detect)
  --output OUTPUT       Output file path for report (JSON or CSV)
  --output-format {json,csv,text}
                        Output format: json, csv, or text (default: text)
  --failed-threshold N  Threshold for failed login attempts (default: 5)
  --traffic-threshold N Threshold for unusual traffic volume per IP (default: 100)
  --suspicious-paths PATH [PATH ...]
                        Additional suspicious paths to monitor
```

## Examples

### Batch Analysis Examples

1. **Analyze a log file and print results:**
   ```bash
   python main.py access.log
   ```

2. **Analyze and save JSON report:**
   ```bash
   python main.py access.log --output report.json --output-format json
   ```

3. **Analyze Syslog format:**
   ```bash
   python main.py syslog.txt --format syslog
   ```

4. **Custom thresholds:**
   ```bash
   python main.py access.log --failed-threshold 10 --traffic-threshold 200
   ```

5. **Monitor custom paths:**
   ```bash
   python main.py access.log --suspicious-paths /api/admin /private /secret
   ```

## Project Structure

```
.
├── main.py              # CLI entry point
├── parser.py            # Log parsing module
├── detector.py          # Security event detection engine (plugin-based)
├── reporter.py          # Report generation module
├── base_rule.py         # Abstract base class for security rules
├── rules/               # Security detection rules (plugins)
│   ├── __init__.py
│   ├── brute_force_rule.py      # Brute force detection
│   ├── path_traversal_rule.py   # Unauthorized access detection
│   ├── unusual_traffic_rule.py  # Traffic pattern detection
│   └── example_custom_rule.py   # Template for new rules
├── requirements.txt     # Dependencies (none required)
└── README.md           # This file
```

## Log Format Support

### Apache Logs

**Common Log Format:**
```
192.168.1.10 - - [25/Dec/2023:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
```

**Combined Log Format (with Referer and User-Agent):**
```
::1 - - [01/Feb/2026:14:25:01 +0200] "GET / HTTP/1.1" 200 10926 "-" "curl/8.5.0"
```

**Features:**
- Supports IPv4 and IPv6 addresses
- Automatic detection of Common vs Combined format
- Extracts IP, method, path, status, referer, user-agent

### Syslog Format

**Traditional Syslog:**
```
Dec 25 10:15:30 server1 sshd[1234]: Failed password for user from 192.168.1.100
```

**Ubuntu System Logs:**
- `/var/log/syslog` - General system messages
- `/var/log/auth.log` - Authentication events (SSH, sudo, etc.)
- `/var/log/kern.log` - Kernel messages

### Systemd Journal Format

**ISO 8601 Timestamps:**
```
2026-01-29T18:23:10.277402+02:00 rahmo-VMware-Virtual-Platform sudo: pam_unix(sudo:session): session opened
```

**Usage:**
```bash
# Export journal to text format
journalctl --no-pager > journal.log

# Analyze
python main.py journal.log --format systemd
```

### Windows Event Viewer CSV Format

**Windows Event Log Export:**
```
TimeCreated,Id,Message,Level,Task,Opcode,Keywords,EventRecordID,ProviderName,...
2026-02-02T10:00:01.123Z,4625,"An account failed to log on. Source Network Address: 192.168.1.100 Target User Name: admin",...
```

**Usage:**
```bash
# Export Windows Event Viewer logs to CSV
# In Event Viewer: Right-click log → Save All Events As → CSV format

# Analyze Windows CSV
python main.py windows_events.csv --format windows_csv

# Auto-detect format
python main.py windows_events.csv --format auto
```

**Features:**
- Automatically detects Windows CSV format by header row
- Maps `TimeCreated` → `timestamp`, `Id` → `event_id`, `Message` → `message`
- Extracts IP addresses and usernames from Event ID 4625 (failed logon)
- Unified reporting format across Windows and Linux logs

## Plugin Architecture

The tool uses a **plugin-based architecture** following the **Open/Closed Principle** (SOLID):

- **Extensible**: Add new security detection rules by creating a new file in `rules/`
- **No Core Modifications**: New rules are automatically discovered and loaded
- **SOLID Principles**: Follows best practices for maintainable code

### Adding a New Rule

1. Create `rules/my_rule.py`:
```python
from base_rule import SecurityRule

class MyRule(SecurityRule):
    def __init__(self):
        super().__init__(rule_name='my_rule', severity='high')
    
    def evaluate(self, log_entry):
        # Your detection logic
        if threat_detected:
            return {
                'type': 'my_threat',
                'severity': self.severity,
                'description': 'Threat description'
            }
        return None
```

2. That's it! The rule is automatically loaded and executed.

## Security Event Detection

### Failed Login Attempts (Brute Force)

Detects multiple failed login attempts from the same IP address.

**Default threshold:** 5 attempts

**Detection criteria:**
- HTTP status codes: 401 (Unauthorized), 403 (Forbidden)
- Log messages containing: "failed password", "authentication failure", "invalid user", "login failed", "access denied", "unauthorized"

### Unauthorized Access Attempts

Monitors access attempts to sensitive paths.

**Default monitored paths:**
- `/admin`, `/wp-admin`, `/phpmyadmin`
- `/.env`, `/config`, `/etc/passwd`
- `/root`, `/.ssh`

**Severity levels:**
- **Critical**: Successful access (200, 301, 302) to sensitive paths
- **High**: Failed attempts (401, 403, 404) to sensitive paths

### Unusual Traffic Patterns

Identifies IP addresses with unusually high request volumes.

**Default threshold:** 100 requests per IP

**Patterns detected:**
- High POST request ratio (>70% of requests)
- Potential web scraping (>90% GET requests)

## Report Formats

### Text Report (Console Output)

Default format includes:
- Overall statistics
- Severity distribution
- Event type distribution
- Top 10 offending IP addresses
- Detailed events grouped by severity

### JSON Report

Structured JSON output containing:
- Report metadata (generation timestamp, total events)
- Statistics (severity distribution, event types, top IPs)
- Complete event details

### CSV Report

Tabular format with columns:
- Type, Severity, IP, Description, Count, Path, Timestamp, etc.

## Exit Codes

- `0`: No security events detected
- `1`: Security events detected (non-critical)
- `2`: Critical security events detected

## Ubuntu/System Logs

### Analyzing Ubuntu Logs

```bash
# Traditional syslog format (requires sudo)
sudo python main.py /var/log/auth.log --format syslog

# Or copy log file first (recommended)
sudo cp /var/log/auth.log ./auth.log
python main.py auth.log --format syslog

# Systemd journal format
journalctl --no-pager > journal.log
python main.py journal.log --format systemd
```

## Troubleshooting

### "No log entries were parsed"
- Check that the log file format matches the expected format
- Try specifying `--format syslog` or `--format apache` explicitly
- Verify the log file is not empty

### "Permission denied"
- Ensure you have read permissions for the log file
- On Unix/Linux systems, use `sudo` or copy the file first
- Check file permissions with `ls -l`

### "Log file not found"
- Verify the file path is correct
- Use absolute paths if relative paths don't work

### Rules not loading
- Ensure rule files are in the `rules/` directory
- Check that rule classes inherit from `SecurityRule`
- Verify Python can import the modules

## Security Considerations

- The tool uses read-only file access for log files
- No write operations are performed on log files
- All file operations use secure error handling
- Input validation prevents path traversal attacks

## Architecture

### Plugin System

- **Base Interface**: `SecurityRule` abstract base class
- **Dynamic Discovery**: Automatically loads rules from `rules/` directory
- **Open/Closed Principle**: Open for extension, closed for modification


## Contributing

This is an academic project. Contributions and improvements are welcome!

### Development Guidelines

1. Follow PEP 8 style guidelines
2. Add docstrings to all functions and classes
3. Test with various log formats
4. Update documentation for new features
5. Create new rules in `rules/` directory following the plugin pattern

## License

This tool is provided as-is for educational and security analysis purposes.

## Author

Cybersecurity Software Engineer - Academic Project
