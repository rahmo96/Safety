# Log Analysis Tool for Security Events

A Python-based security log analysis tool that parses system logs, detects security threats, and generates comprehensive reports.

## Features

- **Log Parsing**: Supports Syslog and Apache Common Log Format with automatic format detection
- **Security Event Detection**:
  - Failed login attempts (Brute force detection)
  - Unauthorized access attempts to sensitive paths
  - Unusual traffic volume or patterns
- **Report Generation**: Creates structured reports in JSON, CSV, or text format
- **CLI Interface**: Simple command-line interface for easy operation
- **Secure**: Read-only file access for log files

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

## Installation

1. Clone or download this repository
2. Ensure Python 3.6+ is installed:
   ```bash
   python --version
   ```

## Usage

### Basic Usage

```bash
python main.py <log_file>
```

### Command-Line Options

```
positional arguments:
  log_file              Path to the log file to analyze

optional arguments:
  --format {auto,syslog,systemd,apache}
                        Log format type (default: auto-detect). Supports syslog, systemd (journal), and apache formats
  --output OUTPUT       Output file path for report (JSON or CSV)
  --output-format {json,csv,text}
                        Output format: json, csv, or text (default: text)
  --failed-threshold N  Threshold for failed login attempts (default: 5)
  --traffic-threshold N Threshold for unusual traffic volume per IP (default: 100)
  --suspicious-paths PATH [PATH ...]
                        Additional suspicious paths to monitor
```

### Examples

1. **Analyze a log file and print results to console:**
   ```bash
   python main.py logs/access.log
   ```

2. **Analyze Syslog format and save JSON report:**
   ```bash
   python main.py logs/syslog.txt --format syslog --output report.json --output-format json
   ```

4. **Analyze Apache logs and save CSV report:**
   ```bash
   python main.py logs/apache.log --format apache --output report.csv --output-format csv
   ```

5. **Custom thresholds:**
   ```bash
   python main.py logs/access.log --failed-threshold 10 --traffic-threshold 200
   ```

6. **Monitor additional suspicious paths:**
   ```bash
   python main.py logs/access.log --suspicious-paths /api/admin /private /secret
   ```

## Project Structure

```
.
├── main.py              # CLI entry point
├── parser.py            # Log parsing module
├── detector.py          # Security event detection engine (plugin-based)
├── reporter.py          # Report generation module
├── base_rule.py        # Abstract base class for security rules
├── rules/               # Security detection rules (plugins)
│   ├── __init__.py
│   ├── brute_force_rule.py      # Brute force detection
│   ├── path_traversal_rule.py  # Unauthorized access detection
│   ├── unusual_traffic_rule.py  # Traffic pattern detection
│   └── example_custom_rule.py   # Example template for new rules
├── requirements.txt     # Dependencies (none required)
├── README.md           # Main documentation (this file)
├── API.md              # Complete API reference
├── ARCHITECTURE.md     # System architecture and design
├── PLUGIN_ARCHITECTURE.md  # Plugin system documentation
├── CHANGELOG.md        # Version history
├── CONTRIBUTING.md     # Contribution guidelines
└── example_*.log       # Example log files for testing
```

## Log Format Examples

### Apache Common Log Format

The tool can parse Apache Common Log Format entries:

```
192.168.1.100 - - [25/Dec/2023:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.101 - - [25/Dec/2023:10:15:31 +0000] "POST /login HTTP/1.1" 401 567
192.168.1.102 - - [25/Dec/2023:10:15:32 +0000] "GET /admin/config HTTP/1.1" 403 890
```

**Example log file (`example_apache.log`):**
```
192.168.1.100 - - [25/Dec/2023:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.101 - - [25/Dec/2023:10:15:31 +0000] "POST /login HTTP/1.1" 401 567
192.168.1.101 - - [25/Dec/2023:10:15:32 +0000] "POST /login HTTP/1.1" 401 567
192.168.1.101 - - [25/Dec/2023:10:15:33 +0000] "POST /login HTTP/1.1" 401 567
192.168.1.101 - - [25/Dec/2023:10:15:34 +0000] "POST /login HTTP/1.1" 401 567
192.168.1.101 - - [25/Dec/2023:10:15:35 +0000] "POST /login HTTP/1.1" 401 567
192.168.1.101 - - [25/Dec/2023:10:15:36 +0000] "POST /login HTTP/1.1" 401 567
192.168.1.102 - - [25/Dec/2023:10:15:37 +0000] "GET /admin/config HTTP/1.1" 403 890
192.168.1.103 - - [25/Dec/2023:10:15:38 +0000] "GET /page1 HTTP/1.1" 200 1234
192.168.1.103 - - [25/Dec/2023:10:15:39 +0000] "GET /page2 HTTP/1.1" 200 1234
192.168.1.103 - - [25/Dec/2023:10:15:40 +0000] "GET /page3 HTTP/1.1" 200 1234
```

### Syslog Format

The tool can parse Syslog format entries, including **Ubuntu system logs**:

```
Dec 25 10:15:30 server1 sshd[1234]: Failed password for user from 192.168.1.100
Dec 25 10:15:31 server1 sshd[1234]: Failed password for user from 192.168.1.100
Dec 25 10:15:32 server1 sshd[1234]: Accepted publickey for user from 192.168.1.101
```

**Ubuntu Log Support:**
The tool supports Ubuntu system logs including:
- `/var/log/syslog` - General system messages
- `/var/log/auth.log` - Authentication events (SSH, sudo, etc.)
- `/var/log/kern.log` - Kernel messages

**Example Ubuntu auth log file (`example_ubuntu_auth.log`):**
```
Dec 25 10:15:30 ubuntu-server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Dec 25 10:15:31 ubuntu-server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Dec 25 10:15:32 ubuntu-server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Dec 25 10:15:33 ubuntu-server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Dec 25 10:15:34 ubuntu-server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Dec 25 10:15:35 ubuntu-server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Dec 25 10:15:36 ubuntu-server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Dec 25 10:16:00 ubuntu-server sshd[1234]: Accepted publickey for user ubuntu from 192.168.1.101 port 54322 ssh2
Dec 25 10:16:01 ubuntu-server sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=1000)
```

**Example log file (`example_syslog.log`):**
```
Dec 25 10:15:30 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.100
Dec 25 10:15:31 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.100
Dec 25 10:15:32 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.100
Dec 25 10:15:33 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.100
Dec 25 10:15:34 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.100
Dec 25 10:15:35 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.100
Dec 25 10:15:36 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.100
Dec 25 10:16:00 server1 apache2[5678]: access denied for /admin/config from 192.168.1.102
Dec 25 10:16:01 server1 apache2[5678]: access denied for /wp-admin from 192.168.1.102
```

**Analyzing Ubuntu logs:**
```bash
# Analyze Ubuntu auth.log (traditional syslog format - requires sudo for read access)
sudo python main.py /var/log/auth.log --format syslog

# Or copy the log file first
sudo cp /var/log/auth.log ./auth.log
python main.py auth.log --format syslog

# Analyze systemd journal format (modern Ubuntu systems)
# Export journal to text format first:
journalctl --no-pager > journal.log
python main.py journal.log --format systemd

# Or use auto-detect (recommended)
python main.py journal.log
```

### Systemd Journal Format (Modern Ubuntu)

The tool supports systemd journal format with ISO 8601 timestamps, commonly used in modern Ubuntu systems:

```
2026-01-29T18:23:10.277402+02:00 rahmo-VMware-Virtual-Platform sudo: pam_unix(sudo:session): session opened for user root (uid=0) by rahmo(uid=1000)
2026-01-29T18:23:15.123456+02:00 rahmo-VMware-Virtual-Platform sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
```

**Example log file (`example_systemd.log`):**
```
2026-01-29T18:23:10.277402+02:00 rahmo-VMware-Virtual-Platform sudo: pam_unix(sudo:session): session opened for user root (uid=0) by rahmo(uid=1000)
2026-01-29T18:23:15.123456+02:00 rahmo-VMware-Virtual-Platform sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
2026-01-29T18:23:16.234567+02:00 rahmo-VMware-Virtual-Platform sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
2026-01-29T18:23:17.345678+02:00 rahmo-VMware-Virtual-Platform sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
2026-01-29T18:23:18.456789+02:00 rahmo-VMware-Virtual-Platform sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
2026-01-29T18:23:19.567890+02:00 rahmo-VMware-Virtual-Platform sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
2026-01-29T18:23:20.678901+02:00 rahmo-VMware-Virtual-Platform sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
```

**Exporting systemd journal for analysis:**
```bash
# Export all journal entries
journalctl --no-pager > journal.log

# Export only authentication events
journalctl -u ssh --no-pager > ssh.log

# Export with specific time range
journalctl --since "2026-01-29 18:00:00" --until "2026-01-29 19:00:00" --no-pager > journal.log
```

## Security Event Detection

### Failed Login Attempts (Brute Force)

The tool detects multiple failed login attempts from the same IP address. Default threshold is 5 attempts.

**Detection criteria:**
- HTTP status codes: 401 (Unauthorized), 403 (Forbidden)
- Log messages containing: "failed password", "authentication failure", "invalid user", "login failed", "access denied", "unauthorized"

### Unauthorized Access Attempts

Monitors access attempts to sensitive paths such as:
- `/admin`, `/wp-admin`, `/phpmyadmin`
- `/.env`, `/config`, `/etc/passwd`
- `/root`, `/.ssh`

**Severity levels:**
- **Critical**: Successful access (200, 301, 302) to sensitive paths
- **High**: Failed attempts (401, 403, 404) to sensitive paths

### Unusual Traffic Patterns

Identifies IP addresses with unusually high request volumes. Default threshold is 100 requests per IP.

**Patterns detected:**
- High POST request ratio (>70% of requests)
- Potential web scraping (>90% GET requests)

## Report Formats

### Text Report (Console Output)

The default text report includes:
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

## Security Considerations

- The tool uses read-only file access for log files
- No write operations are performed on log files
- All file operations use secure error handling
- Input validation prevents path traversal attacks

## Module Documentation

### parser.py

Handles parsing of log files using regex patterns:
- `LogParser`: Main parser class
- Supports Syslog, systemd journal (ISO 8601), and Apache Common Log Format
- Automatic format detection

### detector.py

Implements security event detection rules:
- `SecurityDetector`: Main detection class
- Configurable thresholds
- Multiple detection methods

### reporter.py

Generates reports in various formats:
- `ReportGenerator`: Report generation class
- Supports JSON, CSV, and text formats
- Comprehensive statistics and summaries

## Troubleshooting

**Issue: "No log entries were parsed"**
- Check that the log file format matches the expected format
- Try specifying `--format syslog` or `--format apache` explicitly
- Verify the log file is not empty

**Issue: "Permission denied"**
- Ensure you have read permissions for the log file
- On Unix/Linux systems, check file permissions with `ls -l`

**Issue: "Log file not found"**
- Verify the file path is correct
- Use absolute paths if relative paths don't work

## License

This tool is provided as-is for educational and security analysis purposes.

## Plugin Architecture

The tool uses a **plugin-based architecture** following the **Open/Closed Principle** (SOLID):

- **Extensible**: Add new security detection rules by simply creating a new file in `rules/`
- **No Core Modifications**: New rules are automatically discovered and loaded
- **SOLID Principles**: Follows best practices for maintainable code

**Quick Example - Adding a New Rule:**

1. Create `rules/my_rule.py`:
```python
from base_rule import SecurityRule

class MyRule(SecurityRule):
    def __init__(self):
        super().__init__(rule_name='my_rule', severity='high')
    
    def evaluate(self, log_entry):
        # Your detection logic
        return event_dict if threat_detected else None
```

2. That's it! The rule is automatically loaded and executed.

See **[Plugin Architecture Documentation](PLUGIN_ARCHITECTURE.md)** for complete details.

## Documentation

- **[Quick Start Guide](QUICKSTART.md)** - Get started in minutes
- **[API Documentation](API.md)** - Complete API reference
- **[Architecture Documentation](ARCHITECTURE.md)** - System design and architecture
- **[Plugin Architecture](PLUGIN_ARCHITECTURE.md)** - Plugin system and rule development
- **[Changelog](CHANGELOG.md)** - Version history
- **[Contributing Guidelines](CONTRIBUTING.md)** - How to contribute

## Contributing

This is an academic project. Contributions and improvements are welcome!

### Development Guidelines

1. Follow PEP 8 style guidelines
2. Add docstrings to all functions and classes
3. Test with various log formats
4. Update documentation for new features

## License

This tool is provided as-is for educational and security analysis purposes.

## Author

Cybersecurity Software Engineer - Academic Project

