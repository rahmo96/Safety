# API Documentation

Complete API reference for the Log Analysis Tool for Security Events.

## Table of Contents

- [LogParser](#logparser)
- [SecurityDetector](#securitydetector)
- [ReportGenerator](#reportgenerator)
- [Log Formats](#log-formats)

---

## LogParser

The `LogParser` class handles parsing of various log formats using regex patterns.

### Class: `LogParser`

```python
from parser import LogParser

parser = LogParser(log_format='auto')
```

#### Constructor

**`LogParser(log_format: str = 'auto')`**

Initialize the log parser.

**Parameters:**
- `log_format` (str, optional): Format type. Options:
  - `'auto'`: Auto-detect format from log content (default)
  - `'syslog'`: Traditional syslog format
  - `'systemd'`: Systemd journal format (ISO 8601)
  - `'apache'`: Apache Common/Combined Log Format

**Example:**
```python
# Auto-detect format
parser = LogParser()

# Explicit format
parser = LogParser(log_format='syslog')
```

#### Methods

##### `detect_format(line: str) -> Optional[str]`

Auto-detect log format from a sample line.

**Parameters:**
- `line` (str): A sample log line to analyze

**Returns:**
- `Optional[str]`: Format type (`'syslog'`, `'systemd'`, `'apache'`) or `None` if format cannot be determined

**Example:**
```python
parser = LogParser()
format_type = parser.detect_format("Dec 25 10:15:30 server sshd[1234]: message")
# Returns: 'syslog'
```

##### `parse_file(file_path: str) -> List[Dict]`

Parse a log file and return list of parsed entries.

**Parameters:**
- `file_path` (str): Path to the log file to parse

**Returns:**
- `List[Dict]`: List of parsed log entries, each containing:
  - Format-specific fields (see [Log Formats](#log-formats))
  - `line_number` (int): Original line number in file
  - `raw` (str): Original log line

**Raises:**
- `FileNotFoundError`: If log file doesn't exist
- `PermissionError`: If file cannot be read
- `Exception`: For other file reading errors

**Example:**
```python
parser = LogParser()
logs = parser.parse_file('access.log')
for log in logs:
    print(log['ip'], log['status'])
```

##### `parse_line(line: str) -> Optional[Dict]`

Parse a single log line based on configured format.

**Parameters:**
- `line` (str): Log line to parse

**Returns:**
- `Optional[Dict]`: Dictionary with parsed fields or `None` if parsing fails

**Example:**
```python
parser = LogParser(log_format='apache')
log_entry = parser.parse_line('192.168.1.1 - - [25/Dec/2023:10:00:01 +0000] "GET / HTTP/1.1" 200 1234')
```

##### `get_parsed_logs() -> List[Dict]`

Return the list of parsed logs from the last `parse_file()` call.

**Returns:**
- `List[Dict]`: List of parsed log entries

---

## SecurityDetector

The `SecurityDetector` class implements security event detection rules.

### Class: `SecurityDetector`

```python
from detector import SecurityDetector

detector = SecurityDetector(
    failed_login_threshold=5,
    suspicious_paths=['/admin', '/wp-admin'],
    traffic_threshold=100
)
```

#### Constructor

**`SecurityDetector(failed_login_threshold: int = 5, suspicious_paths: List[str] = None, traffic_threshold: int = 100)`**

Initialize the security detector with configurable thresholds.

**Parameters:**
- `failed_login_threshold` (int, optional): Number of failed login attempts to trigger alert (default: 5)
- `suspicious_paths` (List[str], optional): List of sensitive paths to monitor. Default includes:
  - `/admin`, `/wp-admin`, `/phpmyadmin`
  - `/.env`, `/config`, `/etc/passwd`
  - `/root`, `/.ssh`
- `traffic_threshold` (int, optional): Number of requests per IP to flag as unusual traffic (default: 100)

**Example:**
```python
detector = SecurityDetector(
    failed_login_threshold=10,
    suspicious_paths=['/api/admin', '/private'],
    traffic_threshold=200
)
```

#### Methods

##### `analyze(logs: List[Dict]) -> Dict`

Perform comprehensive security analysis on logs.

**Parameters:**
- `logs` (List[Dict]): List of parsed log entries from `LogParser`

**Returns:**
- `Dict`: Analysis results containing:
  - `total_events` (int): Total number of security events detected
  - `events` (List[Dict]): List of detected security events
  - `statistics` (Dict): Statistics including:
    - `severity_distribution` (Dict): Count of events by severity
    - `event_type_distribution` (Dict): Count of events by type
    - `top_offending_ips` (List[Dict]): Top 10 IPs with most events

**Example:**
```python
parser = LogParser()
logs = parser.parse_file('access.log')

detector = SecurityDetector()
results = detector.analyze(logs)

print(f"Detected {results['total_events']} security events")
for event in results['events']:
    print(f"{event['type']}: {event['description']}")
```

##### `detect_failed_logins(logs: List[Dict]) -> List[Dict]`

Detect brute force attempts (multiple failed login attempts).

**Returns:**
- `List[Dict]`: List of detected failed login events, each containing:
  - `type` (str): `'failed_login_attempts'`
  - `severity` (str): `'high'`
  - `ip` (str): Offending IP address
  - `count` (int): Number of failed attempts
  - `threshold` (int): Configured threshold
  - `details` (List[Dict]): Individual failure details
  - `description` (str): Human-readable description

##### `detect_unauthorized_access(logs: List[Dict]) -> List[Dict]`

Detect unauthorized access attempts to sensitive paths.

**Returns:**
- `List[Dict]`: List of detected unauthorized access events, each containing:
  - `type` (str): `'unauthorized_access'` or `'unauthorized_access_attempt'`
  - `severity` (str): `'critical'` (successful) or `'high'` (failed)
  - `ip` (str): Offending IP address
  - `path` (str): Attempted path
  - `status` (int): HTTP status code
  - `timestamp` (str): Event timestamp
  - `description` (str): Human-readable description

##### `detect_unusual_traffic(logs: List[Dict]) -> List[Dict]`

Detect unusual traffic volume or patterns.

**Returns:**
- `List[Dict]`: List of detected unusual traffic events, each containing:
  - `type` (str): `'unusual_traffic'`
  - `severity` (str): `'medium'`
  - `ip` (str): Offending IP address
  - `request_count` (int): Total requests from IP
  - `threshold` (int): Configured threshold
  - `method_distribution` (Dict): HTTP method breakdown
  - `patterns` (List[str]): Detected suspicious patterns
  - `description` (str): Human-readable description

##### `get_events() -> List[Dict]`

Return the list of detected events from the last `analyze()` call.

**Returns:**
- `List[Dict]`: List of detected security events

---

## ReportGenerator

The `ReportGenerator` class creates structured reports of detected security events.

### Class: `ReportGenerator`

```python
from reporter import ReportGenerator

generator = ReportGenerator(analysis_results)
```

#### Constructor

**`ReportGenerator(analysis_results: Dict)`**

Initialize the report generator.

**Parameters:**
- `analysis_results` (Dict): Dictionary containing analysis results from `SecurityDetector.analyze()`

**Example:**
```python
detector = SecurityDetector()
results = detector.analyze(logs)

generator = ReportGenerator(results)
```

#### Methods

##### `generate_summary() -> str`

Generate a text summary of the analysis.

**Returns:**
- `str`: Formatted summary string with:
  - Overall statistics
  - Severity distribution
  - Event type distribution
  - Top offending IPs
  - Detailed events grouped by severity

**Example:**
```python
summary = generator.generate_summary()
print(summary)
```

##### `generate_json(output_path: str) -> None`

Generate a JSON report file.

**Parameters:**
- `output_path` (str): Path to save the JSON report

**Raises:**
- `Exception`: If file cannot be written

**Example:**
```python
generator.generate_json('report.json')
```

##### `generate_csv(output_path: str) -> None`

Generate a CSV report file.

**Parameters:**
- `output_path` (str): Path to save the CSV report

**Raises:**
- `Exception`: If file cannot be written

**Example:**
```python
generator.generate_csv('report.csv')
```

##### `print_summary() -> None`

Print the summary report to console.

**Example:**
```python
generator.print_summary()
```

---

## Log Formats

### Apache Common Log Format

**Format:**
```
IP - - [timestamp] "method path protocol" status size
```

**Example:**
```
192.168.1.10 - - [25/Dec/2023:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
```

**Parsed Fields:**
- `ip` (str): Client IP address (IPv4 or IPv6)
- `timestamp` (str): Request timestamp
- `method` (str): HTTP method (GET, POST, etc.)
- `path` (str): Requested path
- `protocol` (str): HTTP protocol version
- `status` (int): HTTP status code
- `size` (str): Response size in bytes

### Apache Combined Log Format

**Format:**
```
IP - - [timestamp] "method path protocol" status size "referer" "user-agent"
```

**Example:**
```
::1 - - [01/Feb/2026:14:25:01 +0200] "GET / HTTP/1.1" 200 10926 "-" "curl/8.5.0"
```

**Additional Fields:**
- `referer` (str): HTTP Referer header
- `user_agent` (str): HTTP User-Agent header

### Syslog Format

**Format:**
```
timestamp hostname service[pid]: message
```

**Example:**
```
Dec 25 10:15:30 server1 sshd[1234]: Failed password for user from 192.168.1.100
```

**Parsed Fields:**
- `timestamp` (str): Log timestamp
- `hostname` (str): System hostname
- `service` (str): Service name
- `pid` (str, optional): Process ID
- `message` (str): Log message

### Systemd Journal Format

**Format:**
```
ISO8601_timestamp hostname service[pid]: message
```

**Example:**
```
2026-01-29T18:23:10.277402+02:00 rahmo-VMware-Virtual-Platform sudo: pam_unix(sudo:session): session opened
```

**Parsed Fields:**
- `timestamp` (str): ISO 8601 timestamp
- `hostname` (str): System hostname
- `service` (str): Service name
- `pid` (str, optional): Process ID
- `message` (str): Log message

---

## Complete Example

```python
from parser import LogParser
from detector import SecurityDetector
from reporter import ReportGenerator

# Step 1: Parse log file
parser = LogParser(log_format='auto')
logs = parser.parse_file('access.log')
print(f"Parsed {len(logs)} log entries")

# Step 2: Detect security events
detector = SecurityDetector(
    failed_login_threshold=5,
    traffic_threshold=100
)
results = detector.analyze(logs)
print(f"Detected {results['total_events']} security events")

# Step 3: Generate report
generator = ReportGenerator(results)
generator.print_summary()

# Or save to file
generator.generate_json('report.json')
generator.generate_csv('report.csv')
```

---

## Event Types

### Failed Login Attempts

**Type:** `failed_login_attempts`  
**Severity:** `high`  
**Detection:** Multiple failed login attempts from same IP exceeding threshold

### Unauthorized Access

**Type:** `unauthorized_access`  
**Severity:** `critical`  
**Detection:** Successful access (200, 301, 302) to sensitive paths

### Unauthorized Access Attempt

**Type:** `unauthorized_access_attempt`  
**Severity:** `high`  
**Detection:** Failed attempts (401, 403, 404) to sensitive paths

### Unusual Traffic

**Type:** `unusual_traffic`  
**Severity:** `medium`  
**Detection:** High request volume from single IP exceeding threshold

---

## Severity Levels

- **critical**: Immediate attention required (successful unauthorized access)
- **high**: High priority (brute force, failed unauthorized access)
- **medium**: Medium priority (unusual traffic patterns)
- **low**: Low priority (informational)
