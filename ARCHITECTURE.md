# Architecture Documentation

## Overview

The Log Analysis Tool for Security Events is a modular Python application designed to parse system logs, detect security threats, and generate comprehensive reports. The architecture follows a pipeline pattern with clear separation of concerns.

## System Architecture

```
┌─────────────┐
│  Log File   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Parser    │  ← parser.py
│   Module    │
└──────┬──────┘
       │ Parsed Logs (List[Dict])
       ▼
┌─────────────┐
│  Detector   │  ← detector.py
│   Module    │
└──────┬──────┘
       │ Analysis Results (Dict)
       ▼
┌─────────────┐
│  Reporter   │  ← reporter.py
│   Module    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Reports   │  (JSON/CSV/Text)
└─────────────┘
```

## Module Design

### 1. Parser Module (`parser.py`)

**Responsibility:** Parse log files into structured data

**Key Components:**
- `LogParser` class: Main parser implementation
- Regex patterns for different log formats
- Format auto-detection
- Error handling for file operations

**Design Patterns:**
- Strategy Pattern: Different parsing strategies for different formats
- Factory Pattern: Auto-detection creates appropriate parser

**Supported Formats:**
- Apache Common Log Format
- Apache Combined Log Format (with Referer/User-Agent)
- Traditional Syslog
- Systemd Journal (ISO 8601)
- Kernel logs

### 2. Detector Module (`detector.py`)

**Responsibility:** Detect security events in parsed logs

**Key Components:**
- `SecurityDetector` class: Main detection engine
- Detection rules:
  - Failed login detection
  - Unauthorized access detection
  - Unusual traffic detection
- Configurable thresholds
- IP extraction from various formats

**Design Patterns:**
- Chain of Responsibility: Multiple detection methods
- Strategy Pattern: Configurable detection rules

**Detection Methods:**
1. `detect_failed_logins()`: Brute force detection
2. `detect_unauthorized_access()`: Sensitive path monitoring
3. `detect_unusual_traffic()`: Traffic pattern analysis

### 3. Reporter Module (`reporter.py`)

**Responsibility:** Generate reports in various formats

**Key Components:**
- `ReportGenerator` class: Report generation engine
- Multiple output formats:
  - Text (console)
  - JSON (structured data)
  - CSV (tabular data)
- Statistics aggregation
- Event grouping and sorting

**Design Patterns:**
- Strategy Pattern: Different output formats
- Template Method: Report structure template

### 4. Main Module (`main.py`)

**Responsibility:** CLI interface and orchestration

**Key Components:**
- Argument parsing (argparse)
- File validation
- Pipeline orchestration
- Error handling and exit codes

**Exit Codes:**
- `0`: No security events
- `1`: Security events detected (non-critical)
- `2`: Critical security events detected

## Data Flow

### 1. Input Phase
```
Log File → File Reader → Line Iterator
```

### 2. Parsing Phase
```
Raw Log Line → Format Detection → Regex Matching → Structured Dict
```

### 3. Detection Phase
```
Parsed Logs → Rule Application → Event Aggregation → Statistics
```

### 4. Reporting Phase
```
Analysis Results → Format Selection → Report Generation → Output
```

## Data Structures

### Parsed Log Entry

```python
{
    'format': 'apache' | 'syslog' | 'systemd',
    'timestamp': str,
    'ip': str,  # For Apache format
    'hostname': str,  # For Syslog/Systemd
    'service': str,  # For Syslog/Systemd
    'method': str,  # For Apache
    'path': str,  # For Apache
    'status': int,  # For Apache
    'message': str,  # For Syslog/Systemd
    'line_number': int,
    'raw': str
}
```

### Security Event

```python
{
    'type': str,  # Event type identifier
    'severity': str,  # 'critical' | 'high' | 'medium' | 'low'
    'ip': str,  # Offending IP address
    'description': str,  # Human-readable description
    'count': int,  # Number of occurrences
    'timestamp': str,  # Event timestamp
    'details': List[Dict]  # Additional event details
}
```

### Analysis Results

```python
{
    'total_events': int,
    'events': List[SecurityEvent],
    'statistics': {
        'severity_distribution': Dict[str, int],
        'event_type_distribution': Dict[str, int],
        'top_offending_ips': List[Dict[str, Any]]
    }
}
```

## Security Considerations

### 1. File Access
- Read-only file operations
- No write access to log files
- Permission validation before reading

### 2. Input Validation
- File existence checks
- Path validation
- Encoding handling (UTF-8 with error handling)

### 3. Error Handling
- Graceful error messages
- No sensitive information leakage
- Proper exception handling

## Extensibility

### Adding New Log Formats

1. Add regex pattern to `LogParser`
2. Implement parse method
3. Update `detect_format()` method
4. Update `parse_line()` method

### Adding New Detection Rules

1. Create detection method in `SecurityDetector`
2. Add to `analyze()` method
3. Define event structure
4. Update severity levels if needed

### Adding New Report Formats

1. Add generation method to `ReportGenerator`
2. Implement format-specific logic
3. Update CLI options if needed

## Performance Considerations

### Memory Usage
- Line-by-line processing (not loading entire file)
- Streaming approach for large files
- Efficient data structures (defaultdict)

### Processing Speed
- Compiled regex patterns (re.compile)
- Single-pass parsing
- Efficient aggregation algorithms

### Scalability
- Handles large log files
- Configurable thresholds
- Modular design for optimization

## Testing Strategy

### Unit Tests
- Individual module testing
- Regex pattern validation
- Detection rule validation

### Integration Tests
- End-to-end pipeline testing
- Format compatibility testing
- Error handling validation

### Example Test Cases
- Parse various log formats
- Detect security events
- Generate reports in all formats
- Handle edge cases (empty files, malformed logs)

## Future Enhancements

### Potential Additions
1. Real-time log monitoring
2. Database storage for events
3. Web dashboard interface
4. Email/SMS alerts
5. Machine learning-based detection
6. Log correlation across multiple sources
7. Geographic IP mapping
8. Time-series analysis

### Performance Improvements
1. Parallel processing for large files
2. Caching parsed results
3. Incremental analysis
4. Compression support
