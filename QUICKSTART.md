# Quick Start Guide

Get started with the Log Analysis Tool for Security Events in minutes!

## Installation

No installation required! Just ensure you have Python 3.6+:

```bash
python --version
```

## Basic Usage

### 1. Analyze a Log File

```bash
python main.py your_log_file.log
```

The tool will:
- Auto-detect the log format
- Parse all log entries
- Detect security events
- Print a summary report

### 2. Save Report to File

```bash
# JSON format
python main.py access.log --output report.json --output-format json

# CSV format
python main.py access.log --output report.csv --output-format csv
```

### 3. Specify Log Format

```bash
# Apache logs
python main.py access.log --format apache

# Syslog format
python main.py syslog.txt --format syslog

# Systemd journal
python main.py journal.log --format systemd
```

## Common Use Cases

### Analyze Apache Access Logs

```bash
python main.py /var/log/apache2/access.log --format apache --output apache_report.json --output-format json
```

### Analyze Ubuntu Auth Logs

```bash
# Copy log file first (requires sudo)
sudo cp /var/log/auth.log ./auth.log

# Analyze
python main.py auth.log --format syslog
```

### Analyze Systemd Journal

```bash
# Export journal
journalctl --no-pager > journal.log

# Analyze
python main.py journal.log --format systemd
```

### Custom Detection Thresholds

```bash
# Lower threshold for failed logins (more sensitive)
python main.py access.log --failed-threshold 3

# Higher threshold for traffic (less sensitive)
python main.py access.log --traffic-threshold 200
```

### Monitor Custom Paths

```bash
python main.py access.log --suspicious-paths /api/admin /private /secret
```

## Understanding the Output

### Text Report (Default)

The console output shows:
- **Overall Statistics**: Total events detected
- **Severity Distribution**: Events by severity level
- **Event Type Distribution**: Types of events found
- **Top Offending IPs**: IPs with most events
- **Detailed Events**: Full event details grouped by severity

### JSON Report

Structured data perfect for:
- Integration with other tools
- Automated processing
- Data analysis

### CSV Report

Tabular format perfect for:
- Spreadsheet analysis
- Data visualization
- Import into databases

## Exit Codes

- `0`: No security events detected ✅
- `1`: Security events detected (non-critical) ⚠️
- `2`: Critical security events detected 🚨

Use exit codes in scripts:
```bash
python main.py access.log
if [ $? -eq 2 ]; then
    echo "Critical security events detected!"
    # Send alert
fi
```

## Example Workflow

```bash
# 1. Analyze log file
python main.py access.log --output report.json --output-format json

# 2. Check exit code
echo $?

# 3. Review report
cat report.json | python -m json.tool
```

## Tips

1. **Use auto-detect**: The tool automatically detects log format, so you usually don't need `--format`
2. **Start with defaults**: Default thresholds work well for most cases
3. **Check examples**: Test with provided example files first
4. **JSON for automation**: Use JSON format for integration with other tools
5. **CSV for analysis**: Use CSV format for spreadsheet analysis

## Getting Help

```bash
# Show help
python main.py --help
```

## Next Steps

- Read [README.md](README.md) for detailed documentation
- Check [API.md](API.md) for programmatic usage
- See [ARCHITECTURE.md](ARCHITECTURE.md) for system design
- Review [CONTRIBUTING.md](CONTRIBUTING.md) to contribute

## Troubleshooting

**Problem**: "No log entries were parsed"
- **Solution**: Check log format, try specifying `--format` explicitly

**Problem**: "Permission denied"
- **Solution**: Copy log file to current directory or use sudo

**Problem**: "Log file not found"
- **Solution**: Use absolute path or check file location

For more help, see the [Troubleshooting section](README.md#troubleshooting) in README.md.
