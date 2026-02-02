# Contributing Guidelines

Thank you for your interest in contributing to the Log Analysis Tool for Security Events!

## Development Setup

1. Clone or download the repository
2. Ensure Python 3.6+ is installed
3. No external dependencies required (uses only standard library)

## Code Style

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions focused and modular
- Add comments for complex logic

## Adding New Features

### Adding a New Log Format

1. **Add regex pattern** to `parser.py`:
   ```python
   NEW_FORMAT_PATTERN = re.compile(r'...')
   ```

2. **Implement parse method**:
   ```python
   def parse_new_format(self, line: str) -> Optional[Dict]:
       match = self.NEW_FORMAT_PATTERN.match(line)
       if match:
           return {...}
       return None
   ```

3. **Update detection**:
   - Add to `detect_format()` method
   - Add to `parse_line()` method

4. **Update documentation**:
   - Add format example to README.md
   - Update API.md
   - Create example log file

### Adding a New Detection Rule

1. **Create detection method** in `detector.py`:
   ```python
   def detect_new_threat(self, logs: List[Dict]) -> List[Dict]:
       events = []
       # Detection logic
       return events
   ```

2. **Add to analyze()** method:
   ```python
   new_threats = self.detect_new_threat(logs)
   self.detected_events.extend(new_threats)
   ```

3. **Define event structure**:
   - Type identifier
   - Severity level
   - Required fields

4. **Update documentation**:
   - Add to API.md
   - Update README.md with new detection type

### Adding a New Report Format

1. **Add generation method** to `reporter.py`:
   ```python
   def generate_xml(self, output_path: str) -> None:
       # XML generation logic
   ```

2. **Update CLI** in `main.py`:
   - Add format option
   - Add output handling

3. **Update documentation**:
   - Add format description
   - Add usage examples

## Testing

### Manual Testing

Test with various log formats:
```bash
# Test Apache format
python main.py example_apache.log

# Test Syslog format
python main.py example_syslog.log --format syslog

# Test Systemd format
python main.py example_systemd.log --format systemd
```

### Test Cases to Consider

- Empty log files
- Malformed log entries
- Very large log files
- Mixed log formats
- Edge cases (IPv6, special characters)
- Various security event scenarios

## Documentation

### Code Documentation
- Add docstrings to all functions
- Include parameter descriptions
- Include return value descriptions
- Add usage examples in docstrings

### User Documentation
- Update README.md for new features
- Add examples to README.md
- Update API.md for API changes
- Update ARCHITECTURE.md for design changes

## Pull Request Process

1. Create a feature branch
2. Make your changes
3. Test thoroughly
4. Update documentation
5. Submit pull request with description

## Reporting Issues

When reporting issues, please include:
- Log file format
- Error messages
- Steps to reproduce
- Expected behavior
- Actual behavior
- Python version

## Questions?

Feel free to open an issue for questions or discussions about contributions.
