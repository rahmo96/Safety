# Plugin-Based Architecture Documentation

## Overview

The Log Analysis Tool has been refactored to use a **Plugin-Based Architecture** following the **Open/Closed Principle** from SOLID design principles. This architecture allows the system to be:

- **Open for Extension**: New security detection rules can be added without modifying existing code
- **Closed for Modification**: The core detection engine remains unchanged when adding new rules

## Architecture Components

### 1. Base Interface (`base_rule.py`)

The `SecurityRule` abstract base class defines the contract that all security rules must follow:

```python
from abc import ABC, abstractmethod

class SecurityRule(ABC):
    def __init__(self, rule_name: str, severity: str):
        self.rule_name = rule_name
        self.severity = severity
    
    @abstractmethod
    def evaluate(self, log_entry: Dict) -> Optional[Dict]:
        pass
```

**Key Points:**
- All rules must inherit from `SecurityRule`
- Must implement the `evaluate()` method
- Each rule has a name and severity level

### 2. Rule Implementations (`rules/` directory)

Individual security rules are implemented as separate classes in the `rules/` directory:

- `BruteForceRule`: Detects multiple failed login attempts
- `PathTraversalRule`: Detects unauthorized access to sensitive paths
- `UnusualTrafficRule`: Detects unusual traffic patterns

### 3. Dynamic Discovery Engine (`detector.py`)

The `SecurityDetector` class automatically:

1. **Scans** the `rules/` directory for Python modules
2. **Imports** all modules containing `SecurityRule` subclasses
3. **Instantiates** all discovered rule classes
4. **Executes** all rules during analysis

## Creating a New Rule

### Step 1: Create Rule File

Create a new Python file in the `rules/` directory:

```python
# rules/my_custom_rule.py
from typing import Dict, Optional
from base_rule import SecurityRule

class MyCustomRule(SecurityRule):
    def __init__(self):
        super().__init__(
            rule_name='my_custom_rule',
            severity='high'
        )
    
    def evaluate(self, log_entry: Dict) -> Optional[Dict]:
        # Your detection logic here
        if threat_detected:
            return {
                'type': 'my_custom_threat',
                'severity': self.severity,
                'description': 'Threat description',
                # ... other fields
            }
        return None
```

### Step 2: That's It!

The rule will be automatically:
- Discovered on startup
- Loaded and instantiated
- Executed during analysis

**No modifications to core code required!**

## Rule Types

### Immediate Detection Rules

Rules that evaluate each log entry independently:

```python
def evaluate(self, log_entry: Dict) -> Optional[Dict]:
    # Check log entry
    if condition:
        return event_dict
    return None
```

**Example:** `PathTraversalRule` - detects unauthorized access immediately

### Aggregation Rules

Rules that need to process all logs before generating events:

```python
def evaluate(self, log_entry: Dict) -> Optional[Dict]:
    # Accumulate data
    self.accumulate_data(log_entry)
    return None  # Events generated in finalize()

def finalize(self) -> List[Dict]:
    # Generate events after all logs processed
    return events_list

def reset(self):
    # Reset state for new analysis
    pass
```

**Example:** `BruteForceRule`, `UnusualTrafficRule` - need to count occurrences

## Configuration

Rules can receive configuration through the `SecurityDetector` constructor:

```python
detector = SecurityDetector(
    failed_login_threshold=5,      # → BruteForceRule
    suspicious_paths=['/admin'],   # → PathTraversalRule
    traffic_threshold=100          # → UnusualTrafficRule
)
```

The detector automatically matches rule class names to configuration parameters.

## Example: Adding a New Rule

Let's add a rule to detect SQL injection attempts:

### 1. Create `rules/sql_injection_rule.py`:

```python
from typing import Dict, Optional
from base_rule import SecurityRule

class SqlInjectionRule(SecurityRule):
    def __init__(self):
        super().__init__(
            rule_name='sql_injection',
            severity='critical'
        )
        self.sql_patterns = [
            'union select', 'drop table', '1=1', 
            'or 1=1', 'exec(', 'script>'
        ]
    
    def evaluate(self, log_entry: Dict) -> Optional[Dict]:
        path = log_entry.get('path', '').lower()
        query = log_entry.get('query', '').lower()
        
        for pattern in self.sql_patterns:
            if pattern in path or pattern in query:
                return {
                    'type': 'sql_injection_attempt',
                    'severity': self.severity,
                    'ip': log_entry.get('ip', 'unknown'),
                    'path': path,
                    'description': f'Potential SQL injection detected in {path}'
                }
        return None
```

### 2. Run the tool:

```bash
python main.py access.log
```

The new rule is automatically loaded and executed!

## Benefits of Plugin Architecture

### 1. **Extensibility**
- Add new detection rules without modifying core code
- Each rule is self-contained and testable

### 2. **Maintainability**
- Rules are isolated from each other
- Changes to one rule don't affect others

### 3. **Testability**
- Each rule can be tested independently
- Mock log entries for unit testing

### 4. **Scalability**
- Add unlimited rules without performance degradation
- Rules can be enabled/disabled easily

### 5. **SOLID Principles**
- **Single Responsibility**: Each rule has one purpose
- **Open/Closed**: Open for extension, closed for modification
- **Dependency Inversion**: Depends on abstraction (SecurityRule)

## Rule Discovery Process

```
1. SecurityDetector.__init__()
   ↓
2. _load_rules()
   ↓
3. Scan rules/ directory
   ↓
4. Import each .py file
   ↓
5. Find SecurityRule subclasses
   ↓
6. Instantiate each rule
   ↓
7. Store in self.rules[]
```

## Best Practices

### 1. Rule Naming
- Use descriptive class names: `BruteForceRule`, not `Rule1`
- Use descriptive rule_name: `'brute_force'`, not `'rule1'`

### 2. Error Handling
- Rules should handle missing fields gracefully
- Return `None` if data is insufficient

### 3. Performance
- Keep `evaluate()` methods fast
- Use aggregation (`finalize()`) for expensive operations

### 4. Documentation
- Document what each rule detects
- Include examples in docstrings

## Troubleshooting

### Rule Not Loading

**Problem:** Rule not discovered by detector

**Solutions:**
- Ensure file is in `rules/` directory
- Check class inherits from `SecurityRule`
- Verify class is not abstract
- Check for import errors in rule file

### Rule Not Executing

**Problem:** Rule loaded but no events generated

**Solutions:**
- Check `evaluate()` returns proper event dict
- Verify log entries have required fields
- Test rule independently with sample data

### Configuration Not Applied

**Problem:** Rule not receiving configuration

**Solutions:**
- Check rule class name matches pattern in `_instantiate_rule()`
- Add custom instantiation logic if needed
- Use default values in rule constructor

## Migration from Old Architecture

The old `detector.py` methods have been moved to rule classes:

| Old Method | New Rule Class |
|------------|----------------|
| `detect_failed_logins()` | `BruteForceRule` |
| `detect_unauthorized_access()` | `PathTraversalRule` |
| `detect_unusual_traffic()` | `UnusualTrafficRule` |

The `SecurityDetector` interface remains compatible, so `main.py` requires no changes!

## Future Enhancements

Potential improvements to the plugin architecture:

1. **Rule Priority**: Execute rules in priority order
2. **Rule Dependencies**: Rules that depend on other rules
3. **Rule Configuration File**: YAML/JSON configuration for rules
4. **Rule Enable/Disable**: Toggle rules without removing files
5. **Rule Metrics**: Track rule performance and effectiveness
