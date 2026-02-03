"""
Example Custom Rule
Demonstrates how to create a new security detection rule.

This is an example rule that can be used as a template for creating
new security detection rules. Simply copy this file, modify the logic,
and place it in the rules/ directory - it will be automatically discovered!
"""

from typing import Dict, Optional
from base_rule import SecurityRule


class ExampleCustomRule(SecurityRule):
    """
    Example custom security rule demonstrating the plugin architecture.
    
    This rule detects suspicious user agents (e.g., scanners, bots).
    To use this as a template:
    1. Rename the class to something descriptive
    2. Update the rule_name in __init__
    3. Implement the evaluate() method with your detection logic
    4. Place the file in the rules/ directory
    """
    
    def __init__(self):
        """
        Initialize the custom rule.
        
        You can add parameters here to configure the rule behavior.
        """
        super().__init__(rule_name='suspicious_user_agent', severity='medium')
        
        # Example: List of suspicious user agent patterns
        self.suspicious_patterns = [
            'scanner', 'bot', 'crawler', 'spider', 'hack', 'exploit'
        ]
    
    def evaluate(self, log_entry: Dict) -> Optional[Dict]:
        """
        Evaluate a log entry for suspicious user agents.
        
        This is where you implement your detection logic.
        Return a detection event if a threat is found, None otherwise.
        
        Args:
            log_entry: Parsed log entry
            
        Returns:
            Detection event dictionary or None
        """
        # Check if this is an Apache log with user_agent field
        # Handle None values - systemd/syslog logs don't have 'user_agent' field
        user_agent = (log_entry.get('user_agent') or log_entry.get('message') or '').lower()
        
        if not user_agent:
            return None
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern in user_agent:
                ip = log_entry.get('ip', 'unknown')
                return {
                    'type': 'suspicious_user_agent',
                    'severity': self.severity,
                    'ip': ip,
                    'user_agent': user_agent,
                    'timestamp': log_entry.get('timestamp', 'unknown'),
                    'line_number': log_entry.get('line_number', 0),
                    'description': f'Suspicious user agent detected from {ip}: {user_agent[:50]}'
                }
        
        return None
