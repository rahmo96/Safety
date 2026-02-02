"""
Base Rule Interface
Abstract Base Class for security detection rules following the Open/Closed Principle.
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional


class SecurityRule(ABC):
    """
    Abstract base class for security detection rules.
    
    This class defines the interface that all security rules must implement,
    following the Open/Closed Principle: open for extension, closed for modification.
    
    To create a new security rule:
    1. Inherit from SecurityRule
    2. Implement the evaluate() method
    3. Place the file in the rules/ directory
    4. The rule will be automatically discovered and loaded
    """
    
    def __init__(self, rule_name: str, severity: str):
        """
        Initialize the security rule.
        
        Args:
            rule_name: Name identifier for this rule
            severity: Default severity level ('critical', 'high', 'medium', 'low')
        """
        self.rule_name = rule_name
        self.severity = severity
    
    @abstractmethod
    def evaluate(self, log_entry: Dict) -> Optional[Dict]:
        """
        Evaluate a single log entry for security threats.
        
        This method is called for each log entry during analysis.
        If a threat is detected, return a detection event dictionary.
        If no threat is detected, return None.
        
        Args:
            log_entry: A single parsed log entry dictionary
            
        Returns:
            Detection event dictionary or None if no threat detected.
            Event dictionary should contain at minimum:
            - 'type': Event type identifier
            - 'severity': Severity level
            - 'description': Human-readable description
            - Additional fields specific to the detection
        """
        pass
    
    def __repr__(self) -> str:
        """String representation of the rule."""
        return f"{self.__class__.__name__}(name='{self.rule_name}', severity='{self.severity}')"
