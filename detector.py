"""
Security Event Detector Module
Implements plugin-based security detection using dynamically loaded rules.
Follows the Open/Closed Principle: open for extension, closed for modification.
"""

import os
import importlib
import inspect
from typing import List, Dict
from collections import defaultdict
from base_rule import SecurityRule


class SecurityDetector:
    """
    Detects security events in parsed logs using dynamically loaded rules.
    
    This class automatically discovers and loads all SecurityRule implementations
    from the rules/ directory, demonstrating the Open/Closed Principle.
    New security rules can be added by simply creating a new file in rules/
    without modifying this class.
    """
    
    def __init__(self, 
                 failed_login_threshold: int = 5,
                 suspicious_paths: List[str] = None,
                 traffic_threshold: int = 100,
                 rules_directory: str = 'rules'):
        """
        Initialize the security detector with dynamic rule loading.
        
        Args:
            failed_login_threshold: Threshold for brute force detection (passed to BruteForceRule)
            suspicious_paths: List of sensitive paths (passed to PathTraversalRule)
            traffic_threshold: Threshold for unusual traffic (passed to UnusualTrafficRule)
            rules_directory: Directory containing rule modules (default: 'rules')
        """
        self.rules_directory = rules_directory
        self.rules = []
        self.detected_events = []
        
        # Configuration for rules (can be passed to rule constructors)
        self.config = {
            'failed_login_threshold': failed_login_threshold,
            'suspicious_paths': suspicious_paths or [
                '/admin', '/wp-admin', '/phpmyadmin', '/.env',
                '/config', '/etc/passwd', '/root', '/.ssh'
            ],
            'traffic_threshold': traffic_threshold
        }
        
        # Dynamically load all rules
        self._load_rules()
    
    def _load_rules(self):
        """
        Dynamically discover and load all SecurityRule implementations.
        
        Scans the rules/ directory for Python modules and automatically
        instantiates all classes that inherit from SecurityRule.
        """
        if not os.path.exists(self.rules_directory):
            print(f"Warning: Rules directory '{self.rules_directory}' not found. No rules loaded.")
            return
        
        # Get all Python files in rules directory
        rule_files = [
            f[:-3]  # Remove .py extension
            for f in os.listdir(self.rules_directory)
            if f.endswith('.py') and not f.startswith('__')
        ]
        
        if not rule_files:
            print(f"Warning: No rule files found in '{self.rules_directory}' directory.")
            return
        
        # Import and instantiate rules
        for rule_file in rule_files:
            try:
                # Import the module
                module = importlib.import_module(f'{self.rules_directory}.{rule_file}')
                
                # Find all classes in the module that inherit from SecurityRule
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(obj, SecurityRule) and 
                        obj is not SecurityRule and 
                        obj.__module__ == module.__name__):
                        
                        # Instantiate the rule with appropriate configuration
                        rule_instance = self._instantiate_rule(obj)
                        if rule_instance:
                            self.rules.append(rule_instance)
                            print(f"Loaded rule: {rule_instance.rule_name} ({obj.__name__})")
            
            except Exception as e:
                print(f"Warning: Failed to load rule from '{rule_file}': {str(e)}")
                continue
        
        if not self.rules:
            print("Warning: No security rules were loaded.")
        else:
            print(f"Successfully loaded {len(self.rules)} security rule(s)")
    
    def _instantiate_rule(self, rule_class):
        """
        Instantiate a rule class with appropriate configuration.
        
        Args:
            rule_class: The rule class to instantiate
            
        Returns:
            Instantiated rule object or None if instantiation fails
        """
        try:
            # Try to match rule class names to configuration
            class_name = rule_class.__name__.lower()
            
            if 'bruteforce' in class_name or 'brute_force' in class_name:
                return rule_class(threshold=self.config['failed_login_threshold'])
            elif 'windows' in class_name and ('bruteforce' in class_name or 'brute_force' in class_name):
                # Windows brute force rule also uses failed_login_threshold
                return rule_class(threshold=self.config['failed_login_threshold'])
            elif 'path' in class_name or 'traversal' in class_name:
                return rule_class(suspicious_paths=self.config['suspicious_paths'])
            elif 'traffic' in class_name or 'unusual' in class_name:
                return rule_class(threshold=self.config['traffic_threshold'])
            else:
                # Default: try to instantiate with no arguments
                return rule_class()
        
        except Exception as e:
            print(f"Warning: Failed to instantiate {rule_class.__name__}: {str(e)}")
            return None
    
    def analyze(self, logs: List[Dict]) -> Dict:
        """
        Perform comprehensive security analysis on logs using all loaded rules.
        
        Args:
            logs: List of parsed log entries
            
        Returns:
            Dictionary containing all detected events and statistics
        """
        self.detected_events = []
        
        # Reset rules that have state (for aggregation-based rules)
        for rule in self.rules:
            if hasattr(rule, 'reset'):
                rule.reset()
        
        # Process each log entry through all rules
        for log_entry in logs:
            for rule in self.rules:
                event = rule.evaluate(log_entry)
                if event:
                    self.detected_events.append(event)
        
        # Finalize rules that need aggregation (e.g., brute force, traffic)
        for rule in self.rules:
            if hasattr(rule, 'finalize'):
                events = rule.finalize()
                if events:
                    self.detected_events.extend(events)
        
        # Calculate statistics
        total_events = len(self.detected_events)
        severity_counts = defaultdict(int)
        event_types = defaultdict(int)
        
        for event in self.detected_events:
            severity_counts[event['severity']] += 1
            event_types[event['type']] += 1
        
        # Get top offending IPs
        ip_counts = defaultdict(int)
        for event in self.detected_events:
            if 'ip' in event:
                ip_counts[event['ip']] += 1
        
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_events': total_events,
            'events': self.detected_events,
            'statistics': {
                'severity_distribution': dict(severity_counts),
                'event_type_distribution': dict(event_types),
                'top_offending_ips': [{'ip': ip, 'event_count': count} for ip, count in top_ips]
            }
        }
    
    def get_events(self) -> List[Dict]:
        """Return the list of detected events."""
        return self.detected_events
    
    def get_loaded_rules(self) -> List[SecurityRule]:
        """Return list of loaded security rules."""
        return self.rules
