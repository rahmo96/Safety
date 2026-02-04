
import re
from typing import Dict, Optional, List
from collections import defaultdict
from base_rule import SecurityRule


class BruteForceRule(SecurityRule):
    """
    Detects brute force attacks by identifying multiple failed login attempts.
    
    This rule aggregates failed login attempts per IP address and triggers
    an alert when the threshold is exceeded.
    """
    
    def __init__(self, threshold: int = 5):
        """
        Initialize the brute force detection rule.
        
        Args:
            threshold: Number of failed login attempts to trigger alert (default: 5)
        """
        super().__init__(rule_name='brute_force', severity='high')
        self.threshold = threshold
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        # Accumulate failures across all log entries
        self.ip_failures = defaultdict(int)
        self.ip_details = defaultdict(list)
        self.processed_logs = []
    
    def _extract_ip(self, log: Dict) -> str:
        """Extract IP address from log entry."""
        # Apache format has direct IP field
        if 'ip' in log and log['ip'] != 'unknown':
            return log['ip']
        
        # Syslog format: extract IP from message
        message = log.get('message', '') or log.get('raw', '')
        if message:
            ip_matches = self.ip_pattern.findall(message)
            if ip_matches:
                return ip_matches[-1]  # Return last IP found (usually the source)
        
        return 'unknown'
    
    def evaluate(self, log_entry: Dict) -> Optional[Dict]:
        """
        Evaluate a log entry for failed login attempts.
        
        This method accumulates failures per IP. The actual event generation
        happens in finalize() after all logs are processed.
        
        Args:
            log_entry: Parsed log entry
            
        Returns:
            None (events are generated in finalize())
        """
        # Store log for final processing
        self.processed_logs.append(log_entry)
        
        # Handle None values - some log formats may not have 'message' field
        message = (log_entry.get('message') or log_entry.get('raw') or '').lower()
        status = log_entry.get('status', 0)
        ip = self._extract_ip(log_entry)
        
        # Check for failed login indicators
        is_failed_login = False
        
        # Check status codes
        if status in [401, 403]:
            is_failed_login = True
        
        # Check message patterns
        failed_login_patterns = [
            'failed password', 'authentication failure', 'invalid user',
            'login failed', 'access denied', 'unauthorized', '401', '403'
        ]
        
        if any(pattern in message for pattern in failed_login_patterns):
            is_failed_login = True
        
        if is_failed_login and ip != 'unknown':
            self.ip_failures[ip] += 1
            self.ip_details[ip].append({
                'timestamp': log_entry.get('timestamp', 'unknown'),
                'line_number': log_entry.get('line_number', 0),
                'message': log_entry.get('message', log_entry.get('raw', ''))
            })
        
        return None  # Events generated in finalize()
    
    def finalize(self) -> List[Dict]:
        """
        Generate events after all log entries have been processed.
        
        Returns:
            List of detection events for IPs exceeding threshold
        """
        events = []
        
        for ip, count in self.ip_failures.items():
            if count >= self.threshold:
                events.append({
                    'type': 'failed_login_attempts',
                    'severity': self.severity,
                    'ip': ip,
                    'count': count,
                    'threshold': self.threshold,
                    'details': self.ip_details[ip],
                    'description': f'Brute force detected: {ip} attempted {count} failed logins'
                })
        
        return events
    
    def reset(self):
        """Reset accumulated state for new analysis."""
        self.ip_failures.clear()
        self.ip_details.clear()
        self.processed_logs.clear()
