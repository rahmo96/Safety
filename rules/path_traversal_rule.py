"""
Path Traversal Detection Rule
Detects unauthorized access attempts to sensitive paths.
"""

import re
from typing import Dict, Optional, List
from base_rule import SecurityRule


class PathTraversalRule(SecurityRule):
    """
    Detects unauthorized access attempts to sensitive paths.
    
    Monitors access to sensitive paths such as /admin, /wp-admin, etc.
    Distinguishes between successful access (critical) and failed attempts (high).
    """
    
    def __init__(self, suspicious_paths: List[str] = None):
        """
        Initialize the path traversal detection rule.
        
        Args:
            suspicious_paths: List of sensitive paths to monitor.
                              Default includes common admin and sensitive paths.
        """
        super().__init__(rule_name='path_traversal', severity='high')
        self.suspicious_paths = suspicious_paths or [
            '/admin', '/wp-admin', '/phpmyadmin', '/.env',
            '/config', '/etc/passwd', '/root', '/.ssh'
        ]
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
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
                return ip_matches[-1]
        
        return 'unknown'
    
    def evaluate(self, log_entry: Dict) -> Optional[Dict]:
        """
        Evaluate a log entry for unauthorized access attempts.
        
        Args:
            log_entry: Parsed log entry
            
        Returns:
            Detection event dictionary if threat detected, None otherwise
        """
        path = log_entry.get('path', '').lower()
        ip = self._extract_ip(log_entry)
        status = log_entry.get('status', 0)
        
        if ip == 'unknown':
            return None
        
        # Check if path matches suspicious patterns
        for suspicious_path in self.suspicious_paths:
            if suspicious_path.lower() in path:
                # Successful access (critical severity)
                if status in [200, 301, 302]:
                    return {
                        'type': 'unauthorized_access',
                        'severity': 'critical',
                        'ip': ip,
                        'path': path,
                        'status': status,
                        'timestamp': log_entry.get('timestamp', 'unknown'),
                        'line_number': log_entry.get('line_number', 0),
                        'description': f'Unauthorized access attempt to {path} from {ip}'
                    }
                # Failed but suspicious (high severity)
                elif status in [401, 403, 404]:
                    return {
                        'type': 'unauthorized_access_attempt',
                        'severity': 'high',
                        'ip': ip,
                        'path': path,
                        'status': status,
                        'timestamp': log_entry.get('timestamp', 'unknown'),
                        'line_number': log_entry.get('line_number', 0),
                        'description': f'Suspicious access attempt to {path} from {ip}'
                    }
        
        return None
