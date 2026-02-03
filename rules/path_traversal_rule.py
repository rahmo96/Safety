import re
from typing import Dict, Optional, List
from base_rule import SecurityRule

class PathTraversalRule(SecurityRule):
    def __init__(self, suspicious_paths: List[str] = None):
        super().__init__(rule_name='path_traversal', severity='high')
        self.suspicious_paths = suspicious_paths or [
            '/admin', '/wp-admin', '/phpmyadmin', '/.env',
            '/config', '/etc/passwd', '/root', '/.ssh'
        ]
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    def _extract_ip(self, log: Dict) -> str:
        if 'ip' in log and log['ip'] != 'unknown':
            return log['ip']
        
        message = log.get('message', '') or log.get('raw', '')
        if message:
            ip_matches = self.ip_pattern.findall(message)
            if ip_matches:
                return ip_matches[-1]
        return 'unknown'
    
    def evaluate(self, log_entry: Dict) -> Optional[Dict]:
        path_content = (log_entry.get('path') or log_entry.get('message') or '').lower()
        ip = self._extract_ip(log_entry)
        status = log_entry.get('status', 0)
        
        if not path_content or ip == 'unknown':
            return None
        
        for suspicious_path in self.suspicious_paths:
            if suspicious_path.lower() in path_content:
                severity = 'high'
                if status in [200, 301, 302]:
                    severity = 'critical'
                
                return {
                    'type': 'path_traversal',
                    'severity': severity,
                    'ip': ip,
                    'path': suspicious_path,
                    'timestamp': log_entry.get('timestamp', 'unknown'),
                    'line_number': log_entry.get('line_number', 0),
                    'description': f'Suspicious access attempt to {suspicious_path} from {ip}'
                }
        return None