from .base_rule import SecurityRule
import re

class PrivilegedAccessRule(SecurityRule):
    def __init__(self):
        super().__init__(rule_name='privileged_access', severity='medium')
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def evaluate(self, log_entry):
        msg = (log_entry.get('message') or '').lower()
        if 'session opened for user root' in msg or 'sudo:' in msg:
            message_text = log_entry.get('message', '')
            ip_matches = self.ip_pattern.findall(message_text)
            ip = ip_matches[-1] if ip_matches else 'internal'
            
            return {
                'type': 'privileged_access',
                'severity': self.severity,
                'ip': ip,
                'timestamp': log_entry.get('timestamp', 'unknown'),
                'description': f'Privileged session opened/sudo used: {message_text[:50]}...'
            }
        return None