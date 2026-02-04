

import re
from typing import Dict, Optional, List
from collections import defaultdict
from .base_rule import SecurityRule


class UnusualTrafficRule(SecurityRule):
    """
    Detects unusual traffic patterns such as high request volumes or suspicious patterns.
    
    Monitors request counts per IP and identifies potential scraping or DDoS patterns.
    """
    
    def __init__(self, threshold: int = 100):
        """
        Initialize the unusual traffic detection rule.
        
        Args:
            threshold: Number of requests per IP to flag as unusual (default: 100)
        """
        super().__init__(rule_name='unusual_traffic', severity='medium')
        self.threshold = threshold
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        # Accumulate traffic data
        self.ip_counts = defaultdict(int)
        self.ip_methods = defaultdict(lambda: defaultdict(int))
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
                return ip_matches[-1]
        
        return 'unknown'
    
    def evaluate(self, log_entry: Dict) -> Optional[Dict]:
        """
        Evaluate a log entry for unusual traffic patterns.
        
        This method accumulates traffic data per IP. The actual event generation
        happens in finalize() after all logs are processed.
        
        Args:
            log_entry: Parsed log entry
            
        Returns:
            None (events are generated in finalize())
        """
        self.processed_logs.append(log_entry)
        
        ip = self._extract_ip(log_entry)
        if ip != 'unknown':
            self.ip_counts[ip] += 1
            method = log_entry.get('method', 'unknown')
            self.ip_methods[ip][method] += 1
        
        return None  # Events generated in finalize()
    
    def finalize(self) -> List[Dict]:
        """
        Generate events after all log entries have been processed.
        
        Returns:
            List of detection events for IPs exceeding threshold
        """
        events = []
        
        for ip, count in self.ip_counts.items():
            if count >= self.threshold:
                # Analyze request patterns
                methods = self.ip_methods[ip]
                method_distribution = {m: c for m, c in methods.items()}
                
                # Check for suspicious patterns
                suspicious_patterns = []
                if methods.get('POST', 0) > count * 0.7:  # Mostly POST requests
                    suspicious_patterns.append('High POST request ratio')
                if methods.get('GET', 0) > count * 0.9:  # Mostly GET requests (scraping)
                    suspicious_patterns.append('Potential web scraping')
                
                events.append({
                    'type': 'unusual_traffic',
                    'severity': self.severity,
                    'ip': ip,
                    'request_count': count,
                    'threshold': self.threshold,
                    'method_distribution': method_distribution,
                    'patterns': suspicious_patterns,
                    'description': f'Unusual traffic volume from {ip}: {count} requests'
                })
        
        return events
    
    def reset(self):
        """Reset accumulated state for new analysis."""
        self.ip_counts.clear()
        self.ip_methods.clear()
        self.processed_logs.clear()
