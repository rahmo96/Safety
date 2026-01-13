"""
Security Event Detector Module
Implements rules to identify security threats in parsed logs.
"""

import re
from typing import List, Dict, Set, Optional
from collections import defaultdict
from datetime import datetime, timedelta


class SecurityDetector:
    """Detects security events in parsed logs."""
    
    def __init__(self, 
                 failed_login_threshold: int = 5,
                 suspicious_paths: List[str] = None,
                 traffic_threshold: int = 100):
        """
        Initialize the security detector.
        
        Args:
            failed_login_threshold: Number of failed login attempts to trigger alert
            suspicious_paths: List of sensitive paths to monitor
            traffic_threshold: Number of requests per IP to flag as unusual traffic
        """
        self.failed_login_threshold = failed_login_threshold
        self.suspicious_paths = suspicious_paths or [
            '/admin', '/wp-admin', '/phpmyadmin', '/.env', 
            '/config', '/etc/passwd', '/root', '/.ssh'
        ]
        self.traffic_threshold = traffic_threshold
        self.detected_events = []
        # IP address pattern for extraction from messages
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    def _extract_ip(self, log: Dict) -> str:
        """
        Extract IP address from log entry.
        Handles both Apache (direct IP field) and Syslog (IP in message) formats.
        
        Args:
            log: Parsed log entry
            
        Returns:
            IP address string or 'unknown'
        """
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
    
    def detect_failed_logins(self, logs: List[Dict]) -> List[Dict]:
        """
        Detect brute force attempts (multiple failed login attempts).
        
        Args:
            logs: List of parsed log entries
            
        Returns:
            List of detected failed login events
        """
        events = []
        ip_failures = defaultdict(int)
        ip_details = defaultdict(list)
        
        # Patterns for failed login attempts
        failed_login_patterns = [
            'failed password', 'authentication failure', 'invalid user',
            'login failed', 'access denied', 'unauthorized', '401', '403'
        ]
        
        for log in logs:
            message = log.get('message', '').lower()
            status = log.get('status', 0)
            ip = self._extract_ip(log)
            
            # Check for failed login indicators
            is_failed_login = False
            
            # Check status codes
            if status in [401, 403]:
                is_failed_login = True
            
            # Check message patterns
            if any(pattern in message for pattern in failed_login_patterns):
                is_failed_login = True
            
            if is_failed_login:
                ip_failures[ip] += 1
                ip_details[ip].append({
                    'timestamp': log.get('timestamp', 'unknown'),
                    'line_number': log.get('line_number', 0),
                    'message': log.get('message', log.get('raw', ''))
                })
        
        # Generate events for IPs exceeding threshold
        for ip, count in ip_failures.items():
            if count >= self.failed_login_threshold:
                events.append({
                    'type': 'failed_login_attempts',
                    'severity': 'high',
                    'ip': ip,
                    'count': count,
                    'threshold': self.failed_login_threshold,
                    'details': ip_details[ip],
                    'description': f'Brute force detected: {ip} attempted {count} failed logins'
                })
        
        return events
    
    def detect_unauthorized_access(self, logs: List[Dict]) -> List[Dict]:
        """
        Detect unauthorized access attempts to sensitive paths.
        
        Args:
            logs: List of parsed log entries
            
        Returns:
            List of detected unauthorized access events
        """
        events = []
        ip_accesses = defaultdict(lambda: defaultdict(int))
        
        for log in logs:
            path = log.get('path', '').lower()
            ip = self._extract_ip(log)
            status = log.get('status', 0)
            
            # Check if path matches suspicious patterns
            for suspicious_path in self.suspicious_paths:
                if suspicious_path.lower() in path:
                    # Flag both successful and failed attempts
                    if status in [200, 301, 302]:  # Successful access
                        ip_accesses[ip][suspicious_path] += 1
                        events.append({
                            'type': 'unauthorized_access',
                            'severity': 'critical',
                            'ip': ip,
                            'path': path,
                            'status': status,
                            'timestamp': log.get('timestamp', 'unknown'),
                            'line_number': log.get('line_number', 0),
                            'description': f'Unauthorized access attempt to {path} from {ip}'
                        })
                    elif status in [401, 403, 404]:  # Failed but suspicious
                        ip_accesses[ip][suspicious_path] += 1
                        events.append({
                            'type': 'unauthorized_access_attempt',
                            'severity': 'high',
                            'ip': ip,
                            'path': path,
                            'status': status,
                            'timestamp': log.get('timestamp', 'unknown'),
                            'line_number': log.get('line_number', 0),
                            'description': f'Suspicious access attempt to {path} from {ip}'
                        })
        
        return events
    
    def detect_unusual_traffic(self, logs: List[Dict]) -> List[Dict]:
        """
        Detect unusual traffic volume or patterns.
        
        Args:
            logs: List of parsed log entries
            
        Returns:
            List of detected unusual traffic events
        """
        events = []
        ip_counts = defaultdict(int)
        ip_methods = defaultdict(lambda: defaultdict(int))
        
        # Count requests per IP
        for log in logs:
            ip = self._extract_ip(log)
            if ip != 'unknown':
                ip_counts[ip] += 1
                method = log.get('method', 'unknown')
                ip_methods[ip][method] += 1
        
        # Identify IPs with unusual traffic
        for ip, count in ip_counts.items():
            if count >= self.traffic_threshold:
                # Analyze request patterns
                methods = ip_methods[ip]
                method_distribution = {m: c for m, c in methods.items()}
                
                # Check for suspicious patterns
                suspicious_patterns = []
                if methods.get('POST', 0) > count * 0.7:  # Mostly POST requests
                    suspicious_patterns.append('High POST request ratio')
                if methods.get('GET', 0) > count * 0.9:  # Mostly GET requests (scraping)
                    suspicious_patterns.append('Potential web scraping')
                
                events.append({
                    'type': 'unusual_traffic',
                    'severity': 'medium',
                    'ip': ip,
                    'request_count': count,
                    'threshold': self.traffic_threshold,
                    'method_distribution': method_distribution,
                    'patterns': suspicious_patterns,
                    'description': f'Unusual traffic volume from {ip}: {count} requests'
                })
        
        return events
    
    def analyze(self, logs: List[Dict]) -> Dict:
        """
        Perform comprehensive security analysis on logs.
        
        Args:
            logs: List of parsed log entries
            
        Returns:
            Dictionary containing all detected events and statistics
        """
        self.detected_events = []
        
        # Run all detection methods
        failed_logins = self.detect_failed_logins(logs)
        unauthorized_access = self.detect_unauthorized_access(logs)
        unusual_traffic = self.detect_unusual_traffic(logs)
        
        # Combine all events
        self.detected_events = failed_logins + unauthorized_access + unusual_traffic
        
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

