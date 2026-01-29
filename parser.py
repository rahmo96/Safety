"""
Log Parser Module
Handles parsing of common log formats (Syslog and Apache) using regex.
Supports Ubuntu system logs: /var/log/syslog, /var/log/auth.log, /var/log/kern.log
"""

import re
from typing import List, Dict, Optional
from datetime import datetime


class LogParser:
    """Parser for common log formats."""
    
    # Syslog pattern: timestamp hostname service[pid]: message
    # Supports Ubuntu logs: /var/log/syslog, /var/log/auth.log, /var/log/kern.log
    # Examples:
    #   Dec 25 10:15:30 ubuntu-server sshd[1234]: Failed password...
    #   Dec 25 10:15:30 ubuntu-server kernel: [12345.678] message
    #   Dec 25 10:15:30 ubuntu-server systemd[1]: Started service
    SYSLOG_PATTERN = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>[\w\.-]+)\s+'
        r'(?P<service>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.*)'
    )
    
    # Kernel log pattern (special case for Ubuntu kernel logs)
    KERNEL_PATTERN = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>[\w\.-]+)\s+'
        r'kernel:\s+\[(?P<kern_time>\d+\.\d+)\]\s+'
        r'(?P<message>.*)'
    )
    
    # Apache Common Log Format: IP - - [timestamp] "method path protocol" status size
    APACHE_PATTERN = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'(?P<ident>[\w\-]+|\-)\s+'
        r'(?P<user>[\w\-]+|\-)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>[^\s"]+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+|\-)'
    )
    
    def __init__(self, log_format: str = 'auto'):
        """
        Initialize the parser.
        
        Args:
            log_format: Format type ('syslog', 'apache', or 'auto' for detection)
        """
        self.log_format = log_format
        self.parsed_logs = []
    
    def detect_format(self, line: str) -> Optional[str]:
        """
        Auto-detect log format from a sample line.
        
        Args:
            line: A sample log line
            
        Returns:
            'syslog', 'apache', or None if format cannot be determined
        """
        if self.APACHE_PATTERN.match(line):
            return 'apache'
        elif self.SYSLOG_PATTERN.match(line):
            return 'syslog'
        return None
    
    def parse_syslog(self, line: str) -> Optional[Dict]:
        """
        Parse a Syslog format line.
        Supports Ubuntu logs: /var/log/syslog, /var/log/auth.log, /var/log/kern.log
        
        Args:
            line: Log line to parse
            
        Returns:
            Dictionary with parsed fields or None if parsing fails
        """
        # Try kernel log pattern first (special case)
        kernel_match = self.KERNEL_PATTERN.match(line)
        if kernel_match:
            return {
                'format': 'syslog',
                'timestamp': kernel_match.group('timestamp'),
                'hostname': kernel_match.group('hostname'),
                'service': 'kernel',
                'pid': None,
                'kernel_time': kernel_match.group('kern_time'),
                'message': kernel_match.group('message'),
                'raw': line
            }
        
        # Try standard syslog pattern
        match = self.SYSLOG_PATTERN.match(line)
        if match:
            return {
                'format': 'syslog',
                'timestamp': match.group('timestamp'),
                'hostname': match.group('hostname'),
                'service': match.group('service'),
                'pid': match.group('pid'),
                'message': match.group('message'),
                'raw': line
            }
        
        # Fallback: Try to parse lines without service name (less common)
        # Format: timestamp hostname: message
        fallback_pattern = re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>[\w\.-]+):\s+'
            r'(?P<message>.*)'
        )
        fallback_match = fallback_pattern.match(line)
        if fallback_match:
            return {
                'format': 'syslog',
                'timestamp': fallback_match.group('timestamp'),
                'hostname': fallback_match.group('hostname'),
                'service': 'unknown',
                'pid': None,
                'message': fallback_match.group('message'),
                'raw': line
            }
        
        return None
    
    def parse_apache(self, line: str) -> Optional[Dict]:
        """
        Parse an Apache Common Log Format line.
        
        Args:
            line: Log line to parse
            
        Returns:
            Dictionary with parsed fields or None if parsing fails
        """
        match = self.APACHE_PATTERN.match(line)
        if match:
            return {
                'format': 'apache',
                'ip': match.group('ip'),
                'timestamp': match.group('timestamp'),
                'method': match.group('method'),
                'path': match.group('path'),
                'protocol': match.group('protocol'),
                'status': int(match.group('status')),
                'size': match.group('size'),
                'raw': line
            }
        return None
    
    def parse_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single log line based on configured format.
        
        Args:
            line: Log line to parse
            
        Returns:
            Dictionary with parsed fields or None if parsing fails
        """
        line = line.strip()
        if not line:
            return None
        
        # Auto-detect format if needed
        if self.log_format == 'auto':
            detected_format = self.detect_format(line)
            if detected_format == 'syslog':
                return self.parse_syslog(line)
            elif detected_format == 'apache':
                return self.parse_apache(line)
            return None
        elif self.log_format == 'syslog':
            return self.parse_syslog(line)
        elif self.log_format == 'apache':
            return self.parse_apache(line)
        
        return None
    
    def parse_file(self, file_path: str) -> List[Dict]:
        """
        Parse a log file and return list of parsed entries.
        Uses read-only file access for security.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            List of parsed log entries
        """
        self.parsed_logs = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    parsed = self.parse_line(line)
                    if parsed:
                        parsed['line_number'] = line_num
                        self.parsed_logs.append(parsed)
        except FileNotFoundError:
            raise FileNotFoundError(f"Log file not found: {file_path}")
        except PermissionError:
            raise PermissionError(f"Permission denied: Cannot read {file_path}")
        except Exception as e:
            raise Exception(f"Error reading log file: {str(e)}")
        
        return self.parsed_logs
    
    def get_parsed_logs(self) -> List[Dict]:
        """Return the list of parsed logs."""
        return self.parsed_logs

