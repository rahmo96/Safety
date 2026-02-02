"""
Log Parser Module
Handles parsing of common log formats (Syslog and Apache) using regex.
Supports Ubuntu system logs: /var/log/syslog, /var/log/auth.log, /var/log/kern.log
Supports systemd journal format (ISO 8601 timestamps)
"""

import re
from typing import List, Dict, Optional
from datetime import datetime


class LogParser:
    """Parser for common log formats."""
    
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
    

    SYSTEMD_PATTERN = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+'
        r'(?P<hostname>[\w\.-]+)\s+'
        r'(?P<service>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.*)'
    )
    
    # Apache Common Log Format: IP - - [timestamp] "method path protocol" status size
    APACHE_COMMON_PATTERN = re.compile(
        r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|::1|[\da-fA-F:]+)\s+'
        r'(?P<ident>[\w\-]+|\-)\s+'
        r'(?P<user>[\w\-]+|\-)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>[^\s"]+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+|\-)'
    )
    
    # Apache Combined Log Format: IP - - [timestamp] "method path protocol" status size "referer" "user-agent"
    APACHE_COMBINED_PATTERN = re.compile(
        r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|::1|[\da-fA-F:]+)\s+'
        r'(?P<ident>[\w\-]+|\-)\s+'
        r'(?P<user>[\w\-]+|\-)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>[^\s"]+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+|\-)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
    )
    
    # Backward compatibility - try combined first, then common
    APACHE_PATTERN = APACHE_COMBINED_PATTERN
    
    def __init__(self, log_format: str = 'auto'):
        """
        Initialize the parser.
        
        Args:
            log_format: Format type ('syslog', 'systemd', 'apache', or 'auto' for detection)
        """
        self.log_format = log_format
        self.parsed_logs = []
    
    def detect_format(self, line: str) -> Optional[str]:
        """
        Auto-detect log format from a sample line.
        
        Args:
            line: A sample log line
            
        Returns:
            'syslog', 'systemd', 'apache', or None if format cannot be determined
        """
        if self.APACHE_COMBINED_PATTERN.match(line) or self.APACHE_COMMON_PATTERN.match(line):
            return 'apache'
        elif self.SYSTEMD_PATTERN.match(line):
            return 'systemd'
        elif self.SYSLOG_PATTERN.match(line) or self.KERNEL_PATTERN.match(line):
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
    
    def parse_systemd(self, line: str) -> Optional[Dict]:
        """
        Parse a systemd journal format line (ISO 8601 timestamp).
        Supports modern Ubuntu systems using systemd.
        
        Args:
            line: Log line to parse
            
        Returns:
            Dictionary with parsed fields or None if parsing fails
        """
        match = self.SYSTEMD_PATTERN.match(line)
        if match:
            return {
                'format': 'systemd',
                'timestamp': match.group('timestamp'),
                'hostname': match.group('hostname'),
                'service': match.group('service'),
                'pid': match.group('pid'),
                'message': match.group('message'),
                'raw': line
            }
        return None
    
    def parse_apache(self, line: str) -> Optional[Dict]:
        """
        Parse an Apache log line (Common or Combined Log Format).
        Supports IPv4, IPv6 (including ::1), Referer, and User-Agent fields.
        
        Args:
            line: Log line to parse
            
        Returns:
            Dictionary with parsed fields or None if parsing fails
        """
        # Try Combined Log Format first (has Referer and User-Agent)
        match = self.APACHE_COMBINED_PATTERN.match(line)
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
                'referer': match.group('referer'),
                'user_agent': match.group('user_agent'),
                'raw': line
            }
        
        # Try Common Log Format (no Referer/User-Agent)
        match = self.APACHE_COMMON_PATTERN.match(line)
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
                'referer': None,
                'user_agent': None,
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
            elif detected_format == 'systemd':
                return self.parse_systemd(line)
            elif detected_format == 'apache':
                return self.parse_apache(line)
            return None
        elif self.log_format == 'syslog':
            return self.parse_syslog(line)
        elif self.log_format == 'systemd':
            return self.parse_systemd(line)
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
    
    def stream_log(self, file_path: str, follow_from_end: bool = True):
        """
        Stream log file in real-time (tail -f behavior).
        Generator that yields parsed log entries as they appear.
        
        Args:
            file_path: Path to the log file to monitor
            follow_from_end: If True, start reading from end of file (like tail -f).
                           If False, read from beginning.
        
        Yields:
            Dictionary with parsed log entry fields
            
        Example:
            for log_entry in parser.stream_log('access.log'):
                print(log_entry)
        """
        import time
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Start from end of file if follow_from_end is True
                if follow_from_end:
                    f.seek(0, 2)  # Seek to end of file
                
                line_number = 0
                if not follow_from_end:
                    # Count existing lines if reading from beginning
                    f.seek(0)
                    line_number = sum(1 for _ in f)
                    f.seek(0, 2)  # Go back to end
                
                # Continuous monitoring loop
                while True:
                    line = f.readline()
                    
                    if line:
                        # New line found, parse it
                        line_number += 1
                        parsed = self.parse_line(line)
                        if parsed:
                            parsed['line_number'] = line_number
                            yield parsed
                    else:
                        # No new line, wait a bit before checking again
                        time.sleep(0.1)  # Small delay to avoid CPU spinning
                        
        except FileNotFoundError:
            raise FileNotFoundError(f"Log file not found: {file_path}")
        except PermissionError:
            raise PermissionError(f"Permission denied: Cannot read {file_path}")
        except KeyboardInterrupt:
            # Allow KeyboardInterrupt to propagate for graceful shutdown
            raise
        except Exception as e:
            raise Exception(f"Error streaming log file: {str(e)}")

