"""
Log Parser Module
Handles parsing of common log formats (Syslog and Apache) using regex.
Supports Ubuntu system logs: /var/log/syslog, /var/log/auth.log, /var/log/kern.log
Supports systemd journal format (ISO 8601 timestamps)
Supports Windows Event Viewer CSV exports
"""

import re
import csv
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
        r'(?P<service>[\w\.\-/]+)(?:\[(?P<pid>\d+)\])?:\s+'
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
            log_format: Format type ('syslog', 'systemd', 'apache', 'windows_csv', or 'auto' for detection)
        """
        self.log_format = log_format
        self.parsed_logs = []
        self.windows_csv_headers = None  # Store headers for Windows CSV detection
    
    def detect_format(self, line: str) -> Optional[str]:
        """
        Auto-detect log format from a sample line.
        
        Args:
            line: A sample log line
            
        Returns:
            'syslog', 'systemd', 'apache', 'windows_csv', or None if format cannot be determined
        """
        # Check for Windows CSV format (header row)

        if self.APACHE_COMBINED_PATTERN.match(line) or self.APACHE_COMMON_PATTERN.match(line):
            return 'apache'
        elif self.SYSTEMD_PATTERN.match(line):
            return 'systemd'
        elif self.SYSLOG_PATTERN.match(line) or self.KERNEL_PATTERN.match(line):
            return 'syslog'
        return None
    
        self.parsed_logs = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                csv_reader = csv.DictReader(f)
                for line_num, row in enumerate(csv_reader, 1):
                    parsed_entry = {
                        'format': 'windows_csv',
                        'timestamp': row.get('Date and Time') or row.get('TimeCreated', 'N/A'),
                        'event_id': row.get('Event ID') or row.get('Id', 'N/A'),
                        'message': row.get('Task Category') or row.get('Message', ''),
                        'raw': str(row),
                        'line_number': line_num
                    }
                    self.parsed_logs.append(parsed_entry)
            return self.parsed_logs
        except Exception as e:
            print(f"Error: {e}")
            return []
    
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
    
        """
        Parse Windows Event Viewer CSV export file.
        
        Supports multiple Windows Event Viewer CSV formats:
        - Standard format: TimeCreated, Id, Message
        - Variant format: Date and Time, Event ID, Task Category
        
        Maps Windows Event Viewer fields to standard format using coalesce approach:
        - 'timestamp': 'Date and Time' or 'TimeCreated'
        - 'event_id': 'Event ID' or 'Id'
        - 'message': 'Task Category' or 'Message'
        - Extracts additional fields as available (Level, Keywords, Source, etc.)
        
        Uses coalesce mechanism to avoid KeyError exceptions when one header variant is missing.
        
        Args:
            file_path: Path to the Windows CSV file
            
        Returns:
            List of parsed log entries
        """
        self.parsed_logs = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Read CSV file
                csv_reader = csv.DictReader(f)
                
                # Store headers for reference
                self.windows_csv_headers = csv_reader.fieldnames
                
                for line_num, row in enumerate(csv_reader, 1):
                    # Map Windows Event Viewer fields to standard format
                    # Handle None values from CSV (empty cells)
                    def safe_get(key, default=''):
                        val = row.get(key, default)
                        return val if val is not None else default
                    
                    # Coalesce function: tries multiple keys and returns first non-empty value
                    def coalesce(*keys, default=''):
                        """Try multiple keys and return first non-empty value."""
                        for key in keys:
                            val = row.get(key)
                            if val is not None and str(val).strip():
                                return val
                        return default
                    
                    # Field mapping with fallback mechanism
                    # timestamp: Try "Date and Time" first (variant), then "TimeCreated" (standard)
                    timestamp = coalesce('Date and Time', 'TimeCreated', default='')
                    
                    # event_id: Try "Event ID" first (variant), then "Id" (standard)
                    event_id = coalesce('Event ID', 'Id', default='')
                    
                    # message: Try "Task Category" first (variant), then "Message" (standard)
                    message = coalesce('Task Category', 'Message', default='')
                    
                    parsed_entry = {
                        'format': 'windows_csv',
                        'timestamp': timestamp,
                        'event_id': event_id,
                        'message': message,
                        'level': safe_get('Level'),
                        'task': safe_get('Task'),
                        'opcode': safe_get('Opcode'),
                        'keywords': safe_get('Keywords'),
                        'source': safe_get('Source'),  # Common in variant format
                        'event_record_id': safe_get('EventRecordID'),
                        'provider_name': safe_get('ProviderName'),
                        'provider_guid': safe_get('ProviderGuid'),
                        'log_name': safe_get('LogName'),
                        'process_id': safe_get('ProcessId'),
                        'thread_id': safe_get('ThreadId'),
                        'machine_name': safe_get('MachineName'),
                        'user_id': safe_get('UserId'),
                        'time_created': timestamp,  # Keep original field name too
                        'raw': ','.join([f"{k}={v}" for k, v in row.items() if k is not None]),
                        'line_number': line_num
                    }
                    
                    # Add all other fields from CSV
                    for key, value in row.items():
                        if key and key not in parsed_entry:
                            # Handle None keys and ensure key is a string
                            normalized_key = str(key).lower().replace(' ', '_')
                            parsed_entry[normalized_key] = value
                    
                    self.parsed_logs.append(parsed_entry)
        
        except FileNotFoundError:
            raise FileNotFoundError(f"Log file not found: {file_path}")
        except PermissionError:
            raise PermissionError(f"Permission denied: Cannot read {file_path}")
        except Exception as e:
            raise Exception(f"Error reading Windows CSV file: {str(e)}")
        
        return self.parsed_logs
    
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
        
        Note: Windows CSV format requires parse_windows_csv() method as it's a file-based format.
        
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
            # Windows CSV is file-based, not line-based
            return None
        elif self.log_format == 'syslog':
            return self.parse_syslog(line)
        elif self.log_format == 'systemd':
            return self.parse_systemd(line)
        elif self.log_format == 'apache':
            return self.parse_apache(line)
        # Windows CSV format requires parse_windows_csv() method
        elif self.log_format == 'windows_csv':
            return None  # Not supported for line-by-line parsing
        
        return None
    
    def parse_file(self, file_path: str) -> List[Dict]:
        """
        Parse a log file and return list of parsed entries.
        Uses read-only file access for security.
        Automatically detects Windows CSV format and uses appropriate parser.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            List of parsed log entries
        """
        self.parsed_logs = []
        
        # Check if file is Windows CSV format
        if self.log_format == 'windows_csv' or (self.log_format == 'auto' and self._detect_windows_csv_file(file_path)):
            return self.parse_windows_csv(file_path)
        
        # Standard line-by-line parsing for other formats
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
    
    def _detect_windows_csv_file(self, file_path: str) -> bool:
        """
        Detect if a file is Windows Event Viewer CSV format by reading first line.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file appears to be Windows CSV format
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
                return self._is_windows_csv_header(first_line)
        except Exception:
            return False
    
    def get_parsed_logs(self) -> List[Dict]:
        """Return the list of parsed logs."""
        return self.parsed_logs
    

