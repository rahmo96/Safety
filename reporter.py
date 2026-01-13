"""
Report Generator Module
Creates structured reports of detected security events.
"""

import json
import csv
from typing import Dict, List
from datetime import datetime


class ReportGenerator:
    """Generates security analysis reports in various formats."""
    
    def __init__(self, analysis_results: Dict):
        """
        Initialize the report generator.
        
        Args:
            analysis_results: Dictionary containing analysis results from SecurityDetector
        """
        self.results = analysis_results
        self.events = analysis_results.get('events', [])
        self.statistics = analysis_results.get('statistics', {})
    
    def generate_summary(self) -> str:
        """
        Generate a text summary of the analysis.
        
        Returns:
            Formatted summary string
        """
        summary = []
        summary.append("=" * 70)
        summary.append("SECURITY LOG ANALYSIS REPORT")
        summary.append("=" * 70)
        summary.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append("")
        
        # Overall statistics
        summary.append("OVERALL STATISTICS")
        summary.append("-" * 70)
        summary.append(f"Total Security Events Detected: {self.results.get('total_events', 0)}")
        summary.append("")
        
        # Severity distribution
        severity_dist = self.statistics.get('severity_distribution', {})
        if severity_dist:
            summary.append("Severity Distribution:")
            for severity, count in sorted(severity_dist.items(), key=lambda x: x[1], reverse=True):
                summary.append(f"  {severity.upper()}: {count}")
            summary.append("")
        
        # Event type distribution
        event_types = self.statistics.get('event_type_distribution', {})
        if event_types:
            summary.append("Event Type Distribution:")
            for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
                summary.append(f"  {event_type}: {count}")
            summary.append("")
        
        # Top offending IPs
        top_ips = self.statistics.get('top_offending_ips', [])
        if top_ips:
            summary.append("Top Offending IP Addresses:")
            summary.append("-" * 70)
            for i, ip_info in enumerate(top_ips[:10], 1):
                summary.append(f"  {i}. {ip_info['ip']}: {ip_info['event_count']} events")
            summary.append("")
        
        # Detailed events by severity
        summary.append("DETAILED EVENTS BY SEVERITY")
        summary.append("=" * 70)
        
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_events = [e for e in self.events if e.get('severity') == severity]
            if severity_events:
                summary.append(f"\n{severity.upper()} SEVERITY EVENTS ({len(severity_events)}):")
                summary.append("-" * 70)
                for i, event in enumerate(severity_events[:20], 1):  # Limit to top 20 per severity
                    summary.append(f"\n{i}. {event.get('type', 'unknown').upper()}")
                    summary.append(f"   Description: {event.get('description', 'N/A')}")
                    if 'ip' in event:
                        summary.append(f"   IP Address: {event['ip']}")
                    if 'count' in event:
                        summary.append(f"   Count: {event['count']}")
                    if 'path' in event:
                        summary.append(f"   Path: {event['path']}")
                    if 'timestamp' in event:
                        summary.append(f"   Timestamp: {event['timestamp']}")
        
        summary.append("")
        summary.append("=" * 70)
        summary.append("END OF REPORT")
        summary.append("=" * 70)
        
        return "\n".join(summary)
    
    def generate_json(self, output_path: str) -> None:
        """
        Generate a JSON report file.
        
        Args:
            output_path: Path to save the JSON report
        """
        report_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_events': self.results.get('total_events', 0)
            },
            'statistics': self.statistics,
            'events': self.events
        }
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            raise Exception(f"Error writing JSON report: {str(e)}")
    
    def generate_csv(self, output_path: str) -> None:
        """
        Generate a CSV report file.
        
        Args:
            output_path: Path to save the CSV report
        """
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                if not self.events:
                    # Write header even if no events
                    writer = csv.writer(f)
                    writer.writerow(['Type', 'Severity', 'IP', 'Description', 'Count', 'Path', 'Timestamp'])
                    return
                
                # Get all unique field names
                fieldnames = set()
                for event in self.events:
                    fieldnames.update(event.keys())
                
                # Standardize field order
                fieldnames = ['type', 'severity', 'ip', 'description', 'count', 'path', 
                            'timestamp', 'line_number', 'status', 'request_count']
                fieldnames = [f for f in fieldnames if f in fieldnames]
                
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                
                for event in self.events:
                    # Flatten nested structures
                    row = {}
                    for key, value in event.items():
                        if isinstance(value, (dict, list)):
                            row[key] = json.dumps(value)
                        else:
                            row[key] = value
                    writer.writerow(row)
        except Exception as e:
            raise Exception(f"Error writing CSV report: {str(e)}")
    
    def print_summary(self) -> None:
        """Print the summary report to console."""
        print(self.generate_summary())

