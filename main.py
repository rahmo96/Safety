"""
Main Entry Point
Command-line interface for the Log Analysis Tool for Security Events.

This module provides the CLI interface for the log analysis tool, orchestrating
the parsing, detection, and reporting pipeline.

Usage:
    python main.py <log_file> [options]

Example:
    python main.py access.log --format apache --output report.json
"""

import argparse
import sys
import os
from parser import LogParser
from detector import SecurityDetector
from reporter import ReportGenerator


def main():
    """Main function to run the log analysis tool."""
    parser = argparse.ArgumentParser(
        description='Log Analysis Tool for Security Events',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py logs/access.log
  python main.py logs/syslog.txt --format syslog --output report.json
  python main.py logs/apache.log --format apache --output report.csv --format csv
  python main.py logs/mixed.log --failed-threshold 10 --traffic-threshold 200
        """
    )
    
    parser.add_argument(
        'log_file',
        type=str,
        help='Path to the log file to analyze'
    )
    
    parser.add_argument(
        '--format',
        type=str,
        choices=['auto', 'syslog', 'systemd', 'apache', 'windows_csv'],
        default='auto',
        help='Log format type (default: auto-detect). Supports syslog, systemd (journal), apache, and windows_csv formats'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        help='Output file path for report (JSON or CSV). If not specified, prints to console'
    )
    
    parser.add_argument(
        '--output-format',
        type=str,
        choices=['json', 'csv', 'text'],
        default='text',
        help='Output format: json, csv, or text (default: text)'
    )
    
    parser.add_argument(
        '--failed-threshold',
        type=int,
        default=5,
        help='Threshold for failed login attempts to trigger alert (default: 5)'
    )
    
    parser.add_argument(
        '--traffic-threshold',
        type=int,
        default=100,
        help='Threshold for unusual traffic volume per IP (default: 100)'
    )
    
    parser.add_argument(
        '--suspicious-paths',
        type=str,
        nargs='+',
        help='Additional suspicious paths to monitor (space-separated)'
    )
    
    args = parser.parse_args()
    
    # Validate log file exists and is readable
    if not os.path.exists(args.log_file):
        print(f"Error: Log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)
    
    if not os.access(args.log_file, os.R_OK):
        print(f"Error: Permission denied: Cannot read {args.log_file}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Step 1: Parse the log file
        print(f"Parsing log file: {args.log_file}")
        log_parser = LogParser(log_format=args.format)
        parsed_logs = log_parser.parse_file(args.log_file)
        print(f"Successfully parsed {len(parsed_logs)} log entries")
        
        if len(parsed_logs) == 0:
            print("Warning: No log entries were parsed. Check log format.", file=sys.stderr)
            sys.exit(1)
        
        # Step 2: Detect security events
        print("Analyzing logs for security events...")
        suspicious_paths = args.suspicious_paths if args.suspicious_paths else None
        detector = SecurityDetector(
            failed_login_threshold=args.failed_threshold,
            traffic_threshold=args.traffic_threshold,
            suspicious_paths=suspicious_paths
        )
        analysis_results = detector.analyze(parsed_logs)
        print(f"Detected {analysis_results['total_events']} security events")
        
        # Step 3: Generate report
        print("Generating report...")
        report_generator = ReportGenerator(analysis_results)
        
        # Determine output format from file extension if not specified
        if args.output:
            output_format = args.output_format
            if output_format == 'text':
                # Infer from extension
                if args.output.endswith('.json'):
                    output_format = 'json'
                elif args.output.endswith('.csv'):
                    output_format = 'csv'
            
            if output_format == 'json':
                report_generator.generate_json(args.output)
                print(f"JSON report saved to: {args.output}")
            elif output_format == 'csv':
                report_generator.generate_csv(args.output)
                print(f"CSV report saved to: {args.output}")
            else:
                # Save text report to file
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report_generator.generate_summary())
                print(f"Text report saved to: {args.output}")
        else:
            # Print to console
            report_generator.print_summary()
        
        # Exit with error code if critical events found
        critical_events = [e for e in analysis_results['events'] if e.get('severity') == 'critical']
        if critical_events:
            print(f"\nWarning: {len(critical_events)} critical security events detected!", file=sys.stderr)
            sys.exit(2)
        elif analysis_results['total_events'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except FileNotFoundError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)




if __name__ == '__main__':
    main()

