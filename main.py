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
import time
from datetime import datetime
try:
    import signal
    HAS_SIGNAL = True
except ImportError:
    HAS_SIGNAL = False
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
  python main.py /var/log/auth.log --live --format syslog
  python main.py access.log --follow --from-beginning
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
        choices=['auto', 'syslog', 'systemd', 'apache'],
        default='auto',
        help='Log format type (default: auto-detect). Supports syslog, systemd (journal), and apache formats'
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
    
    parser.add_argument(
        '--live',
        '--follow',
        action='store_true',
        dest='live_mode',
        help='Enable real-time monitoring mode (tail -f behavior). Monitors log file continuously and alerts immediately.'
    )
    
    parser.add_argument(
        '--from-beginning',
        action='store_true',
        help='When using --live, start reading from beginning of file instead of end (default: read from end)'
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
        # Initialize parser and detector
        log_parser = LogParser(log_format=args.format)
        suspicious_paths = args.suspicious_paths if args.suspicious_paths else None
        detector = SecurityDetector(
            failed_login_threshold=args.failed_threshold,
            traffic_threshold=args.traffic_threshold,
            suspicious_paths=suspicious_paths
        )
        
        # Real-time monitoring mode
        if args.live_mode:
            run_live_monitoring(args, log_parser, detector)
        else:
            # Standard batch analysis mode
            run_batch_analysis(args, log_parser, detector)
    
    
    except FileNotFoundError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


def run_batch_analysis(args, log_parser, detector):
    """Run standard batch analysis mode."""
    # Step 1: Parse the log file
    print(f"Parsing log file: {args.log_file}")
    parsed_logs = log_parser.parse_file(args.log_file)
    print(f"Successfully parsed {len(parsed_logs)} log entries")
    
    if len(parsed_logs) == 0:
        print("Warning: No log entries were parsed. Check log format.", file=sys.stderr)
        sys.exit(1)
    
    # Step 2: Detect security events
    print("Analyzing logs for security events...")
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


def run_live_monitoring(args, log_parser, detector):
    """Run real-time monitoring mode (streaming)."""
    print("=" * 70)
    print("REAL-TIME LOG MONITORING MODE")
    print("=" * 70)
    print(f"Monitoring: {args.log_file}")
    print(f"Format: {args.format}")
    print(f"Starting from: {'end' if args.from_beginning == False else 'beginning'}")
    print("Press Ctrl+C to stop and view summary")
    print("=" * 70)
    print()
    
    # Track statistics for final summary
    total_events_detected = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    log_entries_processed = 0  # Counter for aggregation checks
    
    # Flag for graceful shutdown
    shutdown_requested = False
    
    def signal_handler(sig, frame):
        """Handle Ctrl+C gracefully."""
        nonlocal shutdown_requested
        shutdown_requested = True
        print("\n\n" + "=" * 70)
        print("Shutdown requested (Ctrl+C)...")
        print("=" * 70)
    
    # Register signal handler for graceful shutdown (if available)
    if HAS_SIGNAL:
        signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Stream log entries in real-time
        follow_from_end = not args.from_beginning
        for log_entry in log_parser.stream_log(args.log_file, follow_from_end=follow_from_end):
            if shutdown_requested:
                break
            
            log_entries_processed += 1
            
            # Analyze the log entry immediately
            events = detector.analyze_single(log_entry)
            
            # Process and display events immediately
            for event in events:
                total_events_detected += 1
                
                # Update severity counts
                severity = event.get('severity', 'low')
                if severity == 'critical':
                    critical_count += 1
                elif severity == 'high':
                    high_count += 1
                elif severity == 'medium':
                    medium_count += 1
                else:
                    low_count += 1
                
                # Print alert immediately with timestamp
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                severity_symbol = {
                    'critical': '🚨',
                    'high': '⚠️',
                    'medium': '⚡',
                    'low': 'ℹ️'
                }.get(severity, 'ℹ️')
                
                print(f"[{timestamp}] {severity_symbol} [{severity.upper()}] {event.get('type', 'unknown')}")
                print(f"  Description: {event.get('description', 'N/A')}")
                if 'ip' in event:
                    print(f"  IP Address: {event['ip']}")
                if 'path' in event:
                    print(f"  Path: {event['path']}")
                if 'count' in event:
                    print(f"  Count: {event['count']}")
                print()
                
                # Store event for final summary
                detector.detected_events.append(event)
            
            # Periodically check aggregation rules (every 100 log entries processed)
            if log_entries_processed % 100 == 0:
                aggregation_events = detector.finalize_aggregation_rules()
                for event in aggregation_events:
                    # Display aggregation events
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    severity_symbol = {
                        'critical': '🚨',
                        'high': '⚠️',
                        'medium': '⚡',
                        'low': 'ℹ️'
                    }.get(event.get('severity', 'low'), 'ℹ️')
                    
                    print(f"[{timestamp}] {severity_symbol} [{event.get('severity', 'low').upper()}] {event.get('type', 'unknown')}")
                    print(f"  Description: {event.get('description', 'N/A')}")
                    if 'ip' in event:
                        print(f"  IP Address: {event['ip']}")
                    print()
                    
                    detector.detected_events.append(event)
                    total_events_detected += 1
    
    except KeyboardInterrupt:
        # Already handled by signal handler, but catch here too
        pass
    
    # Final summary
    print("\n" + "=" * 70)
    print("MONITORING SESSION SUMMARY")
    print("=" * 70)
    print(f"Total Events Detected: {total_events_detected}")
    print(f"  Critical: {critical_count}")
    print(f"  High: {high_count}")
    print(f"  Medium: {medium_count}")
    print(f"  Low: {low_count}")
    print()
    
    # Finalize any remaining aggregation rules
    final_events = detector.finalize_aggregation_rules()
    if final_events:
        print(f"Final aggregation check found {len(final_events)} additional events")
        for event in final_events:
            detector.detected_events.append(event)
            total_events_detected += 1
    
    # Generate final statistics
    stats = detector.get_session_statistics()
    if stats['top_offending_ips']:
        print("\nTop Offending IPs:")
        for i, ip_info in enumerate(stats['top_offending_ips'][:5], 1):
            print(f"  {i}. {ip_info['ip']}: {ip_info['event_count']} events")
    
    print("=" * 70)
    
    # Exit with appropriate code
    if critical_count > 0:
        sys.exit(2)
    elif total_events_detected > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()

