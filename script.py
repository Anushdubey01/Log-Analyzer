import re
import csv
import sys
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from collections import Counter
from dataclasses import dataclass, asdict

@dataclass
class LogEntry:
    """
    Structured data class to represent a parsed log entry.
    Allows for more robust and type-safe log parsing.
    """
    ip_address: str
    method: str
    endpoint: str
    status_code: str
    message: Optional[str] = None

class LogAnalyzer:
    def __init__(
        self,
        log_file_path: Path,
        failed_login_threshold: int = 10,
        log_level: int = logging.INFO
    ):
        """
        Initialize the Log Analyzer with advanced configuration.

        :param log_file_path: Path to the log file
        :param failed_login_threshold: Threshold for suspicious login attempts
        :param log_level: Logging verbosity level
        """
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.StreamHandler(sys.stderr),
                logging.FileHandler('log_analysis.log', mode='w')
            ]
        )
        self.logger = logging.getLogger(__name__)

        # Validate input file
        self.log_file_path = Path(log_file_path)
        if not self.log_file_path.is_file():
            self.logger.error(f"Log file not found: {self.log_file_path}")
            raise FileNotFoundError(f"Log file not found: {self.log_file_path}")

        # Configuration parameters
        self.failed_login_threshold = failed_login_threshold

        # Analysis storage
        self.parsed_entries: List[LogEntry] = []
        self.ip_request_counts: Counter = Counter()
        self.endpoint_access_counts: Counter = Counter()
        self.failed_login_attempts: Counter = Counter()

    def parse_log_file(self) -> None:
        """
        Advanced log file parsing with comprehensive error handling.
        """
        log_pattern = re.compile(
            r'^(\d+\.\d+\.\d+\.\d+).*"(\w+)\s+([^\s]+)\s+[^"]*"\s+(\d+)\s*(.*)$'
        )

        try:
            with open(self.log_file_path, 'r') as log_file:
                for line_num, line in enumerate(log_file, 1):
                    try:
                        match = log_pattern.match(line.strip())
                        if match:
                            groups = match.groups()
                            log_entry = LogEntry(
                                ip_address=groups[0],
                                method=groups[1],
                                endpoint=groups[2],
                                status_code=groups[3],
                                message=groups[4] or None
                            )
                            self._process_log_entry(log_entry)
                        else:
                            self.logger.warning(f"Unparseable log line {line_num}: {line.strip()}")
                    except Exception as entry_error:
                        self.logger.error(f"Error processing line {line_num}: {entry_error}")

        except IOError as file_error:
            self.logger.critical(f"File reading error: {file_error}")
            raise

    def _process_log_entry(self, entry: LogEntry) -> None:
        """
        Process individual log entries and track metrics.

        :param entry: Parsed log entry
        """
        # Track IP requests
        self.ip_request_counts[entry.ip_address] += 1

        # Track endpoint access
        self.endpoint_access_counts[entry.endpoint] += 1

        # Detect suspicious login attempts
        if (entry.status_code == '401' or
            (entry.message and 'Invalid credentials' in entry.message)):
            self.failed_login_attempts[entry.ip_address] += 1

    def get_most_accessed_endpoint(self) -> Tuple[str, int]:
        """
        Find the most frequently accessed endpoint.

        :return: Tuple of (endpoint, access_count)
        """
        return self.endpoint_access_counts.most_common(1)[0] if self.endpoint_access_counts else ("N/A", 0)

    def get_suspicious_activities(self) -> List[Tuple[str, int]]:
        """
        Identify IP addresses with suspicious login activity.

        :return: List of (IP, failed_login_count) tuples exceeding threshold
        """
        return [
            (ip, count)
            for ip, count in self.failed_login_attempts.items()
            if count > self.failed_login_threshold
        ]

    def display_results(self) -> None:
        """
        Display comprehensive analysis results with formatting.
        """
        print("\n" + "=" * 50)
        print("VRV SECURITY - LOG ANALYSIS REPORT")
        print("=" * 50)

        # IP Request Counts
        print("\n--- IP Request Counts ---")
        for ip, count in self.ip_request_counts.most_common():
            print(f"{ip:<20} {count:>5} requests")

        # Most Accessed Endpoint
        endpoint, access_count = self.get_most_accessed_endpoint()
        print(f"\n--- Most Accessed Endpoint ---")
        print(f"{endpoint} (Accessed {access_count} times)")

        # Suspicious Activities
        suspicious_ips = self.get_suspicious_activities()
        print("\n--- Suspicious Activities ---")
        if suspicious_ips:
            for ip, count in suspicious_ips:
                print(f"{ip:<20} {count:>3} failed login attempts")
        else:
            print("No suspicious activities detected.")

    def export_to_csv(
        self,
        output_file: Path = Path('log_analysis_results.csv')
    ) -> None:
        """
        Export analysis results to a structured CSV file.

        :param output_file: Path to the output CSV file
        """
        try:
            with open(output_file, 'w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile)

                # IP Request Counts
                csv_writer.writerow(["IP Request Counts"])
                csv_writer.writerow(["IP Address", "Request Count"])
                for ip, count in self.ip_request_counts.most_common():
                    csv_writer.writerow([ip, count])

                # Most Accessed Endpoint
                csv_writer.writerow([])
                csv_writer.writerow(["Most Accessed Endpoint"])
                csv_writer.writerow(["Endpoint", "Access Count"])
                endpoint, access_count = self.get_most_accessed_endpoint()
                csv_writer.writerow([endpoint, access_count])

                # Suspicious Activities
                csv_writer.writerow([])
                csv_writer.writerow(["Suspicious Activities"])
                csv_writer.writerow(["IP Address", "Failed Login Count"])
                for ip, count in self.get_suspicious_activities():
                    csv_writer.writerow([ip, count])

            self.logger.info(f"Results exported to {output_file}")

        except IOError as e:
            self.logger.error(f"CSV export failed: {e}")
            raise

def main():
    """
    Main execution function with robust error handling.
    """
    try:
        # Configurable parameters
        log_file_path = Path('sample.log')
        failed_login_threshold = 10

        # Initialize and run log analyzer
        analyzer = LogAnalyzer(
            log_file_path,
            failed_login_threshold,
            log_level=logging.INFO
        )

        # Process log file
        analyzer.parse_log_file()

        # Display results
        analyzer.display_results()

        # Export to CSV
        analyzer.export_to_csv()

    except Exception as e:
        logging.critical(f"Unhandled exception: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
