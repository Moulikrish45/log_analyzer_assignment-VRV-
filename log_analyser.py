import re
from collections import defaultdict
import csv
import argparse


def parse_log_file(file_path):
    """
    Parses a log file to extract IP addresses, endpoints, and HTTP status codes.

    Args:
        file_path (str): Path to the log file.

    Returns:
        list: A list of dictionaries with extracted data.
    """
    log_data = []
    """In this Regular expression I have used the following patterns because the log file had a pattern for each line. 
    If a different log file were given for the assignment we can change it according to the log file pattern."""
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\] "(?P<method>GET|POST) (?P<endpoint>/\S*) HTTP/1\.1" (?P<status>\d{3})'
    )

    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = log_pattern.search(line)
                if match:
                    log_data.append({
                        "ip": match.group("ip"),
                        "endpoint": match.group("endpoint"),
                        "status": int(match.group("status"))
                    })
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file '{file_path}' not found.")
    except Exception as e:
        raise Exception(f"An error occurred while parsing the log file: {e}")

    if not log_data:
        raise ValueError("The log file is empty or contains no valid entries.")
    
    return log_data


def count_requests_per_ip(log_data):
    """
    Counts the number of requests made by each IP address.

    Args:
        log_data (list): Parsed log data.

    Returns:
        dict: Dictionary with IP addresses as keys and request counts as values, sorted by count.
    """
    ip_count = defaultdict(int)
    for entry in log_data:
        ip_count[entry["ip"]] += 1

    return dict(sorted(ip_count.items(), key=lambda item: item[1], reverse=True))


def most_frequent_endpoint(log_data):
    """
    Identifies the most frequently accessed endpoint.

    Args:
        log_data (list): Parsed log data.

    Returns:
        tuple: The endpoint and its access count.
    """
    if not log_data:
        return None, 0

    endpoint_count = defaultdict(int)
    for entry in log_data:
        endpoint_count[entry["endpoint"]] += 1

    return max(endpoint_count.items(), key=lambda item: item[1])


def detect_suspicious_activity(log_data, threshold=10):
    """
    Detects IP addresses with failed login attempts exceeding the threshold.

    Args:
        log_data (list): Parsed log data.
        threshold (int): The number of failed attempts to flag an IP address as suspicious.

    Returns:
        dict: Dictionary with suspicious IP addresses and their failed attempt counts.
    """
    failed_attempts = defaultdict(int)
    for entry in log_data:
        if entry["status"] == 401:  # Failed login
            failed_attempts[entry["ip"]] += 1

    return {ip: count for ip, count in failed_attempts.items() if count > threshold}


def save_results_to_nested_csv(ip_request_counts, most_accessed, suspicious_ips, output_file="log_analysis_results.csv"):
    """
    Saves the analysis results to a CSV file with columns for structured sections.

    Args:
        ip_request_counts (dict): IP address request counts.
        most_accessed (tuple): Most accessed endpoint and its count.
        suspicious_ips (dict): Suspicious IP addresses and their failed login counts.
        output_file (str): Name of the output CSV file.
    """
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)

        # Section: Requests per IP
        writer.writerow(["Requests per IP", "", ""])
        writer.writerow(["IP Address", "Request Count", ""])
        for ip, count in ip_request_counts.items():
            writer.writerow([ip, count, ""])
        writer.writerow([])

        # Section: Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint", "", ""])
        writer.writerow(["Endpoint", "Access Count", ""])
        writer.writerow([most_accessed[0], most_accessed[1], ""])
        writer.writerow([])

        # Section: Suspicious Activity
        writer.writerow(["Suspicious Activity", "", ""])
        writer.writerow(["IP Address", "Failed Login Attempts", ""])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count, ""])


def main():
    # Command-line argument parser this is done to make the code more flexible and easier to use(It's just my thought)
    parser = argparse.ArgumentParser(description="Analyze web server log files for activity and suspicious behavior.")
    parser.add_argument("log_file", help="Path to the log file to analyze")
    parser.add_argument("--output", default="log_analysis_results.csv", help="Output CSV file name")
    parser.add_argument("--threshold", type=int, default=10, help="Threshold for suspicious activity detection")
    args = parser.parse_args()

    try:
        parsed_data = parse_log_file(args.log_file)
        ip_request_counts = count_requests_per_ip(parsed_data)
        most_accessed_endpoint_data = most_frequent_endpoint(parsed_data)
        suspicious_ips = detect_suspicious_activity(parsed_data, args.threshold)
        save_results_to_nested_csv(ip_request_counts, most_accessed_endpoint_data, suspicious_ips, args.output)

        # Displaying the results in terminal
        print("\nIP Address           Request Count")
        for ip, count in ip_request_counts.items():
            print(f"{ip:<20} {count}")

        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint_data[0]} (Accessed {most_accessed_endpoint_data[1]} times)")

        print("\nSuspicious Activity Detected:")
        if suspicious_ips:
            print("IP Address           Failed Login Attempts")
            for ip, count in suspicious_ips.items():
                print(f"{ip:<20} {count}")
        else:
            print("No suspicious activity detected.")

        print(f"\nResults saved to '{args.output}'.")

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()