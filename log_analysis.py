import sys
import csv
from collections import defaultdict, Counter

# Parse the log file and return a list of log entries
def parseLogFile(file_path):
    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
        return logs
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        sys.exit(1)

# Count the number of requests per IP address
def countRequests(logs):
    countIp = Counter()
    for log in logs:
        parts = log.split()
        if parts:
            countIp[parts[0]] += 1
    return countIp

# Find the most frequently accessed endpoint
def findMostFrequentEndpoint(logs):
    countEndpoint = Counter()
    for log in logs:
        parts = log.split()
        if len(parts) > 6:
            endpoint = parts[6]
            countEndpoint[endpoint] += 1
    if countEndpoint:
        most_common = countEndpoint.most_common(1)[0]
        return most_common[0], most_common[1]
    return None, 0

# Detect suspicious activity based on failed login attempts (HTTP 401)
def detectSuspiciousActivity(logs, threshold=10):
    failedLoginCount = defaultdict(int)
    for log in logs:
        parts = log.split()
        if len(parts) > 8 and parts[-2] == '401':  # HTTP status code 401 indicates unauthorized
            ip = parts[0]
            failedLoginCount[ip] += 1
    suspicious_ips = {ip: count for ip, count in failedLoginCount.items() if count > threshold}
    return suspicious_ips

# Save the results to a CSV file
def saveResultsToCsv(countIp, most_frequent_endpoint, suspicious_ips):
    with open('log_analysis_results.csv', mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write IP request counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in countIp.most_common():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint"])
        endpoint, count = most_frequent_endpoint
        writer.writerow([endpoint, count])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Display results in the terminal
def displayResults(countIp, most_frequent_endpoint, suspicious_ips):
    print("\nIP Address           Request Count")
    print("-" * 35)
    for ip, count in countIp.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    endpoint, count = most_frequent_endpoint
    print(f"{endpoint} (Accessed {count} times)")

    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        print("-" * 35)
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("\nNo suspicious activity detected.")

def main():
    log_file_path = r"C:\Users\DELL USER\Documents\sumit\VRV Security\Sample.log"  # Update the path if necessary
    logs = parseLogFile(log_file_path)

    # Task 1: Count requests per IP address
    countIp = countRequests(logs)

    # Task 2: Identify the most frequently accessed endpoint
    most_frequent_endpoint = findMostFrequentEndpoint(logs)

    # Task 3: Detect suspicious activity
    suspicious_ips = detectSuspiciousActivity(logs)

    # Display results in terminal
    displayResults(countIp, most_frequent_endpoint, suspicious_ips)

    # Save results to CSV
    saveResultsToCsv(countIp, most_frequent_endpoint, suspicious_ips)
    print("\nResults have been saved to log_analysis_results.csv")

if __name__ == "__main__":
    main()
