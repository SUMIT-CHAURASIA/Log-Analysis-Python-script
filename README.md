Log Analysis Tool
A Python script for analyzing server log files to extract insights such as IP activity, frequently accessed endpoints, and suspicious behavior. 
The script generates results in the terminal and saves them to a CSV file.

Features
Count Requests Per IP Address
Identify the total number of requests made by each IP address.

Find the Most Frequently Accessed Endpoint
Determine the most accessed endpoint in the server logs.

Detect Suspicious Activity
Detect suspicious IPs based on failed login attempts (HTTP 401 status code) and flag IPs that exceed a configurable threshold.

Save Results
Results are saved to a CSV file for further analysis.

Output
Terminal:

Displays the results:
IP address request counts
Most frequently accessed endpoint
Suspicious activity detection

CSV File:

A file named log_analysis_results.csv is created, containing:
Request counts per IP
The most accessed endpoint
Suspicious activity data

