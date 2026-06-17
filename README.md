# IP Threat Tracker

## Description

IP Threat Tracker is a command-line cybersecurity tool written in Python that helps users investigate an IP address and assess its reputation based on publicly available threat intelligence data.

The program accepts an IP address and a time range as command-line arguments. It first validates the supplied IP address using Python's built-in `ipaddress` module. Once validated, it gathers geolocation and network information using the IP-API service. It then queries AbuseIPDB to determine whether the IP address has been reported for malicious activity and calculates its threat level based on the abuse confidence score.

The tool provides users with important information about an IP address, including its location, Internet Service Provider (ISP), Autonomous System Number (ASN), abuse confidence score, report history, and the date of the most recent abuse report.

This project was developed as the final project for CS50's Introduction to Programming with Python and demonstrates concepts such as command-line arguments, API integration, exception handling, environment variables, JSON processing, and modular program design.

## Features

* Validates IPv4 and IPv6 addresses
* Retrieves geolocation information for an IP address
* Displays ISP and ASN details
* Checks IP reputation using AbuseIPDB
* Classifies IP addresses as Safe, Suspicious, or Malicious
* Displays abuse report statistics
* Handles invalid input and network-related errors
* Protects API credentials using environment variables

## Technologies Used

* Python 3
* Requests
* Python-dotenv
* IP-API
* AbuseIPDB

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd <repository-folder>
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file in the project directory:

```env
my_abuseipdb_key=YOUR_API_KEY_HERE
```

Replace `YOUR_API_KEY_HERE` with your AbuseIPDB API key.

## Usage

Run the program using:

```bash
python ip_tracker.py <IP_ADDRESS> <MAX_AGE_IN_DAYS>
```

Example:

```bash
python ip_tracker.py 8.8.8.8 30
```

### Arguments

| Argument        | Description                                            |
| --------------- | ------------------------------------------------------ |
| IP_ADDRESS      | The IP address to investigate                          |
| MAX_AGE_IN_DAYS | Number of days of AbuseIPDB reports to analyze (1–365) |

## Example Output

```text
IP: 8.8.8.8
Location: Mountain View, California, United States
Internet Service Provider: Google LLC
Autonomous System Number: AS15169

Abuse Score = 0/100 (Safe)
```

If an IP address has previously been reported:

```text
Abuse Score = 82/100 (Malicious)

Total number of reports = 145
Last reported date = 2026-05-12
```

## Project Structure

```text
.
├── ip_tracker.py
├── README.md
├── requirements.txt
├── .env
└── test_project.py
```

**Note:** The `.env` file is intentionally excluded from the repository because it contains private API credentials.

## Design Choices

One of the key design decisions was using Python's `ipaddress` module instead of regular expressions for IP validation. This approach is more reliable and supports both IPv4 and IPv6 addresses.

The project uses environment variables through the `python-dotenv` package to securely store API credentials. This prevents sensitive information from being hardcoded into the source code or uploaded to GitHub.

Two separate APIs were chosen to provide complementary information. IP-API supplies geolocation and network details, while AbuseIPDB provides threat intelligence and abuse-reporting data. Combining these sources allows the user to obtain both technical and security-related information about an IP address in a single command.

## Future Improvements

The current version of IP Threat Tracker focuses on gathering threat intelligence and reputation information about IP addresses. Future versions may include additional functionality such as:

* Export scan results to JSON or CSV files
* Support scanning multiple IP addresses at once
* Add color-coded terminal output
* Integrate additional threat intelligence feeds
* Build a graphical user interface (GUI)
* Generate automated threat reports
* Add the ability to report malicious IP addresses directly to AbuseIPDB from within the application
* Add reputation history tracking for previously scanned IP addresses

## Author

**Yash Kumar Kriplani**

IP Threat Tracker is my first independently developed cybersecurity project. The goal of this project is to combine IP intelligence gathering and threat reputation analysis into a simple command-line tool that can help users quickly investigate potentially suspicious IP addresses.
