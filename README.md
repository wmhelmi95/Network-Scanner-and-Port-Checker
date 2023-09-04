# Network Scanner and Penetration Testing Tool

This is a Python script for network scanning and penetration testing. It automates the process of scanning IP addresses, checking their reachability, performing port scanning using Nmap, and running various enumeration and vulnerability scanning tasks. It also generates an HTML report summarizing the results.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Features](#features)
- [Usage](#usage)
- [Generating an HTML Report](#generating-an-html-report)
- [Author](#author)
- [License](#license)

## Prerequisites

Before using this tool, make sure you have the following prerequisites installed:

- **Python**: Ensure you have Python 3.6 or higher installed on your system.

- **Nmap**: This tool relies on Nmap for port scanning and vulnerability scanning. You can download and install Nmap from the official website: [https://nmap.org/download.html](https://nmap.org/download.html)

- **Clone the Repository**: Clone this repository to your local machine:

   ```sh
   git clone https://github.com/wmhelmi95/network-scanner.git
   ```

- **Install Dependencies**: Navigate to the project directory and install the required Python packages:

   ```sh
   cd network-scanner
   pip install -r requirements.txt
   ```

## Getting Started

1. **Install Prerequisites**: Ensure you have Python and Nmap installed as mentioned in the prerequisites section.

2. **Clone the Repository**: Clone this repository to your local machine:

   ```sh
   git clone https://github.com/wmhelmi95/network-scanner.git
   ```

3. **Install Dependencies**: Navigate to the project directory and install the required Python packages:

   ```sh
   cd network-scanner
   pip install -r requirements.txt
   ```

## Features

- **Flexible Scanning**: Scan one or more IP addresses.
- **Host Reachability**: Check if the provided IP addresses are reachable.
- **Port Scanning**: Perform comprehensive port scanning using Nmap.
- **Nmap Enumeration**: Run Nmap enumeration scripts to gather detailed information about open ports and services.
- **SSL Cipher Enumeration**: Identify SSL ciphers used on target hosts.
- **Vulnerability Scanning**: Perform Nmap vulnerability scanning to uncover potential security issues.
- **SMB/CIFS Enumeration**: Optionally, run enum4linux to gather information about SMB/CIFS services on target hosts.

## Usage

1. **Run the Script**: Execute the script using Python 3:

   ```sh
   python3 network_scanner.py
   ```

2. **Follow the Prompts**: The script will prompt you to select the scanning option and input the target IP addresses.

3. **View Results**: Access the scan results in the `pentest_results` directory.

## Generating an HTML Report

The script automatically generates an HTML report summarizing the scan results. The report is saved as `report.html` in the `pentest_results` directory.

## Author

- GitHub: [https://github.com/wmhelmi95](https://github.com/wmhelmi95)

Feel free to customize this description to accurately represent your project's features and functionality.
