# Network Scanner and Penetration Testing Tool

This is a personal project developed to simplify network scanning, port checking, and penetration testing tasks. It's designed to automate the process of scanning IP addresses, identifying open ports, performing Nmap-based enumeration to uncover potential vulnerabilities, and even running `enum4linux` to gather information about SMB/CIFS services.

## Key Features

- **Flexible Scanning**: Scan IP addresses using either a CIDR range or an IP address file.
- **Host Reachability**: Quickly check the reachability status of hosts and display their current status.
- **Port Scanning**: Perform comprehensive port scanning and save the results for further analysis.
- **Nmap Enumeration**: Run Nmap enumeration scripts to gather in-depth information about open ports and services.
- **SSL Cipher Enumeration**: Identify SSL ciphers used on target hosts.
- **Vulnerability Scanning**: Perform Nmap vulnerability scanning to uncover potential security issues.
- **SMB/CIFS Enumeration**: Execute `enum4linux` to gather information about SMB/CIFS services on target hosts.

## Usage

1. Ensure you have Python 3.6 or higher installed on your system.
2. Clone this repository to your local machine.
3. Install the required dependencies by running `pip install -r requirements.txt`.
4. Execute the script with `python3 network_scanner.py`.
5. Follow the on-screen prompts to select the scanning option and input the target(s).
6. Access the scan results in the `pentest_results` directory, including the output from `enum4linux`.

## Author

- GitHub: [https://github.com/wmhelmi95](https://github.com/wmhelmi95)

Feel free to further customize this description to accurately represent your project's features and functionality.
