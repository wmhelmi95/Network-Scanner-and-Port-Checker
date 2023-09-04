# Network Scanner and Penetration Testing Tool

This is a personal project developed to simplify network scanning, port checking, and penetration testing tasks. It's designed to automate the process of scanning IP addresses, identifying open ports, performing Nmap-based enumeration to uncover potential vulnerabilities, and even running `enum4linux` to gather information about SMB/CIFS services.

## Table of Contents

- [Installation](#installation)
- [Key Features](#key-features)
- [Usage](#usage)
- [License](#license)
- [Contributing](#contributing)
- [Author](#author)

## Installation

1. Ensure you have Python 3.6 or higher installed on your system.

2. Clone this repository to your local machine using Git:

   ```sh
   git clone https://github.com/wmhelmi95/network-scanner.git
   ```

3. Change to the project directory:

   ```sh
   cd network-scanner
   ```

4. Install the required Python packages:

   ```sh
   pip install -r requirements.txt
   ```

## Key Features

- **Flexible Scanning**: Scan IP addresses using either a CIDR range or an IP address file.
- **Host Reachability**: Quickly check the reachability status of hosts and display their current status.
- **Port Scanning**: Perform comprehensive port scanning and save the results for further analysis.
- **Nmap Enumeration**: Run Nmap enumeration scripts to gather in-depth information about open ports and services.
- **SSL Cipher Enumeration**: Identify SSL ciphers used on target hosts.
- **Vulnerability Scanning**: Perform Nmap vulnerability scanning to uncover potential security issues.
- **SMB/CIFS Enumeration**: Execute `enum4linux` to gather information about SMB/CIFS services on target hosts.

## Usage

- Scan a single IP address:

  ```sh
  python3 network_scanner.py
  ```

- Scan IP addresses from a file:

  ```sh
  python3 network_scanner.py -f path/to/ip_addresses.txt
  ```

- Perform a Nmap vulnerability scan:

  ```sh
  python3 network_scanner.py -v
  ```

- Generate an HTML report:

  ```sh
  python3 network_scanner.py -r
  ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! If you'd like to contribute to this project, please follow these guidelines and steps:

1. Fork the project on GitHub.
2. Create a new branch for your feature or bug fix.
3. Make your changes and submit a pull request.
4. Your pull request will be reviewed, and once approved, it will be merged into the main branch.

For more details, please refer to our [Contributing Guidelines](CONTRIBUTING.md).

## Author

- GitHub: [https://github.com/wmhelmi95](https://github.com/wmhelmi95)

Feel free to further customize this description to accurately represent your project's features and functionality.
```

This Markdown document combines all the sections you requested into a single README.md file, making it easy for users to access installation instructions, usage examples, licensing information, and contributing guidelines in one place.
