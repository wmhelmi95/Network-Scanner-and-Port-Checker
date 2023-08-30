import subprocess
import os
import ipaddress
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# Function to check if a host is reachable
def is_host_reachable(ip):
    try:
        output = subprocess.check_output(["ping", "-c", "1", ip])
        return True
    except subprocess.CalledProcessError:
        return False

# Function to check if a target is a valid CIDR range
def is_cidr_range(target):
    try:
        ipaddress.IPv4Network(target)
        return True
    except ValueError:
        return False

# Function to run default Nmap enumeration script
def run_default_nmap_script(ip):
    nmap_script_args = [
        "-sC",  # Run default NSE scripts
        "-Pn", # Assumes hosts are up
        "--script-args", "safe=1",  # Run only safe NSE scripts
        "--open",  # Show only open ports
    ]

    nmap_script_cmd = ["nmap"] + nmap_script_args + [ip]
    nmap_script_output = subprocess.check_output(nmap_script_cmd, text=True)

    output_filename = f"nd/{ip}/{ip}_enum.txt"
    with open(output_filename, "w") as output_file:
        output_file.write(nmap_script_output)

    #print(f"\033[33mDefault Nmap enumeration completed for {ip}. Results saved in {output_filename}\033[0m")

# Function to run Nmap SSL cipher enumeration script
def run_ssl_cipher_nmap_script(ip):
    nmap_script_args = [
        "--script", "ssl-enum-ciphers",
        "-Pn",
        "--open",
    ]

    nmap_script_cmd = ["nmap"] + nmap_script_args + [ip]
    nmap_script_output = subprocess.check_output(nmap_script_cmd, text=True)

    output_filename = f"nd/{ip}/{ip}_ssl_cipher_enum.txt"
    with open(output_filename, "w") as output_file:
        output_file.write(nmap_script_output)

    #print(f"\033[33mSSL cipher enumeration completed for {ip}. Results saved in {output_filename}\033[0m")

# Function to run Nmap vulnerability scan script
def run_nmap_vuln_script(ip):
    nmap_script_args = [
        "--script", "vuln",
        "-Pn",
        "--open",
    ]

    nmap_script_cmd = ["nmap"] + nmap_script_args + [ip]
    nmap_script_output = subprocess.check_output(nmap_script_cmd, text=True)

    output_filename = f"nd/{ip}/{ip}_vuln_scan.txt"
    with open(output_filename, "w") as output_file:
        output_file.write(nmap_script_output)

    #print(f"\033[33mNmap vulnerability scan completed for {ip}. Results saved in {output_filename}\033[0m")

def main():
    print("\033[96m==================================================")
    print("           PING SWEEP AND PORT SCANNER           ")
    print("==================================================\033[0m")

    # Add your trademark or note here
    print("\033[91mNote: This script was customized by Helmi - © 2023 All rights reserved.\033[0m")

    while True:
        print("\n\033[93mSelect an option:")
        print("1. Scan using CIDR range")
        print("2. Scan using IP address file\033[0m")
        option = input("\033[92mEnter your choice (1/2): \033[0m")

        if option == "1":
            cidr_range = input("\033[92mEnter the CIDR range (e.g., 192.168.1.0/24): \033[0m")
            ip_list = [str(ip) for ip in ipaddress.IPv4Network(cidr_range)]
            break
        elif option == "2":
            target = input("\033[92mPlease enter the target (CIDR range or IP address file): \033[0m")
            try:
                ip_list = []

                if is_cidr_range(target):
                    ip_list.extend(str(ip) for ip in ipaddress.IPv4Network(target))
                else:
                    with open(target, "r") as file:
                        for line in file:
                            line = line.strip()
                            if is_cidr_range(line):
                                ip_list.extend(str(ip) for ip in ipaddress.IPv4Network(line))
                            else:
                                ip_list.append(line)
            except FileNotFoundError:
                print("\033[91mFile not found. Please enter a valid filename.\033[0m")
                return
            break
        else:
            print("\033[91mInvalid option. Please choose either 1 or 2.\033[0m")

    os.makedirs("nd", exist_ok=True)

    up_hosts = []
    down_hosts = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(is_host_reachable, ip): ip for ip in ip_list}

        for future in tqdm(as_completed(future_to_ip), total=len(ip_list), desc="\033[95mScanning IPs\033[0m", ncols=100):
            ip = future_to_ip[future]
            if future.result():
                up_hosts.append(ip)
            else:
                down_hosts.append(ip)

    print("\n" + "=" * 50)
    print("{:^50}".format("\033[93mSCANNING IP ADDRESSES\033[0m"))
    print("=" * 50 + "\n")

    for ip in up_hosts:
        print(f"\033[92m{ip} : UP\033[0m")

    for ip in down_hosts:
        print(f"\033[91m{ip} : DOWN\033[0m")

    print("\n")
    if up_hosts:
        choice = input("\033[93mDo you want to perform port scanning and enumeration using Nmap? (yes/no): \033[0m").lower()
        if choice == "yes":
            print("\n" + "=" * 50)
            print("{:^50}".format("\033[95mPORT SCANNING & ENUMERATION\033[0m"))
            print("=" * 50 + "\n")
            
            for idx, ip in enumerate(up_hosts, start=1):
                print(f"\n{'=' * 50}\n\033[96m{ip}\033[0m\n{'=' * 50}")
                
                # Port Scanning
                print("\033[93mScanning Ports:\033[0m")
                nmap_args = [
                    "-Pn",
                    "-T4",
                    "--max-retries", "1",
                    "--max-scan-delay", "20",
                    "-n",
                    "--top-ports", "1000",
                ]
                
                nmap_cmd = ["nmap"] + nmap_args + [ip]
                nmap_output = subprocess.check_output(nmap_cmd, text=True)
                
                port_scan_output_filename = f"nd/{ip}/{ip}_port_scan.txt"
                os.makedirs(os.path.dirname(port_scan_output_filename), exist_ok=True)
                
                with open(port_scan_output_filename, "w") as port_scan_output_file:
                    port_scan_output_file.write(nmap_output)
                    
                print("\033[92mStatus : Complete\033[0m")
                print(f"\033[92mLocation saved : {port_scan_output_filename}\033[0m")
                
                # Default Nmap Enumeration
                print("\n\033[93mDefault Nmap enumeration:\033[0m")
                run_default_nmap_script(ip)
                print("\033[92mStatus : Complete\033[0m")
                print(f"\033[92mLocation saved : nd/{ip}/{ip}_enum.txt\033[0m")

                # SSL Cipher Enumeration
                print("\n\033[93mSSL cipher enumeration:\033[0m")
                run_ssl_cipher_nmap_script(ip)
                print("\033[92mStatus : Complete\033[0m")
                print(f"\033[92mLocation saved : nd/{ip}/{ip}_ssl_cipher_enum.txt\033[0m")

                # Nmap Vulnerability Scan
                print("\n\033[93mNmap vulnerability scan:\033[0m")
                run_nmap_vuln_script(ip)
                print("\033[92mStatus : Complete\033[0m")
                print(f"\033[92mLocation saved : nd/{ip}/{ip}_vuln_scan.txt\033[0m")
                
        else:
            print("\033[91mPort scanning and enumeration skipped.\033[0m")
    else:
        print("\033[91mNo hosts are up.\033[0m")

if __name__ == "__main__":
    main()

