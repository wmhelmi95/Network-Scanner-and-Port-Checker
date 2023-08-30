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

def is_cidr_range(target):
    try:
        ipaddress.IPv4Network(target)
        return True
    except ValueError:
        return False

def run_default_nmap_script(ip):
    nmap_script_args = [
        "-sC",  # Run default NSE scripts
        "--script-args", "safe=1",  # Run only safe NSE scripts
        "-Pn",
        "--open",  # Show only open ports,
    ]

    nmap_script_cmd = ["nmap"] + nmap_script_args + [ip]
    nmap_script_output = subprocess.check_output(nmap_script_cmd, text=True)

    output_filename = f"nd/{ip}/{ip}_enum.txt"
    with open(output_filename, "w") as output_file:
        output_file.write(nmap_script_output)

    #print(f"\033[33mNmap enumeration scripts completed for {ip}. Results saved in {output_filename}\033[0m")

def run_ssl_cipher_nmap_script(ip):
    ssl_cipher_args = [
        "--script", "ssl-enum-ciphers","-Pn",
    ]

    ssl_cipher_cmd = ["nmap"] + ssl_cipher_args + [ip]
    ssl_cipher_output = subprocess.check_output(ssl_cipher_cmd, text=True)

    output_filename = f"nd/{ip}/{ip}_ssl_cipher_enum.txt"
    with open(output_filename, "w") as output_file:
        output_file.write(ssl_cipher_output)

    #print(f"\033[33mSSL cipher enumeration completed for {ip}. Results saved in {output_filename}\033[0m")

def run_nmap_vuln_script(ip):
    vuln_args = [
        "--script", "vuln","-Pn",
    ]

    vuln_cmd = ["nmap"] + vuln_args + [ip]
    vuln_output = subprocess.check_output(vuln_cmd, text=True)

    output_filename = f"nd/{ip}/{ip}_vuln_scan.txt"
    with open(output_filename, "w") as output_file:
        output_file.write(vuln_output)

    #print(f"\033[33mNmap vulnerability scan completed for {ip}. Results saved in {output_filename}\033[0m")

def main():
    print("\033[96m" + r"""
    
	  _   _      _                      _     _____                                 
	 | \ | |    | |                    | |   / ____|                                
	 |  \| | ___| |___      _____  _ __| | _| (___   ___ __ _ _ __  _ __   ___ _ __ 
	 | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
	 | |\  |  __/ |_ \ V  V / (_) | |  |   < ____) | (_| (_| | | | | | | |  __/ |   
	 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\_____/ \___\__,_|_| |_|_| |_|\___|_|   
    """ + "\033[0m")
    print("\n\033[91mNote: This script was customized by Helmi - © 2023 All rights reserved.\033[0m")

    while True:
        print("\nSelect an option:\n")
        print("1. Scan using CIDR range")
        print("2. Scan using IP address file\n")
        option = input("Enter your choice (1/2): ")

        if option == "1":
            cidr_range = input("Enter the CIDR range (e.g., 192.168.1.0/24): ")
            ip_list = [str(ip) for ip in ipaddress.IPv4Network(cidr_range)]
            break
        elif option == "2":
            target = input("Please enter the target (CIDR range or IP address file): ")
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
                print("File not found. Please enter a valid filename.")
                return
            break
        else:
            print("Invalid option. Please choose either 1 or 2.")

    os.makedirs("nd", exist_ok=True)

    up_hosts = []
    down_hosts = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(is_host_reachable, ip): ip for ip in ip_list}

        for future in tqdm(as_completed(future_to_ip), total=len(ip_list), desc="Scanning IPs", ncols=100):
            ip = future_to_ip[future]
            if future.result():
                up_hosts.append(ip)
            else:
                down_hosts.append(ip)

    print("\n" + "=" * 50)
    print("{:^50}".format("SCANNING IP ADDRESSES"))
    print("=" * 50 + "\n")

    for ip in up_hosts:
        print(f"\033[32m{ip} : UP\033[0m")

    for ip in down_hosts:
        print(f"\033[31m{ip} : DOWN\033[0m")

    print("\n")
    if up_hosts:
        choice = input("Do you want to perform port scanning using Nmap? (yes/no): ").lower()
        if choice == "yes":
            print("\n" + "=" * 50)
            print("{:^50}".format("PORT SCANNING"))
            print("=" * 50 + "\n")
            for idx, ip in enumerate(up_hosts, start=1):
                print("\033[96m" + "=" * 50)
                print(f" {idx}. {ip}")
                print("=" * 50 + "\033[0m")

                print("\033[93mScanning Ports:\033[0m")
                nmap_args = [
                    "-T4",
                    "--max-retries", "1",
                    "--max-scan-delay", "20",
                    "-Pn",
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

                print("\n\033[93mDefault Nmap enumeration:\033[0m")
                run_default_nmap_script(ip)
                print("\033[92mStatus : Complete\033[0m")
                print(f"\033[92mLocation saved : nd/{ip}/{ip}_enum.txt\033[0m")

                print("\n\033[93mSSL cipher enumeration:\033[0m")
                run_ssl_cipher_nmap_script(ip)
                print("\033[92mStatus : Complete\033[0m")
                print(f"\033[92mLocation saved : nd/{ip}/{ip}_ssl_cipher_enum.txt\033[0m")

                print("\n\033[93mNmap vulnerability scan:\033[0m")
                run_nmap_vuln_script(ip)
                print("\033[92mStatus : Complete\033[0m")
                print(f"\033[92mLocation saved : nd/{ip}/{ip}_vuln_scan.txt\033[0m")
        else:
            print("Port scanning and enumeration skipped.")
    else:
        print("No hosts are up.")

if __name__ == "__main__":
    main()

