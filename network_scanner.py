import subprocess
import os
import ipaddress
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from jinja2 import Environment, FileSystemLoader

# Function to check if a host is reachable
def is_host_reachable(ip):
    try:
        output = subprocess.check_output(["ping", "-c", "1", ip])
        return True
    except subprocess.CalledProcessError:
        return False

# Function to check if the input is a valid IP address or CIDR notation
def is_valid_ip(target):
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False

# Function to read the content of a text file
def read_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError:
        return "File not found"
    except Exception as e:
        return str(e)

# Function to run default Nmap script
def run_default_nmap_script(ip):
    nmap_script_args = [
        "-sC",  # Run default NSE scripts
        "--script-args", "safe=1",  # Run only safe NSE scripts
        "-Pn",
        "--open",  # Show only open ports,
    ]

    nmap_script_cmd = ["nmap"] + nmap_script_args + [ip]

    try:
        nmap_script_output = subprocess.check_output(nmap_script_cmd, text=True, encoding='utf-8')
        
        output_directory = f"pentest_result/{ip}"
        os.makedirs(output_directory, exist_ok=True)

        output_filename = f"{output_directory}/{ip}_enum.txt"
        with open(output_filename, "w") as output_file:
            output_file.write(nmap_script_output)

        print(f"\033[33mNmap enumeration scripts completed for {ip}. Results saved in {output_filename}\033[0m")
        return output_filename
    except subprocess.CalledProcessError as e:
        print(f"\033[31mNmap enumeration scripts failed for {ip}: {e}\033[0m")
    except Exception as e:
        print(f"\033[31mAn error occurred while running Nmap enumeration scripts on {ip}: {str(e)}\033[0m")
    return None

# Function to run SSL cipher Nmap script
def run_ssl_cipher_nmap_script(ip):
    ssl_cipher_args = [
        "--script", "ssl-enum-ciphers", "-Pn",
    ]

    ssl_cipher_cmd = ["nmap"] + ssl_cipher_args + [ip]
    ssl_cipher_output = subprocess.check_output(ssl_cipher_cmd, text=True, encoding='utf-8')

    output_filename = f"pentest_result/{ip}/{ip}_ssl_cipher_enum.txt"
    with open(output_filename, "w") as output_file:
        output_file.write(ssl_cipher_output)

    print(f"\033[33mSSL cipher enumeration completed for {ip}. Results saved in {output_filename}\033[0m")
    return output_filename

# Function to run Nmap vulnerability scan
def run_nmap_vuln_script(ip):
    vuln_args = [
        "--script", "vuln", "-Pn",
    ]

    vuln_cmd = ["nmap"] + vuln_args + [ip]
    vuln_output = subprocess.check_output(vuln_cmd, text=True, encoding='utf-8')

    output_filename = f"pentest_result/{ip}/{ip}_vuln_scan.txt"
    with open(output_filename, "w") as output_file:
        output_file.write(vuln_output)

    print(f"\033[33mNmap vulnerability scan completed for {ip}. Results saved in {output_filename}\033[0m")
    return output_filename

# Function to run enum4linux
def run_enum4linux(ip):
    try:
        print(f"\nRunning enum4linux on {ip}...")  # Inform the user that enum4linux is being executed
        enum4linux_cmd = ["enum4linux", "-a", ip]
        enum4linux_output = subprocess.check_output(enum4linux_cmd, text=True)

        output_filename = f"pentest_result/{ip}/{ip}_enum4linux.txt"
        with open(output_filename, "w") as output_file:
            output_file.write(enum4linux_output)

        if enum4linux_output.strip():
            print(f"\033[33menum4linux completed for {ip}. Results saved in {output_filename}\033[0m")
        else:
            print(f"\033[33menum4linux completed for {ip}, but no results were found. Results saved in {output_filename}\033[0m")
        return output_filename
    except subprocess.CalledProcessError:
        print(f"\033[31menum4linux failed for {ip}\033[0m")
    except Exception as e:
        print(f"\033[31mAn error occurred while running enum4linux on {ip}: {str(e)}\033[0m")
    return None

# Function to get IP addresses from a file (including CIDR notation)
def get_ip_addresses_from_file(file_path):
    try:
        ip_list = []

        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                if is_valid_ip(line):
                    ip_list.append(line)

        return ip_list
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []
    except Exception as e:
        print(f"Error reading the file: {str(e)}")
        return []

# Function to generate an HTML report
def generate_html_report(up_hosts, down_hosts, nmap_results):
    template_env = Environment(loader=FileSystemLoader('./templates'))
    template = template_env.get_template('report_template.html')
    
    report_data = {
        'up_hosts': {host: 'Up' for host in up_hosts},
        'down_hosts': {host: 'Down' for host in down_hosts},
        'nmap_results': nmap_results,
    }

    # Read and include the content of .txt files in the nmap_results dictionary
    for host, file_paths in nmap_results.items():
        nmap_results[host]['port_scan_content'] = read_file(file_paths['port_scan_output'])
        nmap_results[host]['default_nmap_content'] = read_file(file_paths['default_nmap_output'])
        nmap_results[host]['ssl_cipher_content'] = read_file(file_paths['ssl_cipher_output'])
        nmap_results[host]['vuln_scan_content'] = read_file(file_paths['vuln_scan_output'])
        nmap_results[host]['enum4linux_content'] = read_file(file_paths['enum4linux_output'])

    report_html = template.render(report_data)
    
    with open('pentest_result/report.html', 'w', encoding='utf-8') as html_file:
        html_file.write(report_html)

# Function to run Nmap script
def run_nmap_script(ip):
    nmap_script_args = [
        "-sC",  # Run default NSE scripts
        "--script-args", "safe=1",  # Run only safe NSE scripts
        "-Pn",
        "--open",  # Show only open ports,
    ]

    nmap_script_cmd = ["nmap"] + nmap_script_args + [ip]

    try:
        nmap_script_output = subprocess.check_output(nmap_script_cmd, text=True, encoding='utf-8')
        
        output_directory = f"pentest_result/{ip}"
        os.makedirs(output_directory, exist_ok=True)

        output_filename = f"{output_directory}/{ip}_nmap_script_enum.txt"
        with open(output_filename, "w") as output_file:
            output_file.write(nmap_script_output)

        print(f"\033[33mNmap script enumeration completed for {ip}. Results saved in {output_filename}\033[0m")
        return output_filename
    except subprocess.CalledProcessError as e:
        print(f"\033[31mNmap script enumeration failed for {ip}: {e}\033[0m")
    except Exception as e:
        print(f"\033[31mAn error occurred while running Nmap script enumeration on {ip}: {str(e)}\033[0m")
    return None

# Main function
def main():
    print("\033[96m" + r"""
    
      _   _      _                      _     _____                                 
     | \ | |    | |                    | |   / ____|                                
     |  \| | ___| |___      _____  _ __| | _| (___   ___ __ _ _ __  _ __   ___ _ __ 
     | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /\___ \ / __/ _^| '_ \| '_ \| _^|_  '__|
     | |\  |  __/ |_ \ V  V / (_) | |  |   < ____) | (_| (_| | | | | | | | |  __/ |   
     |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\_____/ \___\__,_|_| |_|_| |_| \___|_|   
    """ + "\033[0m")
    print("\n\033[91mNote: This script was customized by Helmi - © 2023 All rights reserved.\033[0m")
    
    while True:
        print("\nSelect an option:\n")
        print("1. Scan a single IP address")
        print("2. Scan IP address from file\n")
        option = input("Enter your choice (1/2): ")

        if option == "1":
            ip = input("Enter the IP address to scan (e.g., 192.168.1.1): ")
            ip_list = [ip]  # Create a list with a single IP address
            break
        elif option == "2":
            root = Tk()
            root.withdraw()  # Hide the main window
            file_path = askopenfilename(title="Select IP Address File", filetypes=[("Text Files", "*.txt")])

            if file_path:
                ip_list = get_ip_addresses_from_file(file_path)

                if ip_list:
                    break
                else:
                    print("No valid IP addresses found in the selected file.")
            else:
                print("No file selected. Please select a valid IP address file.")
        else:
            print("Invalid option. Please choose either 1 or 2.")
    
    os.makedirs("pentest_result", exist_ok=True)
    
    up_hosts = []
    down_hosts = []
    nmap_results = {}

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
                nmap_output = subprocess.check_output(nmap_cmd, text=True, encoding='utf-8')

                port_scan_output_filename = f"pentest_result/{ip}/{ip}_port_scan.txt"
                os.makedirs(os.path.dirname(port_scan_output_filename), exist_ok=True)

                with open(port_scan_output_filename, "w") as port_scan_output_file:
                    port_scan_output_file.write(nmap_output)

                print("\033[92mStatus : Complete\033[0m")
                print(f"\033[92mLocation saved : {port_scan_output_filename}\033[0m")

                print("\n\033[93mDefault Nmap enumeration:\033[0m")
                run_default_nmap_script(ip)
                print("\033[92mStatus : Complete\033[0m")
                print(f"\033[92mLocation saved : pentest_result/{ip}/{ip}_enum.txt\033[0m")

                print("\n\033[93mSSL cipher enumeration:\033[0m")
                run_ssl_cipher_nmap_script(ip)
                print("\033[92mStatus : Complete\033[0m")
                print(f"\033[92mLocation saved : pentest_result/{ip}/{ip}_ssl_cipher_enum.txt\033[0m")

                print("\n\033[93mNmap vulnerability scan:\033[0m")
                run_nmap_vuln_script(ip)
                print("\033[92mStatus : Complete\033[0m")
                print(f"\033[92mLocation saved : pentest_result/{ip}/{ip}_vuln_scan.txt\033[0m\n")

                # Ask the user if they want to run enum4linux
                enum_choice = input("Do you want to run enum4linux on this host? (yes/no): ").lower()
                if enum_choice == "yes":
                    if ip in up_hosts:
                        run_enum4linux(ip)
                        print("\033[92mStatus : Complete\033[0m")
                        print(f"\033[92mLocation saved : pentest_result/{ip}/{ip}_enum4linux.txt\033[0m\n")
                    else:
                        print(f"\033[31menum4linux failed for {ip}: Host is not up\033[0m")
                else:
                    print("enum4linux skipped.")

                # Capture Nmap results for this host
                nmap_results[ip] = {
                    'port_scan_output': port_scan_output_filename,
                    'default_nmap_output': f"pentest_result/{ip}/{ip}_enum.txt",
                    'ssl_cipher_output': f"pentest_result/{ip}/{ip}_ssl_cipher_enum.txt",
                    'vuln_scan_output': f"pentest_result/{ip}/{ip}_vuln_scan.txt",
                    'enum4linux_output': f"pentest_result/{ip}/{ip}_enum4linux.txt",
                    'nmap_script_output': f"pentest_result/{ip}/{ip}_nmap_script_enum.txt",  # Capture Nmap script results
                }
        else:
            print("Port scanning and enumeration skipped.")
    else:
        print("No hosts are up.")

    # Generate the HTML report
    generate_html_report(up_hosts, down_hosts, nmap_results)

if __name__ == "__main__":
    main()

