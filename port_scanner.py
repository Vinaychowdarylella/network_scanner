import nmap
import sys
import logging
import time
import random

def initiate_stealthy_scan(scanner, target, ports):
    """Perform a more stealthy and distributed Nmap scan."""
    try:
        logging.info("Starting Nmap scan. This may take a while...")
        
        # Randomize port order and slow down the scan
        port_list = ports.split(',')
        random.shuffle(port_list)
        for port in port_list:
            scanner.scan(target, port, arguments='-sS -T2 -sV --version-intensity 0 --osscan-limit')
            time.sleep(random.uniform(5, 15))  # Random sleep between scans of individual ports

        logging.info("Nmap scan completed.")
    except nmap.PortScannerError as e:
        logging.error(f"Nmap scan error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

def print_scan_results(scanner):
    """Prints the results of the Nmap scan."""
    for host in scanner.all_hosts():
        logging.info(f'Analyzing host: {host}')
        print(f'Host : {host} ({scanner[host].hostname()})')
        print(f'State : {scanner[host].state()}')

        os_detail = scanner[host]['osclass'] if 'osclass' in scanner[host] else 'OS details not available'
        print(f'OS Details: {os_detail}')

        for proto in scanner[host].all_protocols():
            print(f'----------\nProtocol : {proto}')

            lport = sorted(scanner[host][proto].keys())
            for port in lport:
                port_info = scanner[host][proto][port]
                service_info = f"{port_info.get('name', 'Unknown')} {port_info.get('product', '')} {port_info.get('version', '')}"
                print(f'Port : {port}\tState : {port_info["state"]}\tService : {service_info}')

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    nm = nmap.PortScanner()

    target = input("Enter the target IP or hostname to scan: ")
    ports = input("Enter port range (e.g., '1-1024'): ")

    logging.info(f"Preparing to scan {target} on ports {ports}.")
    initiate_stealthy_scan(nm, target, ports)
    print_scan_results(nm)

if __name__ == "__main__":
    main()
