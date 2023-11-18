import nmap
import sys
import logging
import os
import argparse
import threading
import random
import time

# Predefined Nmap script arguments for enhanced scanning
SCRIPT_ARGS = "default,vuln"

# Settings for stealthier and parallel scanning
MAX_THREADS = 5
SCAN_DELAY = 2  # Delay in seconds between individual port scans

def get_next_filename(prefix="scan", suffix=".txt", directory="scan_results"):
    """Generates the next available filename for saving scan results."""
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    counter = 0
    while True:
        filename = os.path.join(directory, f"{prefix}{counter}{suffix}")
        if not os.path.exists(filename):
            return filename
        counter += 1

def write_scan_results_to_file(scanner, filename, is_single_port):
    """Writes the results of the Nmap scan to a file."""
    with open(filename, "w") as file:
        for host in scanner.all_hosts():
            file.write(f'Host : {host} ({scanner[host].hostname()})\n')
            file.write(f'State : {scanner[host].state()}\n')

            if 'osclass' in scanner[host]:
                os_detail = f"{scanner[host]['osclass'][0]['osfamily']} {scanner[host]['osclass'][0]['osgen']} {scanner[host]['osclass'][0]['accuracy']}%"
            else:
                os_detail = 'OS details not available'
            file.write(f'OS Details: {os_detail}\n')

            for proto in scanner[host].all_protocols():
                file.write(f'----------\nProtocol : {proto}\n')
                lport = sorted(scanner[host][proto].keys())
                for port in lport:
                    port_info = scanner[host][proto][port]
                    state = port_info['state']
                    if state in ['open', 'filtered'] or (state == 'closed' and is_single_port):
                        service_info = f"{port_info.get('name', 'Unknown')} {port_info.get('product', '')} {port_info.get('version', '')}"
                        port_data = f'Port : {port}\tState : {state}\tService : {service_info}\n'
                        file.write(port_data)

def initiate_scan(scanner, target, port, traceroute=False):
    try:
        scan_arguments = '-sS -T2 -O -sV --osscan-guess --max-os-tries 1 --script=' + SCRIPT_ARGS
        if traceroute:
            scan_arguments += ' --traceroute'

        scanner.scan(target, port, arguments=scan_arguments)
        time.sleep(SCAN_DELAY)  # Adding delay between scans
    except nmap.PortScannerError as e:
        logging.error(f"Nmap scan error: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Perform an Nmap scan on a specified target.')
    parser.add_argument('target', help='IP or hostname to scan')
    parser.add_argument('-p', '--port', help='Specific port(s) to scan (comma-separated, no spaces)', default="1-65535")
    parser.add_argument('-t', '--traceroute', action='store_true', help='Perform traceroute')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    nm = nmap.PortScanner()
    target = args.target
    ports = [p.strip() for p in args.port.split(',')]  # Split the ports by comma and strip spaces
    is_single_port = len(ports) == 1 and '-' not in ports[0]
    traceroute = args.traceroute
    filename = get_next_filename()

    logging.info(f"Preparing to scan {target}. Results will be saved in {filename}.")

    random.shuffle(ports)  # Randomize the port order

    threads = []
    for port in ports:
        while threading.active_count() > MAX_THREADS:
            time.sleep(1)  # Wait if the maximum number of threads is reached
        thread = threading.Thread(target=initiate_scan, args=(nm, target, port, traceroute))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    write_scan_results_to_file(nm, filename, is_single_port)

if __name__ == "__main__":
    main()
