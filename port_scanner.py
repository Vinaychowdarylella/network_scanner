import socket
import sys
import socks  # PySocks
from datetime import datetime
import time
import random
import argparse
import logging

def scan_port(ip, port, timeout, proxy_config):
    """Attempt to connect to a specified port on a given IP."""
    try:
        socks.setdefaultproxy(proxy_config['type'], proxy_config['address'], proxy_config['port'])
        with socks.socksocket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except socket.error as e:
        logging.error(f"Error scanning port {port}: {e}")
        return False

def validate_ip(ip):
    """Validate the IP address format."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def main(start_port, end_port, rate_limit, proxy_config):
    parser = argparse.ArgumentParser(description='Network Port Scanner')
    parser.add_argument('host', help='Host to scan')
    args = parser.parse_args()

    remoteServerIP = socket.gethostbyname(args.host)
    if not validate_ip(remoteServerIP):
        logging.error('Invalid IP address. Exiting')
        sys.exit()

    print("-" * 60)
    print(f"Scanning host {remoteServerIP}, from port {start_port} to {end_port}")
    print("-" * 60)

    t1 = datetime.now()

    try:
        ports = list(range(start_port, end_port + 1))
        random.shuffle(ports)
        for port in ports:
            if scan_port(remoteServerIP, port, 1, proxy_config):
                print(f"Port {port}: Open")
            time.sleep(rate_limit)
    except KeyboardInterrupt:
        logging.info("Scan stopped by user")
        sys.exit()
    except socket.gaierror:
        logging.error('Hostname could not be resolved. Exiting')
        sys.exit()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit()

    t2 = datetime.now()
    print('Scanning Completed in: ', t2 - t1)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    proxy_config = {
        'type': socks.PROXY_TYPE_SOCKS5,
        'address': 'your_proxy_address',
        'port': your_proxy_port
    }
    main(start_port=1, end_port=1024, rate_limit=1.0, proxy_config=proxy_config)  # Rate limit in seconds
