Certainly! Here's a README.md file for the script:

```markdown
# Port Scanner using Nmap

This Python script performs network scanning using the Nmap tool. It allows you to scan a target IP or hostname for open, closed, and filtered ports, retrieve OS details, and perform service version detection. The script provides flexibility in specifying target ports, supports parallel scanning for multiple ports, and includes features for stealthy and efficient scanning.

## Features

- Scan a target IP or hostname for open, closed, and filtered ports.
- Retrieve OS details for the target system (if available).
- Perform service version detection to identify running services.
- Save scan results to a "scan_results" folder.
- Supports parallel scanning for multiple ports.
- Stealthy scanning to avoid detection by intrusion detection systems (IDS) and firewalls.
- Traceroute option to discover the route packets take to reach the target.
- User-friendly command-line interface.

## Usage

1. Ensure you have Python 3.x installed on your system.

2. Install the required Python library `python-nmap` by running:

   ```bash
   pip install python-nmap
   ```

3. Clone this repository or download the `port_scanner.py` script.

4. Make the script executable (optional but recommended):

   ```bash
   chmod +x port_scanner.py
   ```

5. Run the script with the following command:

   ```bash
   ./port_scanner.py <TARGET> [-p PORT] [-t]
   ```

   - `<TARGET>`: The IP address or hostname of the target system.
   - `-p PORT` (optional): Specify the port(s) to scan (comma-separated, e.g., `-p 80,443`). If not provided, it scans all ports from 1 to 65535 by default.
   - `-t` (optional): Perform traceroute to discover the route to the target.

6. View the scan results in the "scan_results" folder. Each scan result is saved as a separate text file.

## Examples

- Scan a specific target for all open, closed, and filtered ports:

  ```bash
  ./port_scanner.py 192.168.1.1
  ```

- Scan a specific target for a single port (e.g., port 80):

  ```bash
  ./port_scanner.py 192.168.1.1 -p 80
  ```

- Scan a specific target for multiple ports (e.g., ports 80 and 443):

  ```bash
  ./port_scanner.py 192.168.1.1 -p 80,443
  ```

- Perform a traceroute while scanning a target:

  ```bash
  ./port_scanner.py 192.168.1.1 -t
  ```

## Disclaimer

Please use this script responsibly and legally. Ensure you have proper authorization to scan any network or system. Unauthorized scanning can be illegal and unethical. The author and OpenAI are not responsible for any misuse of this tool.

## License

This script is released under the [MIT License](LICENSE).
```

You can include this README.md file in your project repository to provide usage instructions and information about the script.
