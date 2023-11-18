The ports should be entered as a comma-separated list (e.g., 22,80,443).
The script significantly slows down the scanning process to reduce detection likelihood, so be prepared for longer scan durations.
As always, ensure you have explicit permission to scan the target network. Unauthorized scanning can lead to serious legal and ethical consequences. This script is intended for educational purposes and authorized security assessments only.

pip install python-nmap
python3 port_scanner.py [target_host]

