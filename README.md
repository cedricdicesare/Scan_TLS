# TLS Scanner

The `TLS_Scanner` script is a Python-based tool that utilizes Nmap to scan specific hosts or IP address ranges to detect TLS versions and cipher suites in use. It checks the compliance of the cipher suites against current security standards, excluding algorithms considered weak or outdated.

## Features

- Scans port 443 to detect TLS versions and cipher suites.
- Checks compliance with current security standards for encryption and hashing algorithms.
- Displays results in a readable table or exports them to a CSV format.

## Installation

The script requires Python 3 and the installation of some dependencies. Here's how to install:

1. Ensure you have Python 3 installed on your system. You can verify this by running:

```bash
python --version
or

python3 --version
Install the required dependencies, including Nmap and the necessary Python packages:
Installing Nmap: Please follow the instructions on the official Nmap website to download and install Nmap if you haven't already done so.

Installing the required Python packages:

pip install python-nmap
pip install prettytable
pip install tqdm
Usage
To run the script, use the following command:

python scan_nmap_TLS3.py <target> [csv]
<target>: Specify the IP address or the IP address range to scan. For example, 192.168.1.1 or 192.168.1.0/24.
[csv]: Add csv after the target address if you wish to export the results to a CSV file. This parameter is optional.
Example Command
python3 Scan_nmap_TLS3.py 192.168.1.0/24 toto.csv
