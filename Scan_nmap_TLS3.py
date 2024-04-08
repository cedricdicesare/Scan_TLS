import sys
from datetime import datetime

# Importation des dépendances
try:
    import nmap
except ImportError:
    print("Le module nmap est requis mais n'est pas installé. Exécutez 'pip install python-nmap' pour l'installer.")
    sys.exit(1)

try:
    from prettytable import PrettyTable
except ImportError:
    print("Le module prettytable est requis mais n'est pas installé. Exécutez 'pip install prettytable' pour l'installer.")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Le module tqdm est requis mais n'est pas installé. Exécutez 'pip install tqdm' pour l'installer.")
    sys.exit(1)

import csv

def check_compliance(tls_version, cipher_suite, cert_validity):
    if tls_version in ["TLSv1.2", "TLSv1.3"]:
        try:
            cert_expiry_date = datetime.strptime(cert_validity, '%Y-%m-%d')
            if cert_expiry_date < datetime.now():
                return "KO"  # La date de validité du certificat est dépassée
            return "OK"
        except ValueError:
            return "Invalid date format"
    else:
        return "KO"

if len(sys.argv) < 2:
    print("Usage: python script.py <target> [csv filename]")
    sys.exit(1)

target = sys.argv[1]
csv_filename = sys.argv[2] if len(sys.argv) == 3 else None
scanner = nmap.PortScanner()

print("Initializing TLS information scan...")
scanner.scan(hosts=target, arguments='-p 443 --script ssl-cert,ssl-enum-ciphers')

results = []
hosts = list(scanner.all_hosts())
progress = tqdm(total=len(hosts), desc="Scanning hosts")

for host in hosts:
    progress.update(1)
    if 'tcp' in scanner[host] and 443 in scanner[host]['tcp']:
        port_info = scanner[host]['tcp'][443]
        if 'script' in port_info:
            script_output = port_info['script'].get('ssl-cert', '')
            cert_validity = "N/A"
            if "Not valid after:" in script_output:
                start = script_output.find("Not valid after:") + len("Not valid after:")
                end = script_output.find("T", start)
                cert_validity = script_output[start:end].strip()
            tls_version = "N/A"
            cipher_suite = "No TLS data available"
            script_output = port_info['script'].get('ssl-enum-ciphers', '')
            for line in script_output.split('\n'):
                if line.strip().startswith("TLSv"):
                    tls_version = line.strip().split(':')[0]
                elif line.strip().startswith("TLS_"):
                    cipher_suite = line.strip().split(' ')[0]
                    compliance = check_compliance(tls_version, cipher_suite, cert_validity)
                    results.append([host, 443, tls_version, cipher_suite, cert_validity, compliance])
                    break

progress.close()

# Générer et afficher le tableau
table = PrettyTable(['Host', 'Port', 'TLS Version', 'Cipher Suite', 'Certificate Validity', 'Compliance'])
for row in results:
    table.add_row(row)
print("\n" + str(table))

# Sauvegarde des résultats dans le fichier CSV si un nom est fourni
if csv_filename:
    with open(csv_filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Host', 'Port', 'TLS Version', 'Cipher Suite', 'Certificate Validity', 'Compliance'])
        writer.writerows(results)
    print(f"\nResults have been saved to {csv_filename}")

