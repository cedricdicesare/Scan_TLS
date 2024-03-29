import csv
import sys

# Vérifier les installations des dépendances
dependencies = {
    'nmap': 'python-nmap',
    'prettytable': 'prettytable',
    'tqdm': 'tqdm'
}

missing_dependencies = []

for lib, package in dependencies.items():
    try:
        __import__(lib)
    except ImportError:
        missing_dependencies.append(package)

if missing_dependencies:
    print("Le script nécessite des bibliothèques qui ne sont pas installées.")
    print("Exécutez les commandes suivantes pour installer les dépendances manquantes :\n")
    for dep in missing_dependencies:
        print(f"pip install {dep}")
    sys.exit(1)

# Si toutes les dépendances sont satisfaites, continuer avec le script
import nmap
from prettytable import PrettyTable
from tqdm import tqdm

def check_compliance(tls_version, cipher_suite):
    if tls_version in ["TLSv1.2", "TLSv1.3"]:
        return "OK"
    else:
        return "KO"

if len(sys.argv) < 2:
    print("Usage: python script.py <target> [csv filename]")
    sys.exit(1)

target = sys.argv[1]
csv_filename = sys.argv[2] if len(sys.argv) > 2 else None
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
        if 'script' in port_info and 'ssl-enum-ciphers' in port_info['script']:
            script_output = port_info['script']['ssl-enum-ciphers']
            tls_version = "N/A"
            cipher_suite = "No TLS data available"
            for line in script_output.split('\n'):
                if line.strip().startswith("TLSv"):
                    tls_version = line.strip().split(':')[0]
                elif line.strip().startswith("TLS_"):
                    cipher_suite = line.strip().split(' ')[0]
                    compliance = check_compliance(tls_version, cipher_suite)
                    results.append([host, 443, tls_version, cipher_suite, compliance])
                    break

progress.close()
table = PrettyTable(['Host', 'Port', 'TLS Version', 'Cipher Suite', 'Compliance'])
table.align = 'l'
for row in results:
    table.add_row(row)
print("\n" + str(table))

if csv_filename:
    with open(csv_filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Host', 'Port', 'TLS Version', 'Cipher Suite', 'Compliance'])
        writer.writerows(results)
    print(f"\nResults have been saved to {csv_filename}")

