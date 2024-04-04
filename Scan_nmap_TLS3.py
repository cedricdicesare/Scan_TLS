import sys
from datetime import datetime

# Vérifier les installations des dépendances
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
    print("Usage: python script.py <target>")
    sys.exit(1)

target = sys.argv[1]
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
            # Parse le script ssl-cert pour extraire la date de fin de validité
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
table = PrettyTable(['Host', 'Port', 'TLS Version', 'Cipher Suite', 'Certificate Validity', 'Compliance'])
table.align = 'l'
for row in results:
    table.add_row(row)
print("\n" + str(table))

