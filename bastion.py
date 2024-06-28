import os
import smtplib
import requests
from scapy.all import *
import subprocess
import socket
from collections import defaultdict
import netifaces
import hashlib
from datetime import datetime
import whois
import pyshark
from collections import Counter
import json
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import re
import psutil
import time

config = open("config.json","w")
basic_conf = """{
    "vtapikey": "",
    "hibpapikey": "",
    "avapikey": ""
}"""
config.write(basic_conf)
config.close()

WATCHED_COMMANDS = [
    'cmd', 'sudo', 'ssh', 'ftp', 'telnet', 'nc', 'netcat', 'bash', 'sh', 'powershell',
    'curl', 'wget', 'tftp', 'scp', 'nmap', 'msfconsole', 'python', 'perl', 'ruby',
    'java', 'gcc', 'g++', 'make', 'install', 'uninstall', 'ls', 'dir', 'cd', 'cat',
    'more', 'less', 'tail', 'head', 'echo', 'rm', 'del', 'rmdir', 'mkdir', 'chmod',
    'chown', 'ifconfig', 'ipconfig', 'netstat', 'traceroute', 'whoami', 'hostname',
    'ping', 'dig', 'nslookup'
]

def server_conn(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
        print(f'Connected to {host}:{port}')
        while True:
            message = input('Type the message or command to send: ')
            if message.lower() == 'exit':
                break
            client_socket.sendall(message.encode('utf-8'))
            print(f'Sent: {message}')
            response = client_socket.recv(1024)
            print(f'Received: {response.decode("utf-8")}')
    except ConnectionRefusedError:
        print('Can\'t connect to the host.')
    finally:
        client_socket.close()
        print('Connection closed.')

def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        print(f"Success: {command}")
        print(stdout.decode())
    else:
        print(f"Error: {command}")
        print(stderr.decode())

def install_apt_packages(packages):
    run_command("sudo apt update")
    for package in packages:
        run_command(f"sudo apt install -y {package}")

def install_pip_packages(packages):
    for package in packages:
        run_command(f"pip install {package}")

def add_apt_repositories(repositories):
    for repo in repositories:
        run_command(f"sudo add-apt-repository -y {repo}")
    run_command("sudo apt update")

def install_security_tools():
    apt_tools = {
        "Nmap": "nmap",
        "Metasploit Framework": "metasploit-framework",
        "Wireshark": "wireshark",
        "John the Ripper": "john",
        "Aircrack-ng": "aircrack-ng",
        "Hydra": "hydra",
        "Tcpdump": "tcpdump",
        "Lynis": "lynis",
        "Nikto": "nikto",
        "Gobuster": "gobuster",
        "Sqlmap": "sqlmap",
        "OpenVAS": "openvas",
        "Netcat": "netcat",
        "Burp Suite": "burpsuite",
        "OWASP ZAP": "owasp-zap",
        "Ettercap": "ettercap-graphical",
        "Social Engineering Toolkit": "set",
        "Maltego": "maltego",
        "Binwalk": "binwalk",
        "Foremost": "foremost",
        "Sleuth Kit": "sleuthkit",
        "Chkrootkit": "chkrootkit",
        "ClamAV": "clamav",
        "Fail2ban": "fail2ban",
        "Yersinia": "yersinia",
        "Recon-ng": "recon-ng",
        "Faraday": "faraday",
        "Radare2": "radare2",
        "Arachni": "arachni",
        "Hashcat": "hashcat",
        "Medusa": "medusa",
        "Fierce": "fierce",
        "Wapiti": "wapiti",
        "Unicornscan": "unicornscan",
        "Exploitdb": "exploitdb",
        "Backdoor Factory": "backdoor-factory",
        "Dnsenum": "dnsenum",
        "Dnsmap": "dnsmap",
        "P0f": "p0f",
        "Wget": "wget",
        "Curl": "curl"
    }
    
    pip_tools = {
        "Scapy": "scapy",
        "Requests": "requests",
        "BeautifulSoup": "bs4",
        "pwntools": "pwntools",
        "impacket": "impacket",
        "twisted": "twisted",
        "Flask": "flask",
        "Django": "django",
        "SQLAlchemy": "sqlalchemy",
        "Scrapy": "scrapy",
        "Faker": "faker"
    }
    
    apt_repositories = [
    ]
    
    print("Select the tools you want to install:")
    
    apt_selections = []
    pip_selections = []
    
    print("\nAPT Packages:")
    for i, (tool_name, package_name) in enumerate(apt_tools.items(), 1):
        print(f"{i}. {tool_name}")
    
    apt_choices = input("\nEnter the numbers of the APT packages you want to install, separated by spaces: ")
    for choice in apt_choices.split():
        if choice.isdigit() and 1 <= int(choice) <= len(apt_tools):
            tool_name = list(apt_tools.keys())[int(choice) - 1]
            apt_selections.append(apt_tools[tool_name])
    
    print("\nPip Packages:")
    for i, (tool_name, package_name) in enumerate(pip_tools.items(), 1):
        print(f"{i}. {tool_name}")
    
    pip_choices = input("\nEnter the numbers of the Pip packages you want to install, separated by spaces: ")
    for choice in pip_choices.split():
        if choice.isdigit() and 1 <= int(choice) <= len(pip_tools):
            tool_name = list(pip_tools.keys())[int(choice) - 1]
            pip_selections.append(pip_tools[tool_name])
    
    add_apt_repositories(apt_repositories)
    
    if apt_selections:
        install_apt_packages(apt_selections)
    
    if pip_selections:
        install_pip_packages(pip_selections)
    
    print("Selected tools installed successfully.")

def check_airmon_ng():
    try:
        subprocess.run(['airmon-ng'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print("airmon-ng is installed.")
    except subprocess.CalledProcessError:
        print("airmon-ng is not installed. Installing...")
        install_airmon_ng()

def install_airmon_ng():
    try:
        subprocess.run(['sudo', 'apt-get', 'update'], check=True)
        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'aircrack-ng'], check=True)
        print("airmon-ng has been installed.")
    except subprocess.CalledProcessError:
        print("Failed to install airmon-ng. Exiting.")
        exit(1)

def select_interface():
    interfaces = os.listdir('/sys/class/net/')
    print("Available interfaces:")
    for idx, interface in enumerate(interfaces):
        print(f"{idx}: {interface}")

    idx = int(input("Select an interface by number: "))
    interface = interfaces[idx]
    return interface

def check_monitor_mode(interface):
    iwconfig_output = subprocess.check_output(['iwconfig', interface]).decode('utf-8')
    if 'Mode:Monitor' in iwconfig_output:
        print(f"Interface {interface} is already in monitor mode.")
        return True
    else:
        print(f"Interface {interface} is not in monitor mode.")
        return False

def enable_monitor_mode(interface):
    print(f"Enabling monitor mode on interface {interface}...")
    subprocess.run(['sudo', 'airmon-ng', 'start', interface])
    return check_monitor_mode(interface)

def packet_handler(packet):

    if packet.haslayer(Dot11):

        if packet.type == 0 and packet.subtype == 12:
            print(f"[ALERT] Deauthentication frame detected from {packet.addr2} to {packet.addr1}")

        elif packet.type == 0 and packet.subtype == 10:
            print(f"[ALERT] Disassociation frame detected from {packet.addr2} to {packet.addr1}")

        elif packet.type == 0 and packet.subtype == 8:
            print(f"Beacon frame: {packet.info.decode('utf-8')} - BSSID: {packet.addr2}")

        elif packet.type == 0 and packet.subtype == 4:
            print(f"Probe request: {packet.addr2}")

        elif packet.type == 0 and packet.subtype == 5:
            print(f"Probe response: {packet.info.decode('utf-8')} - BSSID: {packet.addr2}")

def start_sniffing(interface):
    print(f"Sniffing on interface {interface}...")
    sniff(iface=interface, prn=packet_handler, store=0)

def monitor_wifi():
    check_airmon_ng()
    interface = select_interface()
    if not check_monitor_mode(interface):
        if not enable_monitor_mode(interface):
            print(f"Failed to enable monitor mode on interface {interface}. Exiting.")
            return
    start_sniffing(interface)
def start_listener(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Listening on {host}:{port}...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(f"Received data: {data.decode('utf-8')}")

def list_interfaces():
    return netifaces.interfaces()

def choose_interface():
    interfaces = list_interfaces()
    print("[#]Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx}: {iface}")
    
    iface_index = int(input("[#]Choose the interface by typing the index: "))
    if iface_index < 0 or iface_index >= len(interfaces):
        print("[#]Wrong interface chosen.")
        return None
    
    return interfaces[iface_index]

def detect_arp_spoof(interface):
    print(f"[#]Monitoring ARP on interface: {interface}")
    
    arp_table = defaultdict(set)

    def process_packet(packet):
        if packet.haslayer(ARP):
            arp_op = packet[ARP].op
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            if arp_op == 1: 
                print(f"[#]Received ARP request: {src_ip} wants to know who got {packet[ARP].pdst}")
            elif arp_op == 2: 
                if src_ip in arp_table:
                    if src_mac not in arp_table[src_ip]:
                        print(f"!!! Probable ARP spoofing detected: IP {src_ip} is related to mant MAC adresses: {arp_table[src_ip]} !!!")
                arp_table[src_ip].add(src_mac)
                print(f"[#]ARP reply received: {src_ip} has MAC {src_mac}")


    sniff(iface=interface, prn=process_packet, filter="arp", store=0)
    
def analyze_file(file_path):
    file_info = {}
    file_info['Size'] = os.path.getsize(file_path)
    file_info['Path'] = file_path
    modified_time = os.path.getmtime(file_path)
    file_info['Modified Time'] = datetime.fromtimestamp(modified_time).strftime('%Y-%m-%d %H:%M:%S')
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            md5_hash.update(chunk)
    file_info['MD5'] = md5_hash.hexdigest()
    sha1_hash = hashlib.sha1()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha1_hash.update(chunk)
    file_info['SHA-1'] = sha1_hash.hexdigest()
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256_hash.update(chunk)
    file_info['SHA-256'] = sha256_hash.hexdigest()
    metadata = os.stat(file_path)
    file_info['Metadata'] = {
        'Mode': metadata.st_mode,
        'UID': metadata.st_uid,
        'GID': metadata.st_gid,
        'Size': metadata.st_size,
        'Created Time': datetime.fromtimestamp(metadata.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
        'Modified Time': datetime.fromtimestamp(metadata.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        'Access Time': datetime.fromtimestamp(metadata.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
    }
    return file_info   
def generate_incident_report():
    report = "INCIDENT REPORT\n"
    report += "===============================\n"
    report += "\nINCIDENT DETAILS:\n"
    date = input("Date of the incident (YYYY-MM-DD): ")
    incident_type = input("Type of the incident: ")
    severity = input("Severity of the incident: ")
    reported_by = input("Reported by: ")
    affected_systems = input("Affected systems (comma-separated): ").split(',')
    description = input("Description of the incident: ")
    report += "ACTIONS TAKEN:\n"
    actions_taken = input("Actions taken to resolve the incident: ")
    conclusions = input("Conclusions drawn from the incident: ")
    recommendations = input("Recommendations for future prevention: ")
    report += f"Date: {date}\n"
    report += f"Type: {incident_type}\n"
    report += f"Severity: {severity}\n"
    report += f"Reported by: {reported_by}\n"
    report += f"Affected Systems: {', '.join(affected_systems)}\n"
    report += "INCIDENT DESCRIPTION:\n"
    report += f"{description}\n"
    report += "ACTIONS TAKEN:\n"
    report += f"{actions_taken}\n"
    report += "CONCLUSIONS:\n"
    report += f"{conclusions}\n"
    report += "RECOMMENDATIONS:\n"
    report += f"{recommendations}\n"
    file_name = input("[#]Enter the file name to save the report (without extension): ")
    file_path = f"{file_name}.txt"
    with open(file_path, "w") as file:
        file.write(report)
    print(f"[#]Incident report saved to {file_path}")

def analyze_pcap(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    source_ips = []
    source_ports = []
    destination_ips = []
    destination_ports = []
    protocols = []
    application_protocols = []
    lengths = []
    for packet in capture:
        try:
            source_ips.append(packet.ip.src)
            source_ports.append(packet[packet.transport_layer].srcport)
            destination_ips.append(packet.ip.dst)
            destination_ports.append(packet[packet.transport_layer].dstport)
            protocols.append(packet.transport_layer)
            application_protocols.append(packet.highest_layer)
            lengths.append(packet.length)
        except AttributeError:
            continue

    capture.close()

    source_ip_counts = Counter(source_ips)
    source_port_counts = Counter(source_ports)
    destination_ip_counts = Counter(destination_ips)
    destination_port_counts = Counter(destination_ports)
    protocol_counts = Counter(protocols)
    application_protocol_counts = Counter(application_protocols)
    length_counts = Counter(lengths)

    return {
        "Source IP Counts": source_ip_counts,
        "Source Port Counts": source_port_counts,
        "Destination IP Counts": destination_ip_counts,
        "Destination Port Counts": destination_port_counts,
        "Protocol Counts": protocol_counts,
        "Application Protocol Counts": application_protocol_counts,
        "Length Counts": length_counts,
    }
def track_redirects(url):
    redirects = []
    try:
        response = requests.get(url, allow_redirects=True)
        for history in response.history:
            redirects.append(history.url)
        redirects.append(response.url)
    except requests.exceptions.RequestException as e:
        print("Error while sending a request:", e)
    return redirects

def get_domain_info(domain):
    domain_info = whois.whois(domain)
    if domain_info:
        print(f"Information about domain '{domain}':")
        print("   Registrant:", domain_info.get("registrant"))
        print("   Creation Date:", domain_info.get("creation_date"))
        print("   Expiration Date:", domain_info.get("expiration_date"))
        print("   Registrar:", domain_info.get("registrar"))
    else:
        print("[#]Error while getting information about domain.")

def check_ip_reputation(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})
        print(f"[#]IP Address Reputation for '{ip}':")
        print("   Number of reports:", attributes.get("last_analysis_stats", {}).get("malicious", 0))
        print("   Last analysis date:", datetime.datetime.fromtimestamp(attributes.get("last_analysis_date", 0)))
        print("   Continent:", attributes.get("continent"))
        print("   Country:", attributes.get("country"))
        print("   Regional code:", attributes.get("regional_code"))
        print("   City:", attributes.get("city"))
        print("   ASN:", attributes.get("asn"))
        print("   ISP:", attributes.get("isp"))
        print("   Network:", attributes.get("network"))
        print("   Tags:", ', '.join(attributes.get("tags", [])))
        print("   Last analysis results:")
        last_analysis_results = attributes.get("last_analysis_results", {})
        for engine, details in last_analysis_results.items():
            print(f"      {engine}: {details.get('category')}")

    else:
        print("[#]Error in HTTP request:", response.status_code)

def check_domain_reputation(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})
        print(f"[#]Domain Reputation for '{domain}':")
        print("   Last Analysis Stats:")
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        print(f"      Harmless: {last_analysis_stats.get('harmless', 0)}")
        print(f"      Malicious: {last_analysis_stats.get('malicious', 0)}")
        print(f"      Suspicious: {last_analysis_stats.get('suspicious', 0)}")
        print(f"      Undetected: {last_analysis_stats.get('undetected', 0)}")
        print(f"      Timeout: {last_analysis_stats.get('timeout', 0)}")
        print("   Last analysis date:", datetime.datetime.fromtimestamp(attributes.get("last_analysis_date", 0)))
        print("   Categories:", ', '.join(attributes.get("categories", {}).values()))
        print("   Tags:", ', '.join(attributes.get("tags", [])))
        print("   Whois Date:", datetime.datetime.fromtimestamp(attributes.get("whois_date", 0)))
        print("   Alexa Rank:", attributes.get("rank", {}).get("Alexa", "N/A"))
        print("   Webutation Domain Info:", attributes.get("webutation", "N/A"))
        print("   Last analysis results:")
        last_analysis_results = attributes.get("last_analysis_results", {})
        for engine, details in last_analysis_results.items():
            print(f"      {engine}: {details.get('category')}")

    else:
        print("[#]Error in HTTP request:", response.status_code)

def check_file_reputation(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})

        print(f"[#]File Reputation for hash '{file_hash}':")
        print("   MD5:", attributes.get("md5"))
        print("   SHA1:", attributes.get("sha1"))
        print("   SHA256:", attributes.get("sha256"))
        print("   Size:", attributes.get("size"), "bytes")
        print("   Last analysis date:", datetime.datetime.fromtimestamp(attributes.get("last_analysis_date", 0)))
        
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        print("   Last Analysis Stats:")
        print(f"      Harmless: {last_analysis_stats.get('harmless', 0)}")
        print(f"      Malicious: {last_analysis_stats.get('malicious', 0)}")
        print(f"      Suspicious: {last_analysis_stats.get('suspicious', 0)}")
        print(f"      Undetected: {last_analysis_stats.get('undetected', 0)}")
        print(f"      Timeout: {last_analysis_stats.get('timeout', 0)}")
        print("   Last analysis results:")
        last_analysis_results = attributes.get("last_analysis_results", {})
        for engine, details in last_analysis_results.items():
            print(f"      {engine}: {details.get('category')}")

    else:
        print("[#]Error in HTTP request:", response.status_code)

def check_email_breaches(email, api_key):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "Mozilla/5.0"
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        breaches = response.json()
        if breaches:
            print(f"[#]Email '{email}' found in the following breaches:")
            for breach in breaches:
                print(f"   Name: {breach.get('Name')}")
                print(f"   Domain: {breach.get('Domain')}")
                print(f"   Breach date: {breach.get('BreachDate')}")
                print(f"   Added date: {breach.get('AddedDate')}")
                print(f"   Description: {breach.get('Description')}\n")
        else:
            print(f"[#]No breaches found for email '{email}'.")
    elif response.status_code == 404:
        print(f"[#]No breaches found for email '{email}'.")
    else:
        print(f"[#]Error in HTTP request: {response.status_code}")

def check_phishing(email, api_key):
    url = "https://endpoint.apivoid.com/emailrep/v1/pay-as-you-go/"
    params = {
        "key": api_key,
        "email": email
    }
    response = requests.get(url, params=params)
    
    if response.status_code == 200:
        result = response.json()
        if result.get("data", {}).get("found"):
            print(f"[#]E-mail '{email}' is suspicios.")
            print("[#]Details:")
            print("   Reputation Score:", result.get("data", {}).get("reputation_score"))
            print("   Malicious Activity:", result.get("data", {}).get("malicious_activity"))
            print("   Spam Activity:", result.get("data", {}).get("spam_activity"))
            print("   Leaked Data:", result.get("data", {}).get("leaked_data"))
        else:
            print(f"[#]E-mail '{email}' may not be suspicious.")
    else:
        print("[#]Error in HTTP request:", response.status_code)

def calculate_file_hashes(file_path):
    hash_types = ['md5', 'sha1', 'sha256']
    hash_funcs = {hash_type: hashlib.new(hash_type) for hash_type in hash_types}
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                for hash_func in hash_funcs.values():
                    hash_func.update(chunk)
    except FileNotFoundError:
        return f"File {file_path} not found."
    except Exception as e:
        return f"An error occurred: {e}"
    return {hash_type: hash_func.hexdigest() for hash_type, hash_func in hash_funcs.items()}

def port_scanner(target_ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    return open_ports

def update_config(config_file, key, new_value):
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    config[key] = new_value
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)
def load_config(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)
    return config

def banner_grab(ip, port):
    try:
        sock = socket.socket()
        sock.connect((ip, port))
        sock.settimeout(2)
        banner = sock.recv(1024).decode().strip()
        return banner
    except:
        return None

def ssl_cert_from_file(cert_file_path):
    if not os.path.exists(cert_file_path):
        raise FileNotFoundError(f"The file {cert_file_path} does not exist.")

    try:
        with open(cert_file_path, 'r') as f:
            cert_data = f.read()
    except IOError as e:
        raise IOError(f"Error reading file {cert_file_path}: {e}")

    certificates = cert_data.split("-----END CERTIFICATE-----")
    certificates = [cert + "-----END CERTIFICATE-----" for cert in certificates if cert.strip()]

    cert_info = []
    for cert in certificates:
        try:
            x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            cert_info.append({
                'Subject': x509_cert.subject.rfc4514_string(),
                'Issuer': x509_cert.issuer.rfc4514_string(),
                'Valid From': x509_cert.not_valid_before.isoformat(),
                'Valid To': x509_cert.not_valid_after.isoformat()
            })
        except ValueError as e:
            print(f"Error processing certificate: {e}")
            continue

    return cert_info

def hashid(hash_string):
    hash_types = {
        'MD5': r'^[a-fA-F0-9]{32}$',
        'SHA-1': r'^[a-fA-F0-9]{40}$',
        'SHA-224': r'^[a-fA-F0-9]{56}$',
        'SHA-256': r'^[a-fA-F0-9]{64}$',
        'SHA-384': r'^[a-fA-F0-9]{96}$',
        'SHA-512': r'^[a-fA-F0-9]{128}$',
        'SHA3-224': r'^[a-fA-F0-9]{56}$',
        'SHA3-256': r'^[a-fA-F0-9]{64}$',
        'SHA3-384': r'^[a-fA-F0-9]{96}$',
        'SHA3-512': r'^[a-fA-F0-9]{128}$',
        'Blowfish': r'^\$2[ayb]\$.{56}$',
        'bcrypt': r'^\$2[ayb]\$.{56}$',
        'SHA-1 (Unix)': r'^\{SHA\}[a-zA-Z0-9+/]{27}=$',
        'NTLM': r'^[a-fA-F0-9]{32}$',
        'LM': r'^[a-fA-F0-9]{32}$',
        'MySQL': r'^[a-fA-F0-9]{16}$',
        'MySQL5': r'^\*[a-fA-F0-9]{40}$',
        'MySQL 160bit': r'^[a-fA-F0-9]{40}$',
        'Cisco-IOS(MD5)': r'^[a-fA-F0-9]{16}$',
        'Cisco-IOS(SHA-256)': r'^[a-fA-F0-9]{64}$',
        'Juniper': r'^[a-fA-F0-9]{32}$',
        'GOST R 34.11-94': r'^[a-fA-F0-9]{64}$',
        'RipeMD-160': r'^[a-fA-F0-9]{40}$',
        'Whirlpool': r'^[a-fA-F0-9]{128}$'
    }
    
    for hash_type, pattern in hash_types.items():
        if re.match(pattern, hash_string):
            return hash_type
    return 'Unknown hash type'

def is_online(url):
    try:
        response = requests.get(url)
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"[!]Error checking {url: {e}}")
        return False
    
def sysinfo():
    return {
        'Platform': os.name,
        'Name': os.uname().sysname,
        'Release': os.uname().release,
        'Version': os.uname().version,
        'Machine': os.uname().machine
}

def active_users():
    return psutil.users()

def open_connections():
    return psutil.net_connections()

def monitor_processes():
    processes = [(proc.pid, proc.name()) for proc in psutil.process_iter()]
    return processes

def terminate_process(process_name):
    subprocess.run(['pkill', '-f', process_name])

def monitor_system(cpu_max, ram_max, interval):
    while True:
        cpu_usage = psutil.cpu_percent(interval=1)
        ram_usage = psutil.virtual_memory().percent

        if cpu_usage > cpu_max:
            print(f"[!]Alert. CPU usage is at: {cpu_usage}")
        if ram_usage > ram_max:
            print(f"[!]Alert . RAM usage is at: {ram_usage}")

        time.sleep(interval)


def process_packet(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        for command in WATCHED_COMMANDS:
            if command in payload:
                print(f"[!]Suspicious command found: {command}")
                break

def revshell_sniffing():
    print("[#]Started sniffing on all interfaces...")
    sniff(prn=process_packet, filter="tcp", store=False)

def main():
    try:
        if os.geteuid() == 0:
            pass
        else:
            raise PermissionError("[#]This program must be run as root!")
    except PermissionError as e:
        print(e)
        exit()
    print("""
    
                                                |>>>
                                                |
                                            _  _|_  _
        ╔╗ ┌─┐┌─┐┌┬┐┬┌─┐┌┐┌                |;|_|;|_|;|
        ╠╩╗├─┤└─┐ │ ││ ││││                \\\\.    .  /
        ╚═╝┴ ┴└─┘ ┴ ┴└─┘┘└┘                 \\\\:  .  /
                                             ||:   |
                                             ||:.  |
                                             ||:  .|
                                             ||:   |       \,/
                                             ||: , |            /`\\
                                             ||:   |
                                             ||: . |
              __                            _||_   |
     ____--`~    '--~~__            __ ----~    ~`---,              
-~--~                   ~---__ ,--~'                  ~~----_____""")
    print("""Bastion is a command-line tool for securing a Linux server. 
It provides a user-friendly interface for automating the installation and 
configuration of various security-related services such as SSH, Firewall, and Samba. 
The program offers easy-to-use menus and prompts to guide users through the setup process,
making it ideal for Linux beginners or users who want to quickly secure their server without 
going through the hassle of manual configuration.
In the newest version we added blue teaming modules for begginer and intermediate SOC analysts 
that want a lightweight and quick tools all in one place.""")
    
    input("Press Enter to continue...")
    
    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')    
            print("""    [#]Available modules
        SYSTEM AND SERVICES
        1.System update
        2.System upgrade
        3.Installation and configuration SSH
        4.Installation and configuration FTP
        5.Installation and configuration SMB
        6.Installation and configuration MySQL
        7.Installation and configuration Apache
        8.Installation and configuration OpenVPN
        9.Installation and configuration Fail2Ban
        10.Installation and configuration UFW
        11.Installation and configuration ClamAV
    [#]-----------------------------------------------[#]
        NETWORK TOOLS
        21.ARP-spoof Detection
        22.TCP Connector
        23.Wifi Attacks Detector
        24.TCP Listener
        25.Port Scanner
        26.Banner Grabber
    [#]-----------------------------------------------[#]
        ANALYSIS, FORENSIC, OSINT and THREAT HUNTING
        31.File Analyzer    
        32.PCAP Analyzer
        33.Redirect Checker
        34.WHOIS Domain Information
        35.IP Reputation (VirusTotal)
        36.Domain Reputation (VirusTotal)
        37.File Reputation by Hash (VirusTotal)
        38.HaveIBeenPwned Email Leak    
        39.Suspicious Email Check 
        40.Get File Hashes
        41.Analyze SSL Certifitaces 
        42.Hash Identifier
        43.Check If The Website is online       
    [#]-----------------------------------------------[#]
        ACTIVE MONITORING AND RESPONDING
        61.Get System Info
        62.List Active Users
        63.List Open Network Connections
        64.Monitor Processes
        65.Terminate Process
        66.CPU And RAM usage monitor
        67.Reverse/Bind Shell Connection Detector
     [#]-----------------------------------------------[#]
        REPORTING AND OTHER TOOLS
        81.Report Generator   
        82.Take A Screenshot          
        84.Useful Links And Resources                 
    [#]-----------------------------------------------[#]
        CONFIG AND CREDITS
        96.Advanced Security Configuration
        97.Install Security Tools
        98.Info And Contact
        99.Configure
        0. Exit""")
            module = input("[#]Choose a module: ")
            
            if module == '1':
                print("[#]Executing command apt-get update")
                os.sytem("apt-get update -y > /dev/null")
                print("[#]Update completed!")
            elif module == '2':
                print("[#]Executing command apt-get upgrade ")
                os.system("apt -get upgrade -y /dev/null")
                print("[#]Upgrade completed!")
            elif module == '3':
                os.system("apt-get install openssh-server -y > /dev/null")  
                ssh_config = open('/etc/ssh/sshd_config', 'a')  
                print("[#]Which security settings do you want to apply?")
                print("1. Disable password authentication")
                print("2. Disable root login")
                print("3. Restrict SSH access to specific users")
                print("4. Disable X11 forwarding")
                print("5. Disable PAM authentication")
                print("6. Change SSH port")
                print("[#]Enter the numbers of the settings you want to apply, separated by spaces:")
                settings = list(map(int, input().split()))
                if 1 in settings:
                    ssh_config.write("PasswordAuthentication no\n")
                if 2 in settings:
                    ssh_config.write("PermitRootLogin no\n")
                if 3 in settings:
                    allowed_users = input("[#]Enter the usernames of the users allowed to access SSH, separated by spaces: ")
                    ssh_config.write("AllowUsers " + allowed_users + "\n")
                if 4 in settings:
                    ssh_config.write("X11Forwarding no\n")
                if 5 in settings:
                    ssh_config.write("UsePAM no\n")
                if 6 in settings:
                    new_port = input("[#]Enter the new SSH port number: ")
                    ssh_config.write("Port " + new_port + "\n")
                ssh_config.close()
                os.system("systemctl restart ssh -y > /dev/null")  
                print("[#]Configuring SSH finished!")
            elif module == '4':
                os.system("apt-get install vsftpd -y > /dev/null")
                ftp_config = open('/etc/vsftpd.conf', 'a')
                print("[#]Which security settings do you want to apply?")
                print("1. Disable anonymous FTP access")
                print("2. Restrict FTP access to local users only")
                print("3. Enable userlist file")
                print("4. Enable write access for local users")
                print("5. Allow FTP access from specific IP addresses")
                print("[#]Enter the numbers of the settings you want to apply, separated by spaces:")
                settings = list(map(int, input().split()))
                if 1 in settings:
                    ftp_config.write("anonymous_enable=NO\n")
                if 2 in settings:
                    ftp_config.write("chroot_local_user=YES\n")
                if 3 in settings:
                    ftp_config.write("userlist_enable=YES\n")
                if 4 in settings:
                    ftp_config.write("write_enable=YES\n")
                if 5 in settings:
                    allowed_ips = input("[#]Enter the IP addresses allowed to access FTP, separated by spaces: ")
                    ftp_config.write("tcp_wrappers=YES\n")
                    ftp_config.write("allow_file=/etc/vsftpd.allowed_ips\n")
                    allowed_ips_file = open('/etc/vsftpd.allowed_ips', 'w')
                    allowed_ips_file.write(allowed_ips)
                    allowed_ips_file.close() 
                ftp_config.close()
                os.system("systemctl restart vsftpd -y > /dev/null")
                print("[#]Configuring FTP finished!")
            elif module == '5':
                os.system("apt-get install samba -y > /dev/null")
                samba_config = open('/etc/samba/smb.conf', 'a')
                print("[#W]hich security settings do you want to apply?")
                print("1. Encrypt passwords")
                print("2. Restrict anonymous access")
                print("3. Limit access to specific users")
                print("4. Limit access to specific IP addresses")
                print("5. Require SMB signing")
                print("[#]Enter the numbers of the settings you want to apply, separated by spaces:")
                settings = list(map(int, input().split()))
                if 1 in settings:
                    samba_config.write("encrypt passwords = yes\n")
                if 2 in settings:
                    samba_config.write("restrict anonymous = 2\n")
                if 3 in settings:
                    users = input("[#]Enter the usernames of the users who should have access, separated by spaces: ")
                    samba_config.write("valid users = " + users + "\n")
                if 4 in settings:
                    ips = input("[#]Enter the IP addresses of the machines that should have access, separated by spaces: ")
                    samba_config.write("hosts allow = " + ips + "\n")
                if 5 in settings:
                    samba_config.write("server signing = mandatory\n")
                    samba_config.write("client signing = mandatory\n")
                samba_config.close()
                os.system("systemctl restart smb -y > /dev/null")
                print("[#]Configuring SMB finished!")
            elif module == '6':
                print("[#]Which security settings do you want to apply?")
                print("1. Bind to localhost")
                print("2. Disable networking")
                print("3. Increase max connections and thread cache size")
                print("4. Enable query caching")
                print("5. Enable event scheduler")
                print("[#]Enter the numbers of the settings you want to apply, separated by spaces:")
                settings = list(map(int, input().split()))
                os.system("apt-get install mysql-server")
                os.system("mysql_secure_installation")
                mysql_config = open('/etc/mysql/mysql.conf.d/mysqld.cnf', 'a')
                mysql_config.write("# MySQL security settings\n")
                if 1 in settings:
                    mysql_config.write("bind-address = 127.0.0.1\n")
                if 2 in settings:
                    mysql_config.write("skip-networking\n")
                if 3 in settings:
                    mysql_config.write("max_connections = 500\n")
                    mysql_config.write("thread_cache_size = 50\n")
                if 4 in settings:
                    mysql_config.write("query_cache_limit = 1M\n")
                    mysql_config.write("query_cache_size = 16M\n")
                if 5 in settings:
                    mysql_config.write("event_scheduler = ON\n")
                mysql_config.close()
                os.system("systemctl restart mysql")
                print("[#]Configuring Apache finished!")
            elif module == "7":
                print("[#]Which security settings do you want to apply?")
                print("1. Disable directory listing")
                print("2. Disable server status")
                print("3. Enable HTTP headers")
                print("4. Enable URL rewriting")
                print("[#]Enter the numbers of the settings you want to apply, separated by spaces:")
                settings = list(map(int, input().split()))    
                if settings == "1":
                    os.system("a2dismod -f autoindex")
                elif settings == "2":
                    os.system("a2dismod -f status")
                elif settings == "3":
                    os.system("a2enmod -f headers")
                elif settings == "4":
                    os.system("a2enmod -f rewrite")
                os.system("systemctl restart apache2")
                print("[#]Configuring Apache finished!")
            elif module == "8":
                os.system("apt-get install openvpn")
                os.system("openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj \"/C=US/ST=New York/L=New York/O=Company/OU=IT Department/CN=vpn.example.com\" -keyout /etc/openvpn/server.key -out /etc/openvpn/server.crt")
                openvpn_config = open('/etc/openvpn/server.conf', 'a')
                print("[#]Which OpenVPN security settings would you like to apply?")
                print("1. Basic (recommended for most users)")
                print("2. Advanced (recommended for experienced users)")
                choice = input("[#]Enter your choice (1 or 2): ")
                if choice == "1":
                    openvpn_config.write("# OpenVPN Basic Security Settings\n")
                    openvpn_config.write("user nobody\n")
                    openvpn_config.write("group nogroup\n")
                    openvpn_config.write("cipher AES-256-CBC\n")
                    openvpn_config.write("auth SHA256\n")
                    openvpn_config.write("tls-version-min 1.2\n")
                    openvpn_config.write("keepalive 10 120\n")
                    openvpn_config.write("persist-key\n")
                    openvpn_config.write("persist-tun\n")
                    openvpn_config.write("status /var/log/openvpn-status.log\n")
                    openvpn_config.write("log-append /var/log/openvpn.log\n")
                    print("[#]Configuring OpenVPN finished!")
                elif choice == "2":
                    openvpn_config.write("# OpenVPN Advanced Security Settings\n")
                    openvpn_config.write("user nobody\n")
                    openvpn_config.write("group nogroup\n")
                    openvpn_config.write("cipher AES-256-CBC\n")
                    openvpn_config.write("auth SHA512\n")
                    openvpn_config.write("tls-cipher TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-DSS-WITH-AES-256-CBC-SHA:TLS-RSA-WITH-AES-256-CBC-SHA\n")
                    openvpn_config.write("tls-version-min 1.2\n")
                    openvpn_config.write("tls-auth /etc/openvpn/ta.key 0\n")
                    openvpn_config.write("key-direction 0\n")
                    openvpn_config.write("keepalive 10 120\n")
                    openvpn_config.write("persist-key\n")
                    openvpn_config.write("persist-tun\n")
                    openvpn_config.write("status /var/log/openvpn-status.log\n")
                    openvpn_config.write("log-append /var/log/openvpn.log\n")
                    print("[#]Configuring OpenVPN finished!")
                else:
                    print("Invalid choice. Please enter 1 or 2.")
                    return
                openvpn_config.close()
                os.system("openvpn --genkey --secret /etc/openvpn/ta.key")
                os.system("systemctl enable openvpn-server@server.service")
                os.system("systemctl start openvpn-server@server.service")
            elif module == "9":
                os.system("apt-get install fail2ban")
                jail_local_config = open('/etc/fail2ban/jail.local', 'a')
                jail_local_config.write("[sshd]\n")
                jail_local_config.write("enabled = true\n")
                jail_local_config.write("port = ssh\n")
                jail_local_config.write("filter = sshd\n")
                jail_local_config.write("logpath = /var/log/auth.log\n")
                jail_local_config.write("maxretry = 5\n")
                jail_local_config.write("findtime = 1d\n")
                jail_local_config.write("bantime = 1d\n")
                jail_local_config.close()
                os.system("systemctl enable fail2ban")
                os.system("systemctl start fail2ban")
                print("[#]Configuring Fail2Ban finished!")
            elif module == "10":
                os.system("apt-get install ufw")
                os.system("ufw enable")
                os.system("ufw default deny incoming")
                os.system("ufw default allow outgoing")
                os.system("ufw allow ssh")
                os.system("ufw allow http")
                os.system("ufw allow https")
                os.system("systemctl enable ufw")
                os.system("systemctl start ufw")
                print("[#]Configuring UFW finished!")
            elif module == "11":
                os.system("apt-get install clamav")
                clamd_local_config = open('/etc/clamav/clamd.conf', 'a')
                clamd_local_config.write("LocalSocket /var/run/clamav/clamd.ctl\n")
                clamd_local_config.write("LogFile /var/log/clamav/clamav.log\n")
                clamd_local_config.write("LogSyslog false\n")
                clamd_local_config.write("LogRotate true\n")
                clamd_local_config.write("LogFacility LOG_LOCAL6\n")
                clamd_local_config.write("User clamav\n")
                clamd_local_config.write("TCPSocket 3310\n")
                clamd_local_config.close()
                os.system("freshclam")
                os.system("systemctl enable clamav-daemon")
                os.system("systemctl start clamav-daemon")
                print("[#]Configuring ClamAV finished!")
            elif module == "21":
                print("[#]ARP spoof detector")
                interface = choose_interface()
                if interface:
                    detect_arp_spoof(interface)
            elif module == "22":
                print("[#]TCP Connector")
                print("[#]Type the IP and port that you want to connect to. Type exit to finish connection")
                ip = input("[#]IP:")
                port = int(input("[#]Port:"))
                server_conn(ip,port)
            elif module == "23":
                monitor_wifi()
            elif module == "24":
                print("[#]TCP Listener. Listens and print incoming data from potential target.")
                ip = input("[#]IP of the listener:")
                port = int(input("[#]Port of the listener"))
                start_listener(ip,port)
            elif module == "25":
                print("[#]Simple port scanner")
                target_ip = input("[#]Enter the target IP address: ")
                start_port = int(input("[#]Enter the start port: "))
                end_port = int(input("[#]Enter the end port: "))
                open_ports = port_scanner(target_ip, start_port, end_port)
                if open_ports:
                    print(f"[#]Open ports on {target_ip}: {open_ports}")
                else:
                    print(f"[#]No open ports found on {target_ip}")
                input("Press Enter to continue...")
            elif module == "26":
                print("[#]Banner Grabber")
                ip = input("[#]Enter an IP address: ")
                port = int(input("[#]Enter port: "))
                print(banner_grab(ip, port))
                input("Press Enter to continue...")
            elif module == "31":
                print("[#]File Analyzer")
                file_path = input("[#]Enter the path of file to analyze: ")
                result = analyze_file(file_path)
                print("[#]File Analysis Result:")
                for key, value in result.items():
                    if key == 'Metadata':
                        print(f"\n{key}:")
                        for k, v in value.items():
                            print(f"  {k}: {v}")
                    else:
                        print(f"{key}: {value}")
                input("Press Enter to continue...")
            elif module == "32":
                print("[#]PCAP Analyzer")
                pcap_file = input("[#]Type the path to pcap file: ")
                summary = analyze_pcap(pcap_file)
                for key, value in summary.items():
                    print(key + ":")
                    for item, count in value.items():
                        print(f"   {item}: {count}")
                    print()
                input("Press Enter to continue...")
            elif module == "33":
                print("[#]Redirect check")
                url = input("[#]Enter a url with http or https to check for possible redirects: ")
                redirects = track_redirects(url)
                print("Registered Redirects:")
                for redirect_url in redirects:
                    print(redirect_url)
                input("Press Enter to continue...")
            elif module == "34":
                print("[#]WHOIS domain check")
                get_domain_info(input("[#]Type the domain to check: "))
                input("Press Enter to continue...")
            elif module == "35":
                config = load_config('config.json')
                if config["vtapikey"] == "":
                    print("[#]No VirusTotal API key found. Use Config to add one.")
                    input("Press Enter to continue...")
                else:
                    print("[#]IP Reputation check")
                    ip_address = input("[#]Type the IP Address to check: ")
                    check_ip_reputation(ip_address,config["vtapikey"])
                input("Press Enter to continue...")
            elif module == "36":
                config = load_config('config.json')
                if config["vtapikey"] == "":
                    print("[#]No VirusTotal API key found. Use Config to add one.")
                    input("Press Enter to continue...")
                else:
                    print("[#]Domain Reputation Check")
                    domain = input("[#]Type the domain to check: ")
                    check_domain_reputation(domain, config["vtapikey"])
                input("Press Enter to continue...")
            elif module == "37":
                config = load_config('config.json')
                if config["vtapikey"] == "":
                    print("[#]No VirusTotal API key found. Use Config to add one.")
                    input("Press Enter to continue...")
                else:
                    print("[#]File Reputation Check") 
                    file_hash = input("[#]Type the file hash (MD5/SHA1/SHA256) to check: ")
                    check_file_reputation(file_hash,config["vtapikey"])
                    input("Press Enter to continue...")
            elif module == "38":
                config = load_config('config.json')
                if config["hibpapikey"] == "":
                    print("[#]No HaveIBeenPwned API key found. Use Config to add one.")
                    input("Press Enter to continue...")
                else:    
                    print("[#]HaveIBeenPwned Email Leak Check")
                    email = input("[#]Type the email address to check: ")
                    check_email_breaches(email, config["hibpapikey"])
                input("Press Enter to continue...")
            elif module == "39":
                config = load_config('config.json')
                if config["avapikey"] == "":
                    print("[#]No APIVoid API key found. Use Config to add one")
                    input("Press Enter to continue...")
                else:
                    print("[#]Suspicious Email Check")
                    email = input("[#]Type an email to check: ")
                    check_phishing(email, config["avapikey"])
                input("Press Enter to continue...")
            elif module == "40":
                print("[#]Get File Hashes")
                file_path = input("[#]Enter the path to the file: ")
                hashes = calculate_file_hashes(file_path)
                if isinstance(hashes, dict):
                    for hash_type, hash_value in hashes.items():
                        print(f"The {hash_type.upper()} hash of the file is: {hash_value}")
                else:
                    print(hashes)
                input("Press Enter to continue...")
            elif module == "41":
                print("[#]SSL Certificates Analzyer")
                cert_path = input("[#]Provide a path to certificate file")
                cert_info = ssl_cert_from_file(cert_path)
                for index, info in enumerate(cert_info, start=1):
                    print(f"[#]Certificate {index}:")
                    for key, value in info.items():
                        print(f"  {key}: {value}")
                    print()
                input("Press Enter to continue...")
            elif module == "42":
                print("[#]Hash Identifier")
                hash = input("[#]Provide a hash to identify: ")
                print(f"[#]Hash: {hash} Type: {hashid(hash)}")
                input("Press Enter to continue...")
            elif module == "43":
                print("[#]Check If The Website is online ")
                url = input("[#]Provide the url to check with http/https :")
                print(f"[#]Website is {'online' if is_online(url) else 'offline'}")
                input("Press Enter to continue...")
            elif module == "61":
                print("[#]Get System Info")
                print("System Information:")
                system_info = sysinfo()
                for key, value in system_info.items():
                    print(f"  {key}: {value}")
                input("Press Enter to continue...")
            elif module == "62":
                print("[#]List Active Users")
                users = active_users()
                print("[#]Active Users:")
                for user in users:
                    print(f"  User: {user.name}")
                    print(f"  Terminal: {user.terminal}")
                    print(f"  Host: {user.host}")
                    print(f"  Started: {user.started}")
                    print()
                input("Press Enter to continue...")
            elif module == "63":
                print("[#]List open network connections")
                connections = open_connections()
                print("[#]Open Network Connections:")
                for conn in connections:
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    print(f"  fd: {conn.fd}")
                    print(f"  family: {conn.family}")
                    print(f"  type: {conn.type}")
                    print(f"  laddr: {laddr}")
                    print(f"  raddr: {raddr}")
                    print(f"  status: {conn.status}")
                    print(f"  pid: {conn.pid}")
                    print()
                input("Press Enter to continue...")
            elif module == "64":
                print("[#]Process monitor")
                processes = monitor_processes()
                print("Running Processes:")
                for pid, name in processes:
                    print(f"  PID: {pid}")
                    print(f"  Name: {name}")
                    print()
                input("Press Enter to continue...")
            elif module == "65":
                print("[#]Terminate process")
                name = input("[#]Provide a process name to terminate: ")
                terminate_process(name)
                print("[#]Process terminated")
                input("Press Enter to continue...")
            elif module == "66":
                print("[#]CPU and RAM usage monitor with alerts")
                cpu_max = int(input("[#]Set the maximum CPU usage: "))
                ram_max = int(input("[#]Set the maximum RAM usage: "))
                interval = int(input("[#]Set the interval of checking: "))
                monitor_system(cpu_max, ram_max, interval)
            elif module == "67":
                print("[#]Reverse/Bind Shell Connection Detector")
                revshell_sniffing()
            elif module == "81":
                print("[#]Report generator")
                generate_incident_report()
                input("Press Enter to continue...")
            elif module == "96":
                print("[#]Advanced security configuration (SOON)")
            elif module == "97":
                install_security_tools()
            elif module == "98":
                print("[#]Info and contact")
            elif module == "99":
                print("[#]Config")
                print("1.Add VirusTotal API key")
                print("2.Add HaveIBeenPwned API key")
                print("3.Add APIVoid API key")
                config = input("[#]Type the index of configuration you want to do: ")
                if config == "1":
                    apikey = input("[#]Provide your VirusTotal API key: ")
                    config_file = 'config.json'
                    key_to_update = 'vtapikey'
                    new_value = apikey
                    update_config(config_file, key_to_update, new_value)
                elif config == "2":
                    apikey = input("[#]Provide your HaveIBeenPwned API key: ")
                    config_file = 'config.json'
                    key_to_update = 'hibpapikey'
                    new_value = apikey
                    update_config(config_file, key_to_update, new_value)
                elif config == "3":
                    apikey = input("[#]Provide your APIVoid API key: ")
                    config_file = 'config.json'
                    key_to_update = 'avapikey'
                    new_value = apikey
                    update_config(config_file, key_to_update, new_value)
            elif module == '0':
                print("[#]Goodbye!")
                break
            else:
                print("[#]Wrong module chosen.")
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
