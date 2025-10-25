#!/usr/bin/env python3

#Run the file with OpenVAS / NMAP Exported XMLs in the same direcotry.
#this will generate a list of Hostnames, handy for making a network Map.

import xml.etree.ElementTree as ET
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional

@dataclass
class HostInfo:
    ip: str = ""
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os_name: str = ""
    os_version: str = ""
    open_ports: Set[str] = field(default_factory=set)
    additional_hostnames: Set[str] = field(default_factory=set)

    def merge_with(self, other):
        """Merge information from another HostInfo object"""
        if other.hostname and not self.hostname:
            self.hostname = other.hostname
        if other.mac and not self.mac:
            self.mac = other.mac
        if other.vendor and not self.vendor:
            self.vendor = other.vendor
        if other.os_name and not self.os_name:
            self.os_name = other.os_name
        if other.os_version and not self.os_version:
            self.os_version = other.os_version

        self.open_ports.update(other.open_ports)
        self.additional_hostnames.update(other.additional_hostnames)

        if other.hostname:
            self.additional_hostnames.add(other.hostname)

@dataclass
class NetworkInfo:
    domain: str = ""
    dhcp_server: str = ""
    dns_servers: List[str] = field(default_factory=list)
    gateway: str = ""
    network_range: str = ""

class XMLParser:
    def __init__(self):
        self.hosts = {}
        self.network_info = NetworkInfo()

    def extract_hostname_from_text(self, text):
        """Extract hostnames from various text sources using regex patterns"""
        hostnames = set()
        if not text:
            return hostnames

        # Pattern for real hostnames/FQDN (must contain letters and reasonable length)
        hostname_pattern = r'\b([a-zA-Z][a-zA-Z0-9\-]{2,61}(?:\.[a-zA-Z][a-zA-Z0-9\-]{1,61})*)\b'

        # SSL Certificate Common Name patterns
        ssl_cn_pattern = r'(?:CN=|Subject:.*CN=)([^,\n\r\s]+(?:\.[a-zA-Z]{2,}))'

        # DNS PTR record patterns
        ptr_pattern = r'domain name pointer ([^\s]+)'

        # Specific Windows hostname pattern
        netbios_pattern = r'\b([A-Z][A-Z0-9\-]{2,14})\b'

        # Common words to exclude
        exclude_words = {
            'http', 'https', 'tcp', 'udp', 'ssl', 'tls', 'rpc', 'api', 'service', 'server',
            'client', 'host', 'port', 'protocol', 'version', 'info', 'status', 'error',
            'config', 'admin', 'user', 'guest', 'system', 'local', 'remote', 'domain',
            'windows', 'linux', 'microsoft', 'apache', 'nginx', 'mysql', 'sql',
            'data', 'file', 'log', 'temp', 'test', 'dev', 'prod', 'www', 'mail',
            'ftp', 'ssh', 'telnet', 'dns', 'dhcp', 'ntp', 'snmp', 'ldap'
        }

        # Find all potential hostnames
        for pattern in [hostname_pattern, ssl_cn_pattern, ptr_pattern, netbios_pattern]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                match = match.strip()
                if (match and
                    not re.match(r'^\d+\.\d+\.\d+\.\d+$', match) and  # Skip IP addresses
                    not re.match(r'^[0-9a-fA-F\-]+$', match) and      # Skip UUIDs/hex strings
                    len(match) >= 3 and                                # Minimum length
                    match.lower() not in exclude_words and             # Not in exclude list
                    '.' in match or match.isupper()):                  # FQDN or uppercase (NetBIOS)
                    hostnames.add(match)

        return hostnames

    def parse_nmap_xml(self, xml_file):
        """Parse NMAP XML file and extract host information"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Extract network range from scan info
            scaninfo = root.find('scaninfo')
            if scaninfo is not None:
                args = root.get('args', '')
                if '/24' in args or '/16' in args or '/8' in args:
                    network_match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', args)
                    if network_match:
                        self.network_info.network_range = network_match.group(1)

            # Parse host information
            for host in root.findall('host'):
                if host.find('status').get('state') != 'up':
                    continue

                host_info = HostInfo()

                # Get IP address
                for addr in host.findall('address'):
                    addr_type = addr.get('addrtype')
                    if addr_type == 'ipv4':
                        host_info.ip = addr.get('addr')
                        # Check if this looks like a gateway (usually .1)
                        if host_info.ip.endswith('.1'):
                            self.network_info.gateway = host_info.ip
                    elif addr_type == 'mac':
                        host_info.mac = addr.get('addr')
                        host_info.vendor = addr.get('vendor', '')

                # Get hostname
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    for hostname in hostnames.findall('hostname'):
                        name = hostname.get('name')
                        if name:
                            if not host_info.hostname:
                                host_info.hostname = name
                            else:
                                host_info.additional_hostnames.add(name)

                # Get OS information
                os_elem = host.find('os')
                if os_elem is not None:
                    for osmatch in os_elem.findall('osmatch'):
                        if not host_info.os_name:
                            host_info.os_name = osmatch.get('name', '')
                            break

                    for osclass in os_elem.findall('osclass'):
                        if not host_info.os_version:
                            os_family = osclass.get('osfamily', '')
                            os_gen = osclass.get('osgen', '')
                            if os_family and os_gen:
                                host_info.os_version = f"{os_family} {os_gen}"
                            elif os_family:
                                host_info.os_version = os_family

                # Get open ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            portid = port.get('portid')
                            protocol = port.get('protocol')
                            host_info.open_ports.add(f"{portid}/{protocol}")

                            # Extract service information for hostname hints
                            service = port.find('service')
                            if service is not None:
                                service_name = service.get('name', '')
                                service_product = service.get('product', '')
                                service_version = service.get('version', '')
                                service_info = f"{service_name} {service_product} {service_version}"

                                # Extract hostnames from service info
                                extracted_hostnames = self.extract_hostname_from_text(service_info)
                                host_info.additional_hostnames.update(extracted_hostnames)

                # Extract hostnames from script output
                hostscript = host.find('hostscript')
                if hostscript is not None:
                    for script in hostscript.findall('script'):
                        script_output = script.get('output', '')
                        extracted_hostnames = self.extract_hostname_from_text(script_output)
                        host_info.additional_hostnames.update(extracted_hostnames)

                # Look for network services
                if '53/tcp' in host_info.open_ports or '53/udp' in host_info.open_ports:
                    if host_info.ip not in self.network_info.dns_servers:
                        self.network_info.dns_servers.append(host_info.ip)

                # Store host info
                if host_info.ip:
                    self.hosts[host_info.ip] = host_info

        except Exception as e:
            print(f"Error parsing NMAP XML: {e}")

    def parse_openvas_xml(self, xml_file):
        """Parse OpenVAS XML file and extract host information"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Parse host information from results
            for result in root.findall('.//result'):
                host_elem = result.find('host')
                if host_elem is not None:
                    ip = host_elem.text.strip()
                    if not ip:
                        continue

                    # Get hostname if available
                    hostname_elem = host_elem.find('hostname')
                    hostname = hostname_elem.text if hostname_elem is not None and hostname_elem.text else ""

                    # Create or update host info
                    if ip not in self.hosts:
                        self.hosts[ip] = HostInfo(ip=ip)

                    if hostname and not self.hosts[ip].hostname:
                        self.hosts[ip].hostname = hostname

                    # Extract OS information from detection details
                    detection = result.find('detection')
                    if detection is not None:
                        for detail in detection.findall('.//detail'):
                            name_elem = detail.find('name')
                            value_elem = detail.find('value')
                            if name_elem is not None and value_elem is not None:
                                if name_elem.text == 'product' and value_elem.text:
                                    # Extract OS from CPE
                                    cpe = value_elem.text
                                    if 'cpe:/o:' in cpe:
                                        os_parts = cpe.replace('cpe:/o:', '').split(':')
                                        if len(os_parts) >= 2:
                                            vendor = os_parts[0].replace('_', ' ').title()
                                            product = os_parts[1].replace('_', ' ').title()
                                            version = os_parts[2] if len(os_parts) > 2 else ""

                                            if not self.hosts[ip].os_name:
                                                self.hosts[ip].os_name = f"{vendor} {product}"
                                            if not self.hosts[ip].os_version and version:
                                                self.hosts[ip].os_version = version

                    # Extract port information
                    port_elem = result.find('port')
                    if port_elem is not None and port_elem.text:
                        port_info = port_elem.text.strip()
                        if '/' in port_info:
                            self.hosts[ip].open_ports.add(port_info)

                    # Extract additional hostnames from descriptions
                    description_elem = result.find('description')
                    if description_elem is not None and description_elem.text:
                        extracted_hostnames = self.extract_hostname_from_text(description_elem.text)
                        self.hosts[ip].additional_hostnames.update(extracted_hostnames)

        except Exception as e:
            print(f"Error parsing OpenVAS XML: {e}")

    def detect_domain_info(self):
        """Try to detect domain information from hostnames"""
        domains = set()
        for host_info in self.hosts.values():
            all_names = {host_info.hostname}.union(host_info.additional_hostnames)
            for name in all_names:
                if '.' in name and not name.replace('.', '').isdigit():  # Skip IP addresses
                    parts = name.split('.')
                    if len(parts) >= 2:
                        domain = '.'.join(parts[-2:])
                        domains.add(domain)

        if domains:
            # Use the most common domain
            domain_counts = {}
            for domain in domains:
                domain_counts[domain] = sum(1 for host in self.hosts.values()
                                          if domain in (host.hostname + ' ' + ' '.join(host.additional_hostnames)))
            self.network_info.domain = max(domain_counts.items(), key=lambda x: x[1])[0]

def console_file_selector():
    """Console-based file selection when whiptail is not available"""
    # Get all XML files in current directory
    xml_files = [f for f in os.listdir('.') if f.endswith('.xml')]

    if not xml_files:
        print("No XML files found in current directory")
        return None, None

    # Categorize files by type
    nmap_files = []
    openvas_files = []
    unknown_files = []

    for xml_file in xml_files:
        try:
            with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(2000).lower()  # Read first 2000 chars
                if 'nmaprun' in content or ('nmap' in content and 'scanner' in content):
                    nmap_files.append(xml_file)
                elif 'report' in content and ('openvas' in content or 'gmp' in content):
                    openvas_files.append(xml_file)
                else:
                    unknown_files.append(xml_file)
        except Exception:
            unknown_files.append(xml_file)

    print(f"\nFound {len(xml_files)} XML file(s):")
    print("-" * 40)

    selected_files = {'nmap': None, 'openvas': None}

    # Select NMAP file
    if nmap_files:
        print("\nNMAP Files:")
        for i, file in enumerate(nmap_files):
            print(f"  {i+1}. {file}")

        while True:
            try:
                choice = input(f"\nSelect NMAP file (1-{len(nmap_files)}) or Enter to skip: ").strip()
                if not choice:
                    break
                index = int(choice) - 1
                if 0 <= index < len(nmap_files):
                    selected_files['nmap'] = nmap_files[index]
                    print(f"Selected NMAP file: {selected_files['nmap']}")
                    break
                else:
                    print("Invalid selection. Please try again.")
            except ValueError:
                print("Please enter a valid number.")
    else:
        print("\nNo NMAP files detected.")

    # Select OpenVAS file
    if openvas_files:
        print("\nOpenVAS Files:")
        for i, file in enumerate(openvas_files):
            print(f"  {i+1}. {file}")

        while True:
            try:
                choice = input(f"\nSelect OpenVAS file (1-{len(openvas_files)}) or Enter to skip: ").strip()
                if not choice:
                    break
                index = int(choice) - 1
                if 0 <= index < len(openvas_files):
                    selected_files['openvas'] = openvas_files[index]
                    print(f"Selected OpenVAS file: {selected_files['openvas']}")
                    break
                else:
                    print("Invalid selection. Please try again.")
            except ValueError:
                print("Please enter a valid number.")
    else:
        print("\nNo OpenVAS files detected.")

    # Show unknown files
    if unknown_files:
        print("\nUnknown XML files (skipped):")
        for file in unknown_files:
            print(f"  - {file}")

    return selected_files['nmap'], selected_files['openvas']

def whiptail_file_selector():
    """Use whiptail to select XML files (fallback to console if not available)"""
    # Check if whiptail is available and working
    try:
        subprocess.run(['which', 'whiptail'], capture_output=True, check=True)
        # Test if whiptail actually works by running a simple command
        test_result = subprocess.run(['whiptail', '--title', 'Test', '--msgbox', 'Test', '8', '40'],
                                   capture_output=True, timeout=1)
        use_whiptail = True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        use_whiptail = False

    if not use_whiptail:
        print("Whiptail not available or not working, using console selection...")
        return console_file_selector()

    # Get all XML files in current directory
    xml_files = [f for f in os.listdir('.') if f.endswith('.xml')]

    if not xml_files:
        print("No XML files found in current directory")
        return None, None

    # Create menu items for whiptail
    nmap_files = []
    openvas_files = []

    for xml_file in xml_files:
        with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(1000).lower()  # Read first 1000 chars
            if 'nmaprun' in content or 'nmap' in content.lower():
                nmap_files.append(xml_file)
            elif 'report' in content and ('openvas' in content or 'gmp' in content):
                openvas_files.append(xml_file)

    selected_files = {'nmap': None, 'openvas': None}

    # Select NMAP file
    if nmap_files:
        menu_items = []
        for i, file in enumerate(nmap_files):
            menu_items.extend([str(i), file])

        try:
            result = subprocess.run([
                'whiptail', '--title', 'Select NMAP XML File',
                '--menu', 'Choose an NMAP XML file:',
                '15', '60', str(len(nmap_files))
            ] + menu_items, capture_output=True, text=True, check=True)

            selected_index = int(result.stdout.strip())
            selected_files['nmap'] = nmap_files[selected_index]
        except (subprocess.CalledProcessError, ValueError):
            print("NMAP file selection cancelled or failed")

    # Select OpenVAS file
    if openvas_files:
        menu_items = []
        for i, file in enumerate(openvas_files):
            menu_items.extend([str(i), file])

        try:
            result = subprocess.run([
                'whiptail', '--title', 'Select OpenVAS XML File',
                '--menu', 'Choose an OpenVAS XML file:',
                '15', '60', str(len(openvas_files))
            ] + menu_items, capture_output=True, text=True, check=True)

            selected_index = int(result.stdout.strip())
            selected_files['openvas'] = openvas_files[selected_index]
        except (subprocess.CalledProcessError, ValueError):
            print("OpenVAS file selection cancelled or failed")

    return selected_files['nmap'], selected_files['openvas']

def auto_file_selector():
    """Automatically select XML files based on content analysis"""
    xml_files = [f for f in os.listdir('.') if f.endswith('.xml')]

    if not xml_files:
        print("No XML files found in current directory")
        return None, None

    nmap_files = []
    openvas_files = []

    print(f"Found {len(xml_files)} XML file(s), analyzing...")

    for xml_file in xml_files:
        try:
            with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(2000).lower()
                if 'nmaprun' in content or ('nmap' in content and 'scanner' in content):
                    nmap_files.append(xml_file)
                    print(f"  ✓ NMAP file detected: {xml_file}")
                elif 'report' in content and ('openvas' in content or 'gmp' in content):
                    openvas_files.append(xml_file)
                    print(f"  ✓ OpenVAS file detected: {xml_file}")
        except Exception as e:
            print(f"  ⚠ Error analyzing {xml_file}: {e}")

    # Auto-select the first file of each type
    nmap_file = nmap_files[0] if nmap_files else None
    openvas_file = openvas_files[0] if openvas_files else None

    if nmap_file:
        print(f"Selected NMAP file: {nmap_file}")
    if openvas_file:
        print(f"Selected OpenVAS file: {openvas_file}")

    if not nmap_file and not openvas_file:
        print("No valid NMAP or OpenVAS files found!")

    return nmap_file, openvas_file

def format_ports(ports):
    """Format port list for display"""
    if not ports:
        return "None"

    # Filter out non-numeric ports and sort ports by number
    valid_ports = []
    invalid_ports = []

    for port in ports:
        try:
            port_num = int(port.split('/')[0])
            valid_ports.append(port)
        except ValueError:
            invalid_ports.append(port)

    # Sort valid ports by number
    sorted_valid = sorted(valid_ports, key=lambda x: int(x.split('/')[0]))

    # Combine sorted valid ports with invalid ones at the end
    all_ports = sorted_valid + invalid_ports
    return ', '.join(all_ports)

def main():
    print("Network Assessment Parser")
    print("=" * 50)

    # Select files automatically first, fallback to console if needed
    nmap_file, openvas_file = auto_file_selector()

    # If auto-selection failed, try console selection
    if not nmap_file and not openvas_file:
        print("\nAuto-selection failed, trying console selection...")
        nmap_file, openvas_file = console_file_selector()

    if not nmap_file and not openvas_file:
        print("No files selected. Exiting.")
        return

    # Parse files
    parser = XMLParser()

    if nmap_file:
        print(f"Parsing NMAP file: {nmap_file}")
        parser.parse_nmap_xml(nmap_file)

    if openvas_file:
        print(f"Parsing OpenVAS file: {openvas_file}")
        parser.parse_openvas_xml(openvas_file)

    # Detect additional network info
    parser.detect_domain_info()

    # Display results
    print("\n" + "=" * 80)
    print("NETWORK INFORMATION")
    print("=" * 80)

    print(f"Network Range: {parser.network_info.network_range or 'Not detected'}")
    print(f"Domain: {parser.network_info.domain or 'Not detected'}")
    print(f"Gateway: {parser.network_info.gateway or 'Not detected'}")
    print(f"DNS Servers: {', '.join(parser.network_info.dns_servers) or 'Not detected'}")

    print(f"\n" + "=" * 80)
    print("HOST INFORMATION")
    print("=" * 80)

    if not parser.hosts:
        print("No hosts found in selected files.")
        return

    # Sort hosts by IP
    sorted_hosts = sorted(parser.hosts.items(), key=lambda x: [int(i) for i in x[0].split('.')])

    for ip, host_info in sorted_hosts:
        print(f"\nIP Address: {ip}")
        print(f"Hostname: {host_info.hostname or 'Not identified'}")

        if host_info.additional_hostnames:
            print(f"Additional Hostnames: {', '.join(host_info.additional_hostnames)}")

        print(f"MAC Address: {host_info.mac or 'Not available'}")

        if host_info.vendor:
            print(f"Vendor: {host_info.vendor}")

        os_info = []
        if host_info.os_name:
            os_info.append(host_info.os_name)
        if host_info.os_version:
            os_info.append(f"Version: {host_info.os_version}")

        print(f"Operating System: {' - '.join(os_info) if os_info else 'Not detected'}")
        print(f"Open Ports: {format_ports(host_info.open_ports)}")
        print("-" * 60)

    print(f"\nTotal hosts found: {len(parser.hosts)}")

if __name__ == "__main__":
    main()
