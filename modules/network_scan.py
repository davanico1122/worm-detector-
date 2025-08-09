import scapy.all as scapy
import socket
import ipaddress
import re
from rich.progress import Progress, TaskID
from typing import List, Dict, Optional

def discover_hosts(network: str, progress: Progress, task: TaskID) -> List[Dict[str, str]]:
    active_hosts = []
    hosts = list(ipaddress.ip_network(network).hosts())
    
    # MAC vendor database (simplified)
    mac_vendors = {
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "00:1C:42": "Apple",
        "00:1D:4F": "Apple",
        "A4:83:E7": "Apple",
        "DC:A6:32": "Apple",
        "B8:27:EB": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "28:16:AD": "Google",
        "3C:5A:B4": "Google",
        "F4:F5:24": "Google"
    }
    
    for i, ip in enumerate(hosts):
        ip_str = str(ip)
        progress.update(task, advance=100/len(hosts), description=f"Scanning {ip_str}")
        
        arp_packet = scapy.ARP(pdst=ip_str)
        ether_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_packet/arp_packet
        
        answered = scapy.srp(packet, timeout=1, verbose=False)[0]
        
        if answered:
            mac = answered[0][1].hwsrc
            try:
                hostname = socket.gethostbyaddr(ip_str)[0]
            except (socket.herror, socket.gaierror):
                hostname = "Unknown"
            
            # Find vendor from MAC
            vendor = "Unknown"
            for prefix, vendor_name in mac_vendors.items():
                if mac.lower().startswith(prefix.lower()):
                    vendor = vendor_name
                    break
            
            active_hosts.append({
                'ip': ip_str,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor
            })
    
    return active_hosts

def scan_ports(target: str, ports: List[int]) -> Dict[int, Dict[str, str]]:
    open_ports = {}
    
    for port in ports:
        try:
            # TCP SYN scan
            syn_packet = scapy.IP(dst=target)/scapy.TCP(dport=port, flags="S")
            response = scapy.sr1(syn_packet, timeout=1, verbose=False)
            
            if response and response.haslayer(scapy.TCP):
                if response[scapy.TCP].flags == 0x12:  # SYN-ACK
                    # Get service name
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except OSError:
                        service = "unknown"
                    
                    # Attempt banner grabbing
                    banner = ""
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(2)
                            s.connect((target, port))
                            banner = s.recv(1024).decode('utf-8', 'ignore').strip()
                            # Clean banner
                            banner = re.sub(r'[\x00-\x1F\x7F-\xFF]', '', banner)
                    except:
                        banner = ""
                    
                    open_ports[port] = {
                        'service': service,
                        'banner': banner
                    }
                    
                    # Send RST to close connection
                    scapy.send(scapy.IP(dst=target)/scapy.TCP(dport=port, flags="R"), verbose=False)
        except Exception as e:
            continue
    
    return open_ports
