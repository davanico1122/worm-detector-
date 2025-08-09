import scapy.all as scapy
import socket
import ipaddress
from rich.progress import Progress, TaskID
from typing import List, Dict, Optional

def discover_hosts(network: str, progress: Progress, task: TaskID) -> List[Dict[str, str]]:
    active_hosts = []
    hosts = list(ipaddress.ip_network(network).hosts())
    
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
            except socket.herror:
                hostname = "Unknown"
            
            active_hosts.append({
                'ip': ip_str,
                'mac': mac,
                'hostname': hostname
            })
    
    return active_hosts

def scan_ports(target: str, ports: List[int]) -> Dict[int, str]:
    open_ports = {}
    
    for port in ports:
        syn_packet = scapy.IP(dst=target)/scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(syn_packet, timeout=1, verbose=False)
        
        if response and response.haslayer(scapy.TCP):
            if response[scapy.TCP].flags == 0x12:  # SYN-ACK
                # Get service name
                try:
                    service = socket.getservbyport(port, 'tcp')
                except OSError:
                    service = "unknown"
                open_ports[port] = service
                # Send RST to close connection
                scapy.send(scapy.IP(dst=target)/scapy.TCP(dport=port, flags="R"), verbose=False)
    
    return open_ports
