from collections import defaultdict, deque
import time
import scapy.all as scapy
from typing import List

class AnomalyDetector:
    def __init__(self, 
                 flood_threshold: int = 100,
                 port_scan_threshold: int = 15,
                 anomaly_window: int = 10):
        self.flood_threshold = flood_threshold
        self.port_scan_threshold = port_scan_threshold
        self.anomaly_window = anomaly_window
        
        # Data structures for anomaly detection
        self.packet_counts = defaultdict(int)
        self.port_access = defaultdict(lambda: defaultdict(int))
        self.connections = deque(maxlen=1000)
        self.last_reset = time.time()
    
    def add_packet(self, packet: scapy.Packet):
        current_time = time.time()
        
        # Reset counters periodically
        if current_time - self.last_reset > self.anomaly_window:
            self.packet_counts.clear()
            self.port_access.clear()
            self.last_reset = current_time
        
        if not packet.haslayer(scapy.IP):
            return
        
        src_ip = packet[scapy.IP].src
        
        # Flood detection
        self.packet_counts[src_ip] += 1
        
        # Port scan detection
        if packet.haslayer(scapy.TCP):
            dst_port = packet[scapy.TCP].dport
            self.port_access[src_ip][dst_port] += 1
        
        # Connection tracking
        self.connections.append({
            'time': current_time,
            'src_ip': src_ip,
            'dst_ip': packet[scapy.IP].dst,
            'proto': packet[scapy.IP].proto
        })
    
    def check_anomalies(self) -> List[str]:
        anomalies = []
        current_time = time.time()
        
        # Flood detection
        for ip, count in self.packet_counts.items():
            if count > self.flood_threshold:
                anomalies.append(f"FLOOD: {ip} sent {count} packets in {self.anomaly_window}s")
        
        # Port scan detection
        for ip, ports in self.port_access.items():
            if len(ports) > self.port_scan_threshold:
                anomalies.append(f"PORT SCAN: {ip} scanned {len(ports)} ports")
        
        # Suspicious connection pattern detection
        unusual_ports = defaultdict(int)
        for conn in self.connections:
            if conn['proto'] == 6:  # TCP
                if conn.get('dport', 0) > 1024:  # Non-standard port
                    unusual_ports[conn['src_ip']] += 1
        
        for ip, count in unusual_ports.items():
            if count > 5:
                anomalies.append(f"UNUSUAL PORTS: {ip} connected to {count} non-standard ports")
        
        return anomalies
