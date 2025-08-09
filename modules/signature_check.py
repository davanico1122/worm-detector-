import json
import os
import re
import hashlib
import scapy.all as scapy
from typing import List, Dict

class SignatureDetector:
    def __init__(self, signature_dir: str = "signatures"):
        self.signature_dir = signature_dir
        self.signatures = self.load_signatures()
    
    def load_signatures(self) -> List[Dict]:
        all_signatures = []
        for file in os.listdir(self.signature_dir):
            if file.endswith(".json"):
                path = os.path.join(self.signature_dir, file)
                try:
                    with open(path, 'r') as f:
                        all_signatures += json.load(f)
                except Exception as e:
                    print(f"Error loading {path}: {e}")
        return all_signatures
    
    def detect(self, packet: scapy.Packet) -> List[str]:
        alerts = []
        
        if not self.signatures:
            return alerts
        
        # Check packet payload
        payload = self.get_payload(packet)
        if not payload:
            return alerts
        
        for sig in self.signatures:
            if sig['type'] == "hex":
                hex_pattern = bytes.fromhex(sig['pattern'].replace(" ", ""))
                if hex_pattern in payload:
                    alerts.append(f"SIGNATURE: {sig['name']} | {sig['threat']}")
            
            elif sig['type'] == "regex":
                if re.search(sig['pattern'], payload.decode('utf-8', 'ignore')):
                    alerts.append(f"SIGNATURE: {sig['name']} | {sig['threat']}")
            
            elif sig['type'] == "hash":
                payload_hash = hashlib.md5(payload).hexdigest()
                if payload_hash == sig['pattern']:
                    alerts.append(f"HASH MATCH: {sig['name']} | {sig['threat']}")
        
        return alerts
    
    def get_payload(self, packet) -> bytes:
        for layer in (scapy.Raw, scapy.DNS, scapy.HTTP):
            if packet.haslayer(layer):
                return bytes(packet[layer])
        return b""

class SignatureUpdater:
    def __init__(self, repo_url: str = "https://example.com/signatures/"):
        self.repo_url = repo_url
    
    def update_signatures(self) -> int:
        # In a real implementation, this would download from repo
        # Placeholder for actual update logic
        return 0  # Return count of updated signatures
