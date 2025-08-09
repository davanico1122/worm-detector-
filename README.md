# Worm Detector - Network Security Monitoring Tool

![Worm Detector Banner](https://via.placeholder.com/800x200?text=Worm+Detector+Banner)

Worm Detector is a Python-based network security tool designed to detect suspicious activities such as worms and malware in local networks. This tool uses signature-based and heuristic detection approaches to identify potential threats in real-time.

## Key Features

- 🔍 **Automated Network Scanning**: 
  - Active host discovery using ARP scanning
  - Open port scanning and service identification
  - Banner grabbing for accurate identification

- 🛡️ **Multi-Layer Detection**:
  - Signature-based detection for known malware/worms
  - Behavior-based anomaly detection (flood, port scan)
  - Identification of suspicious activities on uncommon ports

- 📊 **Real-Time Monitoring**:
  - Continuous network traffic analysis
  - Instant alerting for suspicious activities
  - Centralized logging with full context

- 🔄 **Signature Management**:
  - Easy-to-update signature system
  - Flexible signature formats (hex, regex, hash)
  - Multi-file signature support

## Installation

### Prerequisites

- Python 3.9 or newer
- Root/administrator access (for packet sniffing)
- Operating system: Linux, macOS, or Windows (with WinPcap/Npcap)

### Installation Steps

1. Clone the repository:
```bash
git clone https://github.com/yourusername/worm-detector.git
cd worm-detector
```

2. Create virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate    # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. For Windows users:
   - Install [Npcap](https://npcap.com/) or WinPcap
   - Run command prompt as administrator

## Usage

### Basic Network Scanning

```bash
sudo python worm_detector.py scan
```

This command will:
1. Scan the local network (default: 192.168.1.0/24)
2. Detect active hosts
3. Scan common open ports
4. Display results in table format

Additional options:
- `-n/--network`: Specify network (example: 192.168.0.0/24)
- `-p/--ports`: Specific ports to scan (example: 22,80,443)

Example:
```bash
sudo python worm_detector.py scan -n 10.0.0.0/24 -p 21,22,80,443
```

### Real-Time Monitoring

```bash
sudo python worm_detector.py monitor
```

This feature will:
1. Monitor network traffic in real-time
2. Detect suspicious activities
3. Generate immediate alerts in CLI
4. Log all detections to detections.log

Additional options:
- `-i/--interface`: Specify network interface (example: eth0, en0)

Example:
```bash
sudo python worm_detector.py monitor -i eth0
```

### Signature Updates

```bash
python worm_detector.py update
```

Note: This feature is currently a placeholder and requires further implementation for integration with external signature feeds.

## Detection Methods

### 1. Signature-Based Detection
The tool uses a signature database to detect known malware/worms. Signatures are stored in JSON format in the `signatures/` directory.

Signature format:
```json
{
  "name": "Malware Name",
  "pattern": "Detection pattern (hex, regex, or hash)",
  "type": "hex|regex|hash",
  "threat": "Threat description",
  "severity": "critical|high|medium|low"
}
```

Detection examples:
- Hex pattern matching in payload
- Regular expression matching
- MD5 hash verification of payload

### 2. Anomaly-Based Detection
Behavior-based detection uses heuristic approaches to identify:
- **Network Floods**: Abnormal packet volume from a single source
- **Port Scans**: Attempts to access many ports in a short time
- **Suspicious Connections**: Connections to uncommon ports or known malware ports
- **Unusual Traffic Patterns**: Abnormal communication patterns

Configurable thresholds:
- Flood threshold (default: 100 packets/10 seconds)
- Port scan threshold (default: 15 different ports)
- Unusual port connection threshold (default: 5 connections)

## Project Structure

```
worm-detector/
├── worm_detector.py        # Main CLI utility
├── modules/                # Detection modules
│   ├── __init__.py         # Package initialization
│   ├── network_scan.py     # Host & port scanning
│   ├── signature_check.py  # Signature-based detection
│   └── anomaly_detect.py   # Behavior-based anomaly detection
├── signatures/             # Signature database
│   └── known_signatures.json
├── detections.log          # Detection results log (created at runtime)
├── README.md               # Project documentation
└── requirements.txt        # Dependencies
```

## Logging and Reporting

All detections are logged in the `detections.log` file with the format:
```
[Timestamp] [Level] - Message
```

Example log entries:
```
2023-10-15 14:30:25,123 - WARNING - SIGNATURE: SQL_Slammer | Worm
2023-10-15 14:31:45,678 - WARNING - FLOOD: 192.168.1.15 sent 250 packets in 10s
2023-10-15 14:32:10,987 - WARNING - PORT SCAN: 192.168.1.23 scanned 25 ports
2023-10-15 14:33:05,456 - WARNING - SUSPICIOUS PORT: 192.168.1.42 accessed BackOrifice port (31337)
```

## Customization

### Adding New Signatures
1. Create a new JSON file in the `signatures/` directory
2. Add signatures in the appropriate format
3. Restart monitoring to load new signatures

Example signature:
```json
{
  "name": "New_Malware_Threat",
  "pattern": "\\x90\\x90\\x90\\x90\\x90",
  "type": "hex",
  "threat": "Newly discovered malware threat",
  "severity": "high"
}
```

### Adjusting Detection Thresholds
Anomaly detection thresholds can be adjusted in `modules/anomaly_detect.py`:
```python
class AnomalyDetector:
    def __init__(self, 
                 flood_threshold: int = 150,       # Change flood threshold value
                 port_scan_threshold: int = 20,    # Change port scan threshold
                 anomaly_window: int = 15,          # Change detection time window
                 connection_threshold: int = 60):   # Change connection threshold
```

## Limitations and Security Notes

1. **Technical Limitations**:
   - Signature-based detection is effective only for known malware
   - Anomaly detection may produce false positives in dynamic network environments
   - Performance may be affected in high-speed networks (>1Gbps)

2. **Security Considerations**:
   - This tool is for detection and monitoring purposes only
   - Does not contain exploitation or malware spreading functions
   - Requires administrator privileges for sniffing operations
   - Usage must comply with local network policies and applicable regulations

3. **Platform Limitations**:
   - Windows requires Npcap/WinPcap installation
   - Some systems may need temporary firewall disabling for scanning

## Contributing

Contributions to this project are highly welcome! Here's how to contribute:

1. Fork the repository
2. Create a new feature branch (`git checkout -b new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin new-feature`)
5. Create a pull request

Areas needing contribution:
- Implementation of automatic signature updates
- Addition of protocol-specific detection (DNS, HTTP, etc.)
- Integration with threat intelligence feeds
- UI and reporting improvements

## Troubleshooting

### Common Issues and Solutions

**Issue: Cannot capture packets on Windows**
- Solution:
  1. Ensure Npcap/WinPcap is installed
  2. Run as administrator
  3. Try different interface with `-i` option

**Issue: Signatures not detected**
- Solution:
  1. Check signature file format
  2. Ensure signature files are in correct directory
  3. Verify signature patterns match traffic

**Issue: Slow performance during monitoring**
- Solution:
  1. Limit monitoring interface with `-i` option
  2. Reduce load with BPF filters
  3. Increase anomaly detection thresholds

**Issue: No scan results**
- Solution:
  1. Ensure device is on correct network
  2. Check firewall policies
  3. Try smaller network range (e.g., /28)

## Development Roadmap

- [ ] Integration with threat intelligence feeds
- [ ] Implementation of automatic signature updates
- [ ] Addition of web-based GUI
- [ ] Machine learning-based detection
- [ ] Automatic response system (e.g., auto-blocking)
- [ ] Distributed monitoring support

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

This tool is intended solely for security and educational purposes. Users are fully responsible for using this tool in accordance with applicable laws and regulations. The developers are not responsible for misuse or damage caused by the use of this tool.

---

With Worm Detector, you can proactively monitor your network and detect threats before they cause damage. For questions or issues, please open an issue in the GitHub repository.
