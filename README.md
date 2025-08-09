# 🛡️ Worm Detector

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)](https://github.com/yourusername/worm-detector)

A comprehensive network security tool for detecting worms, malware, and suspicious network activities in real-time. Built with Python and designed for security professionals, network administrators, and researchers.

## ✨ Features

### 🔍 Network Discovery & Scanning
- **ARP-based Host Discovery**: Identify active hosts on network segments
- **TCP SYN Port Scanning**: Fast and stealthy port enumeration
- **Service Detection**: Identify running services and versions
- **Customizable Network Ranges**: Flexible subnet scanning capabilities

### 🦠 Malware Detection
- **Signature-based Detection**: Extensible hex pattern and regex matching
- **Payload Hash Verification**: Known malware hash identification
- **Real-time Pattern Matching**: Live traffic analysis for malicious signatures
- **Multi-protocol Support**: HTTP, TCP, UDP payload inspection

### 📊 Network Anomaly Detection
- **Flood Detection**: Identify network flood attacks (SYN, UDP, ICMP)
- **Port Scan Detection**: Recognize reconnaissance activities
- **Connection Pattern Analysis**: Detect unusual network behaviors
- **Threshold-based Alerting**: Configurable detection sensitivity

### 🖥️ Real-time Monitoring
- **Live Packet Capture**: Continuous network traffic analysis
- **Parallel Processing**: Multi-threaded detection systems
- **Rich CLI Interface**: Beautiful terminal output with progress bars
- **Instant Alerts**: Real-time threat notifications

### 📝 Logging & Reporting
- **Comprehensive Logging**: Detailed detection logs with timestamps
- **Alert Context**: Full packet details and detection reasoning
- **Persistent Storage**: Long-term log retention and analysis
- **Export Capabilities**: Multiple output formats for integration

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- Administrative/root privileges (for packet capture)
- Network interface access

### Installation

```bash
# Clone the repository
git clone https://github.com/davanico1122/worm-detector-.git
cd worm-detector

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x worm_detector.py
```

### Basic Usage

```bash
# Scan local network for hosts and vulnerabilities
sudo python worm_detector.py scan

# Monitor network traffic for threats
sudo python worm_detector.py monitor

# Update malware signatures
python worm_detector.py update
```

## 📖 Detailed Usage

### Network Scanning

```bash
# Scan specific network range
sudo python worm_detector.py scan --network 192.168.1.0/24

# Scan specific ports
sudo python worm_detector.py scan --ports 22,80,443,8080

# Comprehensive scan with custom range and ports
sudo python worm_detector.py scan -n 10.0.0.0/16 -p 1-1000
```

### Real-time Monitoring

```bash
# Monitor default interface
sudo python worm_detector.py monitor

# Monitor specific interface
sudo python worm_detector.py monitor --interface eth0

# Monitor with verbose output
sudo python worm_detector.py monitor -v
```

### Signature Management

```bash
# Update signatures from remote source
python worm_detector.py update

# Validate signature database
python worm_detector.py update --validate

# Show signature statistics
python worm_detector.py update --stats
```

## ⚙️ Configuration

### Command Line Options

#### Scan Command
| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--network` | `-n` | Network range to scan | `192.168.1.0/24` |
| `--ports` | `-p` | Ports to scan | `22,80,443` or `1-1000` |
| `--timeout` | `-t` | Connection timeout | `5` (seconds) |
| `--threads` | `-th` | Number of threads | `50` |

#### Monitor Command
| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--interface` | `-i` | Network interface | `eth0`, `wlan0` |
| `--verbose` | `-v` | Verbose output | Flag |
| `--filter` | `-f` | BPF filter | `tcp port 80` |
| `--duration` | `-d` | Monitor duration | `3600` (seconds) |

#### Update Command
| Option | Short | Description |
|--------|-------|-------------|
| `--validate` | | Validate signatures |
| `--stats` | | Show statistics |
| `--source` | `-s` | Signature source URL |

### Configuration File

Create `config.json` for persistent settings:

```json
{
    "scanning": {
        "default_network": "192.168.1.0/24",
        "default_ports": [22, 80, 443, 8080],
        "timeout": 5,
        "threads": 50
    },
    "monitoring": {
        "default_interface": "eth0",
        "capture_filter": "",
        "log_level": "INFO"
    },
    "detection": {
        "signature_path": "./signatures/",
        "enable_heuristics": true,
        "flood_threshold": 100,
        "scan_threshold": 10
    }
}
```

## 🏗️ Architecture

### Core Components

```
worm-detector/
├── worm_detector.py
├── modules/
│   ├── network_scan.py
│   ├── signature_check.py
│   ├── anomaly_detect.py
│   └── __init__.py
├── signatures/
│   └── known_signatures.json
├── detections.log
├── README.md
└── requirements.txt
```

### Detection Engines

1. **Signature Engine**: Pattern matching for known threats
2. **Anomaly Engine**: Statistical analysis for unknown threats
3. **Heuristic Engine**: Behavioral analysis and AI-based detection
4. **Correlation Engine**: Multi-vector attack detection

### Extensibility

The tool is designed with modularity in mind:

```python
# Adding custom detectors
class CustomDetector(BaseDetector):
    def analyze(self, packet):
        # Custom detection logic
        return detection_result

# Adding new signatures
{
    "name": "Custom Malware",
    "type": "hex",
    "pattern": "deadbeef",
    "severity": "high"
}
```

## 🛡️ Security & Ethics

### Defensive Purpose Only
- **Detection Only**: No offensive capabilities included
- **No Exploitation**: Does not attempt to exploit vulnerabilities
- **Passive Analysis**: Read-only network analysis
- **Legal Compliance**: Designed for authorized network monitoring

### Privacy & Legal Considerations
- **Authorization Required**: Only use on networks you own or have permission to monitor
- **Data Protection**: Sensitive data is not logged or transmitted
- **Compliance**: Adheres to responsible disclosure practices
- **Documentation**: Maintains audit trail of all activities

## 🔧 Development

### Requirements
```txt
scapy>=2.5.0
rich>=13.0.0
python>=3.9
```

### Testing
```bash
# Run unit tests
python -m pytest tests/

# Run integration tests
python -m pytest tests/integration/

# Generate coverage report
coverage run -m pytest && coverage report
```

### Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📊 Detection Examples

### Malware Signatures
- **Known Worm Patterns**: Conficker, Stuxnet, WannaCry signatures
- **Trojan Communications**: C&C server communications
- **Backdoor Traffic**: Remote access tool detection
- **Cryptocurrency Miners**: Mining pool communications

### Network Anomalies
- **SYN Flood Attacks**: High-volume connection attempts
- **Port Scanning**: Sequential or random port probing
- **DNS Tunneling**: Suspicious DNS query patterns
- **Data Exfiltration**: Unusual outbound traffic volumes

### Advanced Threats
- **APT Indicators**: Advanced persistent threat signatures
- **Zero-day Exploits**: Heuristic-based unknown threat detection
- **Lateral Movement**: Internal network reconnaissance
- **Living off the Land**: Abuse of legitimate tools

## 📋 System Requirements

### Minimum Requirements
- **OS**: Linux (Ubuntu 18.04+), macOS (10.14+), Windows 10
- **Python**: 3.7+
- **RAM**: 512 MB available
- **Storage**: 100 MB free space
- **Network**: Administrative privileges required

### Recommended Requirements
- **OS**: Linux (Ubuntu 20.04+), macOS (11+), Windows 11
- **Python**: 3.9+
- **RAM**: 2 GB available
- **Storage**: 1 GB free space
- **CPU**: Multi-core processor for better performance

## 🆘 Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Solution: Run with sudo/administrator privileges
sudo python worm_detector.py monitor
```

**Interface Not Found**
```bash
# List available interfaces
ip link show  # Linux
ifconfig -l   # macOS
```

**Signature Update Fails**
```bash
# Check internet connection and proxy settings
python worm_detector.py update --verbose
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [API Documentation](docs/api.md)
- [Signature Development](docs/signatures.md)
- [Troubleshooting Guide](docs/troubleshooting.md)

## 🤝 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/worm-detector/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/worm-detector/discussions)
- **Security**: security@yourdomain.com
- **Documentation**: [Wiki](https://github.com/yourusername/worm-detector/wiki)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Scapy Team**: For the excellent packet manipulation library
- **Security Community**: For threat intelligence and signatures
- **Contributors**: All developers who have contributed to this project
- **Testers**: Security professionals who helped validate the tool

---

**⚠️ Disclaimer**: This tool is intended for educational and defensive security purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this software.
