#!/usr/bin/env python3
import argparse
import logging
import sys
from datetime import datetime
from modules import network_scan, signature_check, anomaly_detect
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import scapy.all as scapy
import threading

console = Console()
logging.basicConfig(
    filename='detections.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def display_banner():
    banner = r"""
██     ██ ███████ ██████  ███    ███ ██████  ███████ ██████  ████████ 
██     ██ ██      ██   ██ ████  ████ ██   ██ ██      ██   ██    ██    
██  █  ██ █████   ██████  ██ ████ ██ ██   ██ █████   ██████     ██    
██ ███ ██ ██      ██   ██ ██  ██  ██ ██   ██ ██      ██   ██    ██    
 ███ ███  ███████ ██   ██ ██      ██ ██████  ███████ ██   ██    ██    
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print(f"[bold yellow]Worm Detector v1.0 | Active Monitoring System[/bold yellow]\n")

def scan_command(args):
    console.print("[bold green]🚀 Starting network scan...[/bold green]")
    network = args.network if args.network else "192.168.1.0/24"
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning network...", total=100)
        active_hosts = network_scan.discover_hosts(network, progress, task)
    
    if not active_hosts:
        console.print("[bold red]No active hosts found![/bold red]")
        return
    
    table = Table(title="Active Hosts")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="magenta")
    table.add_column("Hostname", style="green")
    
    for host in active_hosts:
        table.add_row(host['ip'], host['mac'], host['hostname'])
    
    console.print(table)
    
    for host in active_hosts:
        if args.ports:
            ports = [int(p) for p in args.ports.split(",")]
        else:
            ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389]
        
        open_ports = network_scan.scan_ports(host['ip'], ports)
        
        if open_ports:
            port_table = Table(title=f"Open Ports on {host['ip']}")
            port_table.add_column("Port", style="cyan")
            port_table.add_column("Service", style="magenta")
            port_table.add_column("Status", style="green")
            
            for port, service in open_ports.items():
                port_table.add_row(str(port), service, "[bold green]OPEN[/bold green]")
            
            console.print(port_table)

def monitor_command(args):
    console.print("[bold green]👁️ Starting real-time monitoring... Press Ctrl+C to stop[/bold green]")
    interface = args.interface if args.interface else scapy.conf.iface
    
    # Inisialisasi detektor
    sig_detector = signature_check.SignatureDetector()
    anomaly_detector = anomaly_detect.AnomalyDetector()
    
    # Thread untuk deteksi anomali
    def anomaly_thread():
        while True:
            anomalies = anomaly_detector.check_anomalies()
            for anomaly in anomalies:
                alert = f"ANOMALY DETECTED: {anomaly}"
                console.print(f"[bold red]{alert}[/bold red]")
                logging.warning(alert)
            threading.Event().wait(10)
    
    threading.Thread(target=anomaly_thread, daemon=True).start()
    
    # Callback untuk packet capture
    def packet_callback(packet):
        signature_alerts = sig_detector.detect(packet)
        for alert in signature_alerts:
            console.print(f"[bold yellow]{alert}[/bold yellow]")
            logging.warning(alert)
        
        anomaly_detector.add_packet(packet)
    
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Monitoring stopped![/bold yellow]")

def update_command(args):
    console.print("[bold green]🔄 Updating malware signatures...[/bold green]")
    try:
        updater = signature_check.SignatureUpdater()
        count = updater.update_signatures()
        console.print(f"[bold green]Successfully updated {count} signatures![/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error updating signatures: {e}[/bold red]")

def main():
    display_banner()
    
    parser = argparse.ArgumentParser(
        description="Worm Detector - Network Security Monitoring Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    subparsers = parser.add_subparsers(title="commands", dest="command")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan network for hosts and ports")
    scan_parser.add_argument("-n", "--network", help="Network to scan (e.g., 192.168.1.0/24)")
    scan_parser.add_argument("-p", "--ports", help="Ports to scan (comma separated)")
    
    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Start real-time monitoring")
    monitor_parser.add_argument("-i", "--interface", help="Network interface to monitor")
    
    # Update command
    update_parser = subparsers.add_parser("update", help="Update malware signatures")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == "scan":
            scan_command(args)
        elif args.command == "monitor":
            monitor_command(args)
        elif args.command == "update":
            update_command(args)
    except PermissionError:
        console.print("[bold red]Error: Permission denied! Try running with sudo/Admin privileges[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Critical error: {e}[/bold red]")
        logging.exception("Critical error occurred")

if __name__ == "__main__":
    main()
