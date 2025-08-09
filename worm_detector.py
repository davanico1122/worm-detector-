#!/usr/bin/env python3
import argparse
import logging
import sys
import os
import time
from datetime import datetime
from modules import discover_hosts, scan_ports, SignatureDetector, SignatureUpdater, AnomalyDetector
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import scapy.all as scapy
import threading

console = Console()
logging.basicConfig(
    filename='detections.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'  # Append mode
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
    console.print(f"[bold green]Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold green]")

def scan_command(args):
    console.print("[bold green]🚀 Starting network scan...[/bold green]")
    network = args.network if args.network else "192.168.1.0/24"
    
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning network...", total=100)
            active_hosts = discover_hosts(network, progress, task)
        
        if not active_hosts:
            console.print("[bold red]No active hosts found![/bold red]")
            return
        
        table = Table(title="Active Hosts", show_header=True, header_style="bold magenta")
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="magenta")
        table.add_column("Hostname", style="green")
        table.add_column("Vendor", style="yellow")
        
        for host in active_hosts:
            table.add_row(host['ip'], host['mac'], host.get('hostname', 'Unknown'), host.get('vendor', 'Unknown'))
        
        console.print(table)
        
        if args.ports:
            ports = [int(p) for p in args.ports.split(",")]
        else:
            ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
        
        for host in active_hosts:
            open_ports = scan_ports(host['ip'], ports)
            
            if open_ports:
                port_table = Table(title=f"Open Ports on {host['ip']}", show_header=True, header_style="bold blue")
                port_table.add_column("Port", style="cyan")
                port_table.add_column("Service", style="magenta")
                port_table.add_column("Status", style="green")
                port_table.add_column("Banner", style="yellow")
                
                for port, info in open_ports.items():
                    service = info.get('service', 'unknown')
                    banner = info.get('banner', '')[:30] + '...' if info.get('banner') else ''
                    port_table.add_row(str(port), service, "[bold green]OPEN[/bold green]", banner)
                
                console.print(port_table)
    except Exception as e:
        console.print(f"[bold red]Scan error: {e}[/bold red]")
        logging.error(f"Scan error: {e}")

def monitor_command(args):
    console.print("[bold green]👁️ Starting real-time monitoring... Press Ctrl+C to stop[/bold green]")
    interface = args.interface if args.interface else scapy.conf.iface
    
    # Initialize detectors
    sig_detector = SignatureDetector()
    anomaly_detector = AnomalyDetector()
    
    # Thread for periodic anomaly checks
    def anomaly_thread():
        while True:
            try:
                anomalies = anomaly_detector.check_anomalies()
                for anomaly in anomalies:
                    alert = f"{anomaly}"
                    console.print(f"[bold red]{alert}[/bold red]")
                    logging.warning(alert)
            except Exception as e:
                logging.error(f"Anomaly detection error: {e}")
            time.sleep(10)
    
    threading.Thread(target=anomaly_thread, daemon=True).start()
    
    # Packet callback
    def packet_callback(packet):
        try:
            # Signature detection
            signature_alerts = sig_detector.detect(packet)
            for alert in signature_alerts:
                console.print(f"[bold yellow]{alert}[/bold yellow]")
                logging.warning(alert)
            
            # Add to anomaly detector
            anomaly_alert = anomaly_detector.add_packet(packet)
            if anomaly_alert:
                console.print(f"[bold red]{anomaly_alert}[/bold red]")
                logging.warning(anomaly_alert)
        except Exception as e:
            logging.error(f"Packet processing error: {e}")
    
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Monitoring stopped![/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Monitoring error: {e}[/bold red]")
        logging.error(f"Monitoring error: {e}")

def update_command(args):
    console.print("[bold green]🔄 Updating malware signatures...[/bold green]")
    try:
        updater = SignatureUpdater()
        count = updater.update_signatures()
        console.print(f"[bold green]Successfully updated {count} signatures![/bold green]")
        logging.info(f"Signatures updated: {count} new signatures")
    except Exception as e:
        console.print(f"[bold red]Error updating signatures: {e}[/bold red]")
        logging.error(f"Signature update error: {e}")

def main():
    display_banner()
    
    parser = argparse.ArgumentParser(
        description="Worm Detector - Network Security Monitoring Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    subparsers = parser.add_subparsers(title="commands", dest="command", required=True)
    
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
    
    try:
        if args.command == "scan":
            scan_command(args)
        elif args.command == "monitor":
            monitor_command(args)
        elif args.command == "update":
            update_command(args)
    except PermissionError:
        console.print("[bold red]Error: Permission denied! Try running with sudo/Admin privileges[/bold red]")
        logging.error("Permission denied - requires admin privileges")
    except Exception as e:
        console.print(f"[bold red]Critical error: {e}[/bold red]")
        logging.exception("Critical error occurred")

if __name__ == "__main__":
    main()
