#!/usr/bin/env python3
"""
Python Network Toolkit - A cool CLI for network scanning and analysis
"""

import socket
import sys
import argparse
from datetime import datetime
import threading
from queue import Queue
import os
import time
from typing import List, Tuple, Optional
import json

# Optional: Install rich for enhanced UI: pip install rich
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

lock = threading.Lock()
console = Console() if RICH_AVAILABLE else None

# ================= VERSION =================
VERSION = "1.0.0"
AUTHOR = "Moexblade"

# ================= BANNER =================
def show_banner():
    """Display a cool ASCII banner"""
    banner = r"""
╔══════════════════════════════════════════════════════════╗
║  ██████╗ ██╗   ██╗████████╗██╗  ██╗ ██████╗ ███╗   ██╗   ║
║  ██╔══██╗╚██╗ ██╔╝╚══██╔══╝██║  ██║██╔═══██╗████╗  ██║   ║
║  ██████╔╝ ╚████╔╝    ██║   ███████║██║   ██║██╔██╗ ██║   ║
║  ██╔═══╝   ╚██╔╝     ██║   ██╔══██║██║   ██║██║╚██╗██║   ║
║  ██║        ██║      ██║   ██║  ██║╚██████╔╝██║ ╚████║   ║
║  ╚═╝        ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ║
║                                                          ║    
║                      Port Scanner                        ║   
╚══════════════════════════════════════════════════════════╝
    """
    print(banner)
    print(f"Version: {VERSION} | Author: {AUTHOR}\n")

# ================= COLOR SUPPORT =================
class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ================= NETWORK SCANNER =================
class NetworkScanner:
    def __init__(self, output_format: str = "table", verbose: bool = False):
        self.output_format = output_format
        self.verbose = verbose
        self.results = []
        
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def ping_ip(self, ip: str) -> bool:
        """Ping a single IP address"""
        param = "-n 1 -w 1000" if os.name == "nt" else "-c 1 -W 1"
        command = f"ping {param} {ip} > {'nul' if os.name == 'nt' else '/dev/null'} 2>&1"
        return os.system(command) == 0
    
    def scan_subnet(self, subnet: str, start: int = 1, end: int = 254, 
                   max_threads: int = 100, timeout: float = 1.0) -> List[str]:
        """Scan a subnet for active IPs"""
        active_ips = []
        
        if not (1 <= start <= 254 and 1 <= end <= 254 and start <= end):
            print(f"{Colors.RED}Error: Invalid IP range{Colors.END}")
            return []
        
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"[cyan]Scanning {subnet}.{start}-{end}...", total=end-start+1)
                
                def worker(ip: str):
                    if self.ping_ip(ip):
                        with lock:
                            active_ips.append(ip)
                            if self.verbose:
                                console.print(f"[green]✓ {ip}")
                    progress.update(task, advance=1)
                
                threads = []
                for i in range(start, end + 1):
                    ip = f"{subnet}.{i}"
                    thread = threading.Thread(target=worker, args=(ip,))
                    threads.append(thread)
                    thread.start()
                    
                    if len(threads) >= max_threads:
                        for t in threads:
                            t.join()
                        threads = []
                
                for t in threads:
                    t.join()
        else:
            print(f"{Colors.CYAN}Scanning subnet {subnet}.{start} → {subnet}.{end}{Colors.END}")
            print(f"Started at: {datetime.now()}")
            print("-" * 60)
            
            def worker(ip: str):
                if self.ping_ip(ip):
                    with lock:
                        active_ips.append(ip)
                        print(f"{Colors.GREEN}[ACTIVE] {ip}{Colors.END}")
            
            threads = []
            for i in range(start, end + 1):
                ip = f"{subnet}.{i}"
                thread = threading.Thread(target=worker, args=(ip,))
                threads.append(thread)
                thread.start()
                
                if len(threads) >= max_threads:
                    for t in threads:
                        t.join()
                    threads = []
            
            for t in threads:
                t.join()
        
        return sorted(active_ips, key=lambda x: list(map(int, x.split('.'))))
    
    def scan_ports(self, target: str, start_port: int = 1, end_port: int = 1024,
                  max_threads: int = 100, banner_grab: bool = True) -> List[Tuple[int, str, str]]:
        """Scan ports on a target host"""
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"{Colors.RED}Error: Cannot resolve hostname{Colors.END}")
            return []
        
        open_ports = []
        queue = Queue()
        
        # Fill queue with ports to scan
        for port in range(start_port, end_port + 1):
            queue.put(port)
        
        if RICH_AVAILABLE:
            console.print(f"[bold cyan]Target:[/bold cyan] {target} ({target_ip})")
            console.print(f"[bold cyan]Port Range:[/bold cyan] {start_port}-{end_port}")
            console.print(f"[bold cyan]Started:[/bold cyan] {datetime.now()}")
            console.print("-" * 60)
        
        def worker():
            while not queue.empty():
                port = queue.get()
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((target_ip, port))
                    
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        
                        banner = ""
                        if banner_grab:
                            try:
                                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                                banner = sock.recv(1024).decode(errors="ignore").strip()
                                if len(banner) > 50:
                                    banner = banner[:50] + "..."
                            except:
                                banner = "no banner"
                        
                        with lock:
                            open_ports.append((port, service, banner))
                            if RICH_AVAILABLE:
                                console.print(f"[green][✓] Port {port:5} ({service:15}) - {banner}[/green]")
                            else:
                                print(f"{Colors.GREEN}[OPEN] Port {port} ({service}) - {banner}{Colors.END}")
                    
                    sock.close()
                except:
                    pass
                finally:
                    queue.task_done()
        
        # Create and start worker threads
        threads = []
        for _ in range(min(max_threads, end_port - start_port + 1)):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all tasks to complete
        queue.join()
        
        return sorted(open_ports, key=lambda x: x[0])
    
    def get_local_ip(self) -> dict:
        """Get local network information"""
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except:
            local_ip = "127.0.0.1"
        
        # Try to get public IP
        public_ip = "N/A"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                interface_ip = s.getsockname()[0]
        except:
            interface_ip = local_ip
        
        return {
            "hostname": hostname,
            "local_ip": local_ip,
            "interface_ip": interface_ip,
            "timestamp": datetime.now().isoformat()
        }
    
    def display_results(self, scan_type: str, data: any):
        """Display results in various formats"""
        if self.output_format == "json":
            print(json.dumps(data, indent=2))
        elif self.output_format == "csv":
            if scan_type == "ports":
                print("Port,Service,Banner")
                for port, service, banner in data:
                    print(f'{port},"{service}","{banner}"')
            elif scan_type == "ips":
                print("IP,Status")
                for ip in data:
                    print(f'{ip},active')
        else:  # table format
            if RICH_AVAILABLE:
                if scan_type == "ports":
                    table = Table(title=f"Open Ports on Target", box=box.ROUNDED)
                    table.add_column("Port", style="cyan")
                    table.add_column("Service", style="magenta")
                    table.add_column("Banner", style="green")
                    
                    for port, service, banner in data:
                        table.add_row(str(port), service, banner)
                    
                    console.print(table)
                    
                elif scan_type == "ips":
                    table = Table(title="Active IP Addresses", box=box.ROUNDED)
                    table.add_column("IP Address", style="cyan")
                    table.add_column("Type", style="yellow")
                    
                    for ip in data:
                        ip_type = "Gateway" if ip.endswith(".1") else "Device"
                        table.add_row(ip, ip_type)
                    
                    console.print(table)
                    
                elif scan_type == "local":
                    table = Table(title="Local Network Info", box=box.ROUNDED)
                    table.add_column("Property", style="cyan")
                    table.add_column("Value", style="green")
                    
                    for key, value in data.items():
                        table.add_row(key.replace("_", " ").title(), str(value))
                    
                    console.print(table)
            else:
                # Basic table without rich
                if scan_type == "ports":
                    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
                    print(f"{Colors.BOLD}Open Ports Found:{Colors.END}")
                    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
                    print(f"{'Port':<10} {'Service':<20} {'Banner':<30}")
                    print(f"{'-'*60}")
                    for port, service, banner in data:
                        print(f"{Colors.GREEN}{port:<10}{Colors.END} {service:<20} {banner:<30}")
                
                elif scan_type == "ips":
                    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
                    print(f"{Colors.BOLD}Active IP Addresses:{Colors.END}")
                    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
                    for ip in data:
                        if ip.endswith(".1"):
                            print(f"{Colors.YELLOW}{ip:<20} (Gateway){Colors.END}")
                        else:
                            print(f"{Colors.GREEN}{ip:<20} (Device){Colors.END}")
                
                elif scan_type == "local":
                    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
                    print(f"{Colors.BOLD}Local Network Information:{Colors.END}")
                    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
                    for key, value in data.items():
                        print(f"{Colors.CYAN}{key.replace('_', ' ').title():<20}:{Colors.END} {value}")

# ================= COMMAND LINE INTERFACE =================
def main():
    parser = argparse.ArgumentParser(
        description="Python Network Toolkit - Advanced network scanning and analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan subnet 192.168.1.0/24
  %(prog)s scan ports example.com --ports 1-1000
  %(prog)s scan ports 192.168.1.1 --quick
  %(prog)s info local
  %(prog)s scan subnet 10.0.0.0/24 --output json
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Subnet scanning
    subnet_parser = subparsers.add_parser("scan", help="Scan network subnet")
    subnet_subparsers = subnet_parser.add_subparsers(dest="scan_type", help="Type of scan")
    
    # Subnet IP scan
    ip_scan = subnet_subparsers.add_parser("subnet", help="Scan subnet for active IPs")
    ip_scan.add_argument("subnet", help="Subnet to scan (e.g., 192.168.1 or 192.168.1.0/24)")
    ip_scan.add_argument("--start", type=int, default=1, help="Start IP (default: 1)")
    ip_scan.add_argument("--end", type=int, default=254, help="End IP (default: 254)")
    ip_scan.add_argument("--threads", type=int, default=100, help="Max threads (default: 100)")
    ip_scan.add_argument("--output", choices=["table", "json", "csv"], default="table", 
                        help="Output format (default: table)")
    
    # Port scan
    port_scan = subnet_subparsers.add_parser("ports", help="Scan target ports")
    port_scan.add_argument("target", help="Target hostname or IP address")
    port_scan.add_argument("--ports", default="1-5000", help="Port range (default: 1-5000)")
    port_scan.add_argument("--threads", type=int, default=100, help="Max threads (default: 100)")
    port_scan.add_argument("--quick", action="store_true", help="Scan only common ports")
    port_scan.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")
    port_scan.add_argument("--output", choices=["table", "json", "csv"], default="table",
                          help="Output format (default: table)")
    
    # Local info
    info_parser = subparsers.add_parser("info", help="Get network information")
    info_subparsers = info_parser.add_subparsers(dest="info_type", help="Type of information")
    info_subparsers.add_parser("local", help="Show local network information")
    
    # Version
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if not args.command:
        show_banner()
        parser.print_help()
        return
    
    scanner = NetworkScanner(output_format=args.output if hasattr(args, 'output') else "table",
                           verbose=args.verbose)
    
    try:
        if args.command == "scan":
            if args.scan_type == "subnet":
                # Parse subnet
                subnet = args.subnet
                if "/" in subnet:
                    # Handle CIDR notation (basic implementation)
                    subnet = subnet.split("/")[0].rstrip('.')
                
                print(f"{Colors.CYAN}Starting subnet scan...{Colors.END}")
                active_ips = scanner.scan_subnet(
                    subnet=subnet,
                    start=args.start,
                    end=args.end,
                    max_threads=args.threads
                )
                
                scanner.display_results("ips", active_ips)
                print(f"\n{Colors.GREEN}Found {len(active_ips)} active devices{Colors.END}")
                
            elif args.scan_type == "ports":
                # Parse port range
                if args.quick:
                    # Common ports
                    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                                  445, 993, 995, 1723, 3306, 3389, 5900, 8080]
                    start_port, end_port = 1, max(common_ports)
                    ports_to_scan = common_ports
                else:
                    if "-" in args.ports:
                        start_port, end_port = map(int, args.ports.split("-"))
                    else:
                        start_port = end_port = int(args.ports)
                    ports_to_scan = range(start_port, end_port + 1)
                
                print(f"{Colors.CYAN}Starting port scan...{Colors.END}")
                open_ports = scanner.scan_ports(
                    target=args.target,
                    start_port=start_port,
                    end_port=end_port,
                    max_threads=args.threads,
                    banner_grab=not args.no_banner
                )
                
                scanner.display_results("ports", open_ports)
                print(f"\n{Colors.GREEN}Found {len(open_ports)} open ports{Colors.END}")
                
        elif args.command == "info":
            if args.info_type == "local":
                local_info = scanner.get_local_ip()
                scanner.display_results("local", local_info)
                
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user.{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.END}")
        sys.exit(1)

# ================= INTERACTIVE MENU =================
def interactive_menu():
    """Interactive menu for those who prefer GUI-like interface"""
    scanner = NetworkScanner()
    
    while True:
        scanner.clear_screen()
        show_banner()
        
        print(f"{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.CYAN}║                 INTERACTIVE MENU                                      ║{Colors.END}")
        print(f"{Colors.CYAN}╠═══════════════════════════════════════════════════════════════════════╣{Colors.END}")
        print(f"{Colors.CYAN}║   {Colors.GREEN}1{Colors.CYAN}. Scan Subnet for Active IPs            ║{Colors.END}")
        print(f"{Colors.CYAN}║   {Colors.GREEN}2{Colors.CYAN}. Scan Ports on Target Host             ║{Colors.END}")
        print(f"{Colors.CYAN}║   {Colors.GREEN}3{Colors.CYAN}. Show Local Network Information        ║{Colors.END}")
        print(f"{Colors.CYAN}║   {Colors.GREEN}4{Colors.CYAN}. Quick Scan (Common Ports)             ║{Colors.END}")
        print(f"{Colors.CYAN}║   {Colors.GREEN}5{Colors.CYAN}. Exit                                  ║{Colors.END}")
        print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════════════╝{Colors.END}")
        print()
        
        choice = input(f"{Colors.YELLOW}Select option (1-5): {Colors.END}").strip()
        
        try:
            if choice == "1":
                scanner.clear_screen()
                show_banner()
                print(f"{Colors.CYAN}Subnet Scanner{Colors.END}")
                print(f"{Colors.CYAN}{'='*50}{Colors.END}")
                
                subnet = input(f"{Colors.YELLOW}Enter subnet (e.g., 192.168.1): {Colors.END}").strip().rstrip('.')
                start = input(f"{Colors.YELLOW}Start IP [1]: {Colors.END}").strip()
                end = input(f"{Colors.YELLOW}End IP [254]: {Colors.END}").strip()
                
                start = int(start) if start.isdigit() else 1
                end = int(end) if end.isdigit() else 254
                
                active_ips = scanner.scan_subnet(subnet, start, end)
                scanner.display_results("ips", active_ips)
                
                input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
                
            elif choice == "2":
                scanner.clear_screen()
                show_banner()
                print(f"{Colors.CYAN}Port Scanner{Colors.END}")
                print(f"{Colors.CYAN}{'='*50}{Colors.END}")
                
                target = input(f"{Colors.YELLOW}Enter target host/IP: {Colors.END}").strip()
                ports = input(f"{Colors.YELLOW}Port range [1-5000]: {Colors.END}").strip() or "1-5000"
                
                if "-" in ports:
                    start_port, end_port = map(int, ports.split("-"))
                else:
                    start_port = end_port = int(ports)
                
                open_ports = scanner.scan_ports(target, start_port, end_port)
                scanner.display_results("ports", open_ports)
                
                input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
                
            elif choice == "3":
                scanner.clear_screen()
                show_banner()
                local_info = scanner.get_local_ip()
                scanner.display_results("local", local_info)
                input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
                
            elif choice == "4":
                scanner.clear_screen()
                show_banner()
                print(f"{Colors.CYAN}Quick Scanner{Colors.END}")
                print(f"{Colors.CYAN}{'='*50}{Colors.END}")
                
                target = input(f"{Colors.YELLOW}Enter target host/IP: {Colors.END}").strip()
                
                # Scan common ports
                common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3389, 8080]
                open_ports = []
                
                print(f"\n{Colors.CYAN}Scanning common ports...{Colors.END}")
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((socket.gethostbyname(target), port))
                        if result == 0:
                            try:
                                service = socket.getservbyport(port)
                            except:
                                service = "unknown"
                            open_ports.append((port, service, ""))
                            print(f"{Colors.GREEN}[✓] Port {port} ({service}){Colors.END}")
                        sock.close()
                    except:
                        pass
                
                scanner.display_results("ports", open_ports)
                input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
                
            elif choice == "5":
                print(f"\n{Colors.GREEN}Goodbye! 👋{Colors.END}")
                sys.exit(0)
            else:
                print(f"{Colors.RED}Invalid choice. Please try again.{Colors.END}")
                time.sleep(1)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Operation cancelled.{Colors.END}")
            time.sleep(1)
        except Exception as e:
            print(f"{Colors.RED}Error: {str(e)}{Colors.END}")
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

# ================= ENTRY POINT =================
if __name__ == "__main__":
    # Check if running with arguments (CLI mode) or interactive mode
    if len(sys.argv) > 1:
        main()
    else:
        interactive_menu()