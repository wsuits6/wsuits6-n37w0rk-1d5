#!/usr/bin/env python3
# ^ Tells the OS to run this file using Python 3

"""
=========================================================================
By: WSUITS6 
Network IDS Terminal Monitor
A comprehensive network monitoring tool for cybersecurity professionals
=========================================================================
"""

# ===================== IMPORT REQUIRED LIBRARIES ======================

import psutil              # Used to gather system and network information
import socket              # Used for hostname and network-related operations
import requests            # Used to make HTTP requests (IP geolocation API)
import time                # Used for delays and sleep timers
from datetime import datetime  # Used to display timestamps
from collections import defaultdict  # Dictionary with default values
from colorama import init, Fore, Back, Style  # Colored terminal output
import os                  # Used for system-level operations
import platform            # Used to detect operating system type


# ===================== INITIALIZE COLORAMA ============================

init(autoreset=True)  
# autoreset=True ensures colors reset automatically after each print


# ===================== NETWORK IDS CLASS ==============================

class NetworkIDS:
    def __init__(self):
        # Dictionary to cache IP geolocation results
        # Prevents repeated API calls for the same IP
        self.ip_cache = {}

        # Dictionary to track connection statistics
        self.connection_stats = defaultdict(int)

    # ===================== CLEAR TERMINAL SCREEN =======================

    def clear_screen(self):
        """Detect OS and clear the terminal screen"""
        # Use 'cls' for Windows, 'clear' for Linux/macOS
        os.system('cls' if platform.system() == 'Windows' else 'clear')

    # ===================== IP GEOLOCATION LOOKUP =======================

    def get_ip_info(self, ip):
        """Get geolocation information for an IP address"""

        # If IP info is already cached, return it
        if ip in self.ip_cache:
            return self.ip_cache[ip]

        # Detect local/private IP addresses
        if ip.startswith(('127.', '192.168.', '10.', '172.')) or ip == '::1':
            info = {
                'country': 'Local',
                'city': 'N/A',
                'org': 'Private Network'
            }
            # Store result in cache
            self.ip_cache[ip] = info
            return info

        # Query public IP geolocation API
        try:
            response = requests.get(
                f'http://ip-api.com/json/{ip}',
                timeout=2  # Prevent long waits
            )

            # If request is successful
            if response.status_code == 200:
                data = response.json()

                # Extract relevant data fields
                info = {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'isp': data.get('isp', 'Unknown')
                }

                # Cache the IP info
                self.ip_cache[ip] = info
                return info

        except:
            # Ignore any API/network errors
            pass

        # Fallback if lookup fails
        info = {
            'country': 'Unknown',
            'city': 'Unknown',
            'org': 'Unknown'
        }

        # Cache unknown result
        self.ip_cache[ip] = info
        return info

    # ===================== SERVICE NAME BY PORT ========================

    def get_service_name(self, port):
        """Return common service name for a given port"""

        # Dictionary of common port-to-service mappings
        services = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-ALT',
            27017: 'MongoDB',
            6379: 'Redis'
        }

        # Return service name or UNKNOWN if not found
        return services.get(port, 'UNKNOWN')

    # ===================== GET NETWORK CONNECTIONS =====================

    def get_connections(self):
        """Retrieve all active network connections"""

        connections = []  # Store valid connections here

        try:
            # Iterate through all internet connections
            for conn in psutil.net_connections(kind='inet'):
                # Only keep LISTEN or ESTABLISHED connections
                if conn.status in ('ESTABLISHED', 'LISTEN'):
                    connections.append(conn)

        except (psutil.AccessDenied, PermissionError):
            # Display permission error message
            print(
                f"{Fore.RED}[!] Permission denied. "
                f"Run with sudo/admin privileges{Style.RESET_ALL}"
            )

        return connections

    # ===================== GET PROCESS NAME ============================

    def get_process_name(self, pid):
        """Return process name given a PID"""

        try:
            if pid:
                process = psutil.Process(pid)
                return process.name()
        except:
            pass

        return "Unknown"

    # ===================== HEADER DISPLAY ==============================

    def print_header(self):
        """Print IDS header banner"""

        print(f"\n{Back.BLUE}{Fore.WHITE}{'='*100}{Style.RESET_ALL}")
        print(f"{Back.BLUE}{Fore.WHITE}{' '*35}NETWORK IDS MONITOR{' '*46}{Style.RESET_ALL}")
        print(f"{Back.BLUE}{Fore.WHITE}{'='*100}{Style.RESET_ALL}")

        # Print current timestamp
        print(
            f"{Fore.CYAN}Timestamp: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}"
        )

        # Print hostname
        print(f"{Fore.CYAN}Host: {socket.gethostname()}{Style.RESET_ALL}\n")

    # ===================== ACTIVE CONNECTIONS ==========================

    def display_active_connections(self):
        """Display active established network connections"""

        print(f"\n{Back.GREEN}{Fore.BLACK} ACTIVE CONNECTIONS {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*100}{Style.RESET_ALL}")

        connections = self.get_connections()

        # Filter only ESTABLISHED connections
        active_conns = [c for c in connections if c.status == 'ESTABLISHED']

        if not active_conns:
            print(f"{Fore.YELLOW}No active connections found{Style.RESET_ALL}")
            return

        # Table headers
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")
        print(
            f"{Fore.CYAN}"
            f"{'Local Address':<25} "
            f"{'Remote Address':<25} "
            f"{'Status':<15} "
            f"{'PID':<8} "
            f"{'Process':<20}"
            f"{Style.RESET_ALL}"
        )
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")

        # Display only first 15 connections
        for conn in active_conns[:15]:
            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            process = self.get_process_name(conn.pid)

            print(
                f"{Fore.GREEN}{local:<25} "
                f"{Fore.MAGENTA}{remote:<25} "
                f"{Fore.YELLOW}{conn.status:<15} "
                f"{Fore.CYAN}{str(conn.pid):<8} "
                f"{Fore.WHITE}{process:<20}"
                f"{Style.RESET_ALL}"
            )

    # ===================== INCOMING CONNECTIONS ========================

    def display_incoming_connections(self):
        """Display incoming remote IP connections with geolocation"""

        print(f"\n{Back.RED}{Fore.WHITE} INCOMING CONNECTIONS (Remote IPs) {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*100}{Style.RESET_ALL}")

        connections = self.get_connections()

        # Filter established connections with remote addresses
        active_conns = [
            c for c in connections
            if c.status == 'ESTABLISHED' and c.raddr
        ]

        if not active_conns:
            print(f"{Fore.YELLOW}No incoming connections detected{Style.RESET_ALL}")
            return

        # Table header
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")
        print(
            f"{Fore.CYAN}"
            f"{'Remote IP':<18} "
            f"{'Port':<8} "
            f"{'Country':<20} "
            f"{'City':<20} "
            f"{'Organization':<30}"
            f"{Style.RESET_ALL}"
        )
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")

        seen_ips = set()  # Track unique IPs

        for conn in active_conns:
            if conn.raddr.ip not in seen_ips:
                seen_ips.add(conn.raddr.ip)

                # Get geolocation info
                ip_info = self.get_ip_info(conn.raddr.ip)

                # Color local vs external IPs
                ip_color = (
                    Fore.GREEN if ip_info['country'] == 'Local'
                    else Fore.RED
                )

                print(
                    f"{ip_color}{conn.raddr.ip:<18} "
                    f"{Fore.YELLOW}{str(conn.raddr.port):<8} "
                    f"{Fore.CYAN}{ip_info['country']:<20} "
                    f"{Fore.MAGENTA}{ip_info['city']:<20} "
                    f"{Fore.WHITE}{ip_info['org'][:29]:<30}"
                    f"{Style.RESET_ALL}"
                )

                # Limit output to 10 IPs
                if len(seen_ips) >= 10:
                    break

    # ===================== LISTENING SERVICES ==========================

    def display_listening_services(self):
        """Display services listening on local ports"""

        print(f"\n{Back.MAGENTA}{Fore.WHITE} LISTENING SERVICES {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*100}{Style.RESET_ALL}")

        connections = self.get_connections()

        # Filter listening connections
        listening = [c for c in connections if c.status == 'LISTEN']

        if not listening:
            print(f"{Fore.YELLOW}No listening services found{Style.RESET_ALL}")
            return

        # Table header
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")
        print(
            f"{Fore.CYAN}"
            f"{'Local Address':<20} "
            f"{'Port':<8} "
            f"{'Service':<15} "
            f"{'PID':<8} "
            f"{'Process':<20} "
            f"{'State':<12}"
            f"{Style.RESET_ALL}"
        )
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")

        for conn in listening[:20]:
            if conn.laddr:
                service = self.get_service_name(conn.laddr.port)
                process = self.get_process_name(conn.pid)

                # Highlight risky ports
                port_color = (
                    Fore.RED if conn.laddr.port in [23, 21, 3389]
                    else Fore.GREEN
                )

                print(
                    f"{Fore.CYAN}{conn.laddr.ip:<20} "
                    f"{port_color}{str(conn.laddr.port):<8} "
                    f"{Fore.YELLOW}{service:<15} "
                    f"{Fore.MAGENTA}{str(conn.pid):<8} "
                    f"{Fore.WHITE}{process:<20} "
                    f"{Fore.GREEN}{'LISTENING':<12}"
                    f"{Style.RESET_ALL}"
                )

    # ===================== STATISTICS ================================

    def display_statistics(self):
        """Display network statistics"""

        print(f"\n{Back.CYAN}{Fore.BLACK} CONNECTION STATISTICS {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*100}{Style.RESET_ALL}")

        connections = self.get_connections()

        stats = {
            'Total Connections': len(connections),
            'Established': len([c for c in connections if c.status == 'ESTABLISHED']),
            'Listening': len([c for c in connections if c.status == 'LISTEN']),
            'Time Wait': len([c for c in connections if c.status == 'TIME_WAIT']),
        }

        for key, value in stats.items():
            print(f"{Fore.WHITE}{key:<25}: {Fore.GREEN}{value}{Style.RESET_ALL}")

        # Network I/O statistics
        net_io = psutil.net_io_counters()

        print(
            f"\n{Fore.WHITE}{'Bytes Sent':<25}: "
            f"{Fore.CYAN}{self.format_bytes(net_io.bytes_sent)}"
            f"{Style.RESET_ALL}"
        )
        print(
            f"{Fore.WHITE}{'Bytes Received':<25}: "
            f"{Fore.CYAN}{self.format_bytes(net_io.bytes_recv)}"
            f"{Style.RESET_ALL}"
        )

    # ===================== FORMAT BYTES ===============================

    def format_bytes(self, bytes_val):
        """Convert bytes into human-readable format"""

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0

        return f"{bytes_val:.2f} PB"

    # ===================== MAIN LOOP ================================

    def run(self, refresh_interval=5):
        """Run the IDS monitor loop"""

        print(f"{Fore.GREEN}Starting Network IDS Monitor...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Press Ctrl+C to exit{Style.RESET_ALL}")
        time.sleep(2)

        try:
            while True:
                self.clear_screen()
                self.print_header()
                self.display_statistics()
                self.display_active_connections()
                self.display_incoming_connections()
                self.display_listening_services()

                print(
                    f"\n{Fore.CYAN}Refreshing in {refresh_interval} seconds..."
                    f" (Ctrl+C to exit){Style.RESET_ALL}"
                )
                time.sleep(refresh_interval)

        except KeyboardInterrupt:
            print(f"\n\n{Fore.GREEN}[+] IDS Monitor stopped by user{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Thank you for using Network IDS Monitor!{Style.RESET_ALL}\n")


# ===================== PROGRAM ENTRY POINT ============================

if __name__ == "__main__":

    # ASCII banner
    print(f"{Fore.CYAN}")
    print(r"""
    ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗    ██╗██████╗ ███████╗
    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝    ██║██╔══██╗██╔════╝
    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝     ██║██║  ██║███████╗
    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗     ██║██║  ██║╚════██║
    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗    ██║██████╔╝███████║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝╚═════╝ ╚══════╝
    """)
    print(f"{Style.RESET_ALL}")

    # Program description
    print(f"{Fore.YELLOW}Network Intrusion Detection System - Terminal Monitor{Style.RESET_ALL}")
    print(f"{Fore.CYAN}For Cybersecurity Professionals{Style.RESET_ALL}\n")

    # Create IDS object
    ids = NetworkIDS()

    # Start monitoring
    ids.run(refresh_interval=5)

    # This is an awesome tool for anyone who wants to be paranoid for no reason 😄
