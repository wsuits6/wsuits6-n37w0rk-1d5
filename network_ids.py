#!/usr/bin/env python3
"""
=========================================================================
By: WSUITS6 
Network IDS Terminal Monitor
A comprehensive network monitoring tool for cybersecurity professionals
"""


#importing necessary libraries
#=========================================================================
import psutil
import socket
import requests
import time
from datetime import datetime
from collections import defaultdict
from colorama import init, Fore, Back, Style
import os
import platform




# Initialize colorama
#=======================================================================
init(autoreset=True)


#NetworkIDS Class Innitialization
#=====================================================
class NetworkIDS:
    def __init__(self):
        #ip_cache => is a Dictionary to automatically store GEO location of IPs
        self.ip_cache = {}
        #track statisitic for connection
        self.connection_stats = defaultdict(int)
        

    #clear terminal screen
    def clear_screen(self):
        """Detect OS and Clear terminal screen"""
        #command
        os.system('cls' if platform.system() == 'Windows' else 'clear')



    #getting IP info
    # (1) Check if the Ip is in ip_cache to prevent Bogus API calls
    # Identify Public and Private Ips 
    def get_ip_info(self, ip):
        """Get geolocation info for an IP address"""
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        # Skip local/private IPs
        if ip.startswith(('127.', '192.168.', '10.', '172.')) or ip == '::1':
            info = {'country': 'Local', 'city': 'N/A', 'org': 'Private Network'}
            self.ip_cache[ip] = info
            return info
        
        #Check Public IPs GEO location Using API
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
            if response.status_code == 200:
                data = response.json()
                #INFO Structure
                info = {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'isp': data.get('isp', 'Unknown')
                }
                self.ip_cache[ip] = info
                return info
        except:
            pass
        
        info = {'country': 'Unknown', 'city': 'Unknown', 'org': 'Unknown'}
        self.ip_cache[ip] = info
        return info
    
    def get_service_name(self, port):
        """Get common service name for a port"""
        services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-ALT',
            27017: 'MongoDB', 6379: 'Redis'
        }
        return services.get(port, 'UNKNOWN')
    
    def get_connections(self):
        """Get all network connections"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                    connections.append(conn)
        except (psutil.AccessDenied, PermissionError):
            print(f"{Fore.RED}[!] Permission denied. Run with sudo/admin privileges{Style.RESET_ALL}")
        return connections
    
    def get_process_name(self, pid):
        """Get process name from PID"""
        try:
            if pid:
                process = psutil.Process(pid)
                return process.name()
        except:
            pass
        return "Unknown"
    
    def print_header(self):
        """Print fancy header"""
        print(f"\n{Back.BLUE}{Fore.WHITE}{'='*100}{Style.RESET_ALL}")
        print(f"{Back.BLUE}{Fore.WHITE}{' '*35}NETWORK IDS MONITOR{' '*46}{Style.RESET_ALL}")
        print(f"{Back.BLUE}{Fore.WHITE}{'='*100}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Host: {socket.gethostname()}{Style.RESET_ALL}\n")
    
    def display_active_connections(self):
        """Display active network connections"""
        print(f"\n{Back.GREEN}{Fore.BLACK} ACTIVE CONNECTIONS {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*100}{Style.RESET_ALL}")
        
        connections = self.get_connections()
        active_conns = [c for c in connections if c.status == 'ESTABLISHED']
        
        if not active_conns:
            print(f"{Fore.YELLOW}No active connections found{Style.RESET_ALL}")
            return
        
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'Local Address':<25} {'Remote Address':<25} {'Status':<15} {'PID':<8} {'Process':<20}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")
        
        for conn in active_conns[:15]:  # Limit to 15 for readability
            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            process = self.get_process_name(conn.pid)
            
            print(f"{Fore.GREEN}{local:<25} {Fore.MAGENTA}{remote:<25} {Fore.YELLOW}{conn.status:<15} {Fore.CYAN}{str(conn.pid):<8} {Fore.WHITE}{process:<20}{Style.RESET_ALL}")
    
    def display_incoming_connections(self):
        """Display incoming connections with geolocation"""
        print(f"\n{Back.RED}{Fore.WHITE} INCOMING CONNECTIONS (Remote IPs) {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*100}{Style.RESET_ALL}")
        
        connections = self.get_connections()
        active_conns = [c for c in connections if c.status == 'ESTABLISHED' and c.raddr]
        
        if not active_conns:
            print(f"{Fore.YELLOW}No incoming connections detected{Style.RESET_ALL}")
            return
        
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'Remote IP':<18} {'Port':<8} {'Country':<20} {'City':<20} {'Organization':<30}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")
        
        seen_ips = set()
        for conn in active_conns:
            if conn.raddr and conn.raddr.ip not in seen_ips:
                seen_ips.add(conn.raddr.ip)
                ip_info = self.get_ip_info(conn.raddr.ip)
                
                # Color code based on whether it's local or external
                ip_color = Fore.GREEN if ip_info['country'] == 'Local' else Fore.RED
                
                print(f"{ip_color}{conn.raddr.ip:<18} {Fore.YELLOW}{str(conn.raddr.port):<8} {Fore.CYAN}{ip_info['country']:<20} {Fore.MAGENTA}{ip_info['city']:<20} {Fore.WHITE}{ip_info['org'][:29]:<30}{Style.RESET_ALL}")
                
                if len(seen_ips) >= 10:  # Limit display
                    break
    
    def display_listening_services(self):
        """Display services listening on ports"""
        print(f"\n{Back.MAGENTA}{Fore.WHITE} LISTENING SERVICES {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*100}{Style.RESET_ALL}")
        
        connections = self.get_connections()
        listening = [c for c in connections if c.status == 'LISTEN']
        
        if not listening:
            print(f"{Fore.YELLOW}No listening services found{Style.RESET_ALL}")
            return
        
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'Local Address':<20} {'Port':<8} {'Service':<15} {'PID':<8} {'Process':<20} {'State':<12}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'-'*100}{Style.RESET_ALL}")
        
        for conn in listening[:20]:  # Limit to 20
            if conn.laddr:
                service = self.get_service_name(conn.laddr.port)
                process = self.get_process_name(conn.pid)
                
                # Color code based on security risk
                port_color = Fore.RED if conn.laddr.port in [23, 21, 3389] else Fore.GREEN
                
                print(f"{Fore.CYAN}{conn.laddr.ip:<20} {port_color}{str(conn.laddr.port):<8} {Fore.YELLOW}{service:<15} {Fore.MAGENTA}{str(conn.pid):<8} {Fore.WHITE}{process:<20} {Fore.GREEN}{'LISTENING':<12}{Style.RESET_ALL}")
    
    def display_statistics(self):
        """Display connection statistics"""
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
        
        # Network interface stats
        net_io = psutil.net_io_counters()
        print(f"\n{Fore.WHITE}{'Bytes Sent':<25}: {Fore.CYAN}{self.format_bytes(net_io.bytes_sent)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'Bytes Received':<25}: {Fore.CYAN}{self.format_bytes(net_io.bytes_recv)}{Style.RESET_ALL}")
    
    def format_bytes(self, bytes_val):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"
    
    def run(self, refresh_interval=5):
        """Run the IDS monitor"""
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
                
                print(f"\n{Fore.CYAN}Refreshing in {refresh_interval} seconds... (Ctrl+C to exit){Style.RESET_ALL}")
                time.sleep(refresh_interval)
                
        except KeyboardInterrupt:
            print(f"\n\n{Fore.GREEN}[+] IDS Monitor stopped by user{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Thank you for using Network IDS Monitor!{Style.RESET_ALL}\n")

if __name__ == "__main__":
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
    print(f"{Fore.YELLOW}Network Intrusion Detection System - Terminal Monitor{Style.RESET_ALL}")
    print(f"{Fore.CYAN}For Cybersecurity Professionals{Style.RESET_ALL}\n")
    
    ids = NetworkIDS()
    ids.run(refresh_interval=5)


    #THis si an Awesome tool for anyone who wants to just be patanoid for no reason