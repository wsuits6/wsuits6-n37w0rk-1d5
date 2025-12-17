# Network IDS Terminal Monitor

A comprehensive network intrusion detection system (IDS) for monitoring network connections, identifying incoming threats, and tracking active services on your system.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Code Architecture](#code-architecture)
- [Detailed Code Explanation](#detailed-code-explanation)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Features

✅ **Real-time Network Monitoring** - Live tracking of all network connections  
✅ **Geolocation Intelligence** - Identifies country, city, and organization for remote IPs  
✅ **Service Identification** - Recognizes common services by port numbers  
✅ **Process Tracking** - Shows which processes are making connections  
✅ **Listening Port Detection** - Identifies all services accepting incoming connections  
✅ **Color-coded Interface** - Easy-to-read terminal output with threat indicators  
✅ **Connection Statistics** - Real-time metrics on network activity  
✅ **Auto-refresh** - Continuous monitoring with configurable intervals

---

## Installation

### Prerequisites
- Python 3.6 or higher
- Administrative/root privileges (required for network monitoring)

### Install Dependencies

```bash
pip install psutil colorama requests
```

**Dependency Details:**
- `psutil` - System and network monitoring library
- `colorama` - Cross-platform colored terminal output
- `requests` - HTTP library for geolocation API calls

---

## Usage

### Basic Usage

**Linux/macOS:**
```bash
sudo python3 network_ids.py
```

**Windows (Run as Administrator):**
```bash
python network_ids.py
```

### Exit the Program
Press `Ctrl+C` to gracefully exit the monitor.

### Configuration
To change the refresh interval, modify the `refresh_interval` parameter in the `run()` method (default: 5 seconds).

---

## Code Architecture

The application follows an object-oriented design with a single `NetworkIDS` class that encapsulates all functionality:

```
NetworkIDS
├── __init__()              # Initialize cache and statistics
├── clear_screen()          # Terminal management
├── get_ip_info()           # Geolocation lookup
├── get_service_name()      # Port-to-service mapping
├── get_connections()       # Retrieve network connections
├── get_process_name()      # PID-to-process mapping
├── print_header()          # Display banner
├── display_active_connections()    # Show established connections
├── display_incoming_connections()  # Show remote IPs with geo data
├── display_listening_services()    # Show listening ports
├── display_statistics()    # Show network metrics
├── format_bytes()          # Human-readable byte formatting
└── run()                   # Main monitoring loop
```

---

## Detailed Code Explanation

### 1. Imports and Initialization

```python
import psutil
import socket
import requests
import time
from datetime import datetime
from collections import defaultdict
from colorama import init, Fore, Back, Style
import os
import platform
```

**What each library does:**
- **psutil**: Provides cross-platform system and network information. Used to retrieve network connections, process details, and I/O statistics.
- **socket**: Standard library for network operations. Used to get the hostname.
- **requests**: Makes HTTP requests to the geolocation API.
- **time**: Handles sleep intervals between refreshes.
- **datetime**: Displays timestamps in the interface.
- **defaultdict**: Automatically initializes dictionary values for statistics counting.
- **colorama**: Enables colored terminal output on Windows, macOS, and Linux.
- **os/platform**: Determines the operating system for terminal clearing.

```python
init(autoreset=True)
```
Initializes colorama with `autoreset=True`, which automatically resets colors after each print statement, preventing color bleed.

### 2. Class Initialization

```python
def __init__(self):
    self.ip_cache = {}
    self.connection_stats = defaultdict(int)
```

**Purpose:**
- `ip_cache`: Dictionary that stores geolocation data for IPs to avoid redundant API calls. Improves performance and respects API rate limits.
- `connection_stats`: Tracks statistics about connections (currently initialized for future expansion).

### 3. Terminal Management

```python
def clear_screen(self):
    os.system('cls' if platform.system() == 'Windows' else 'clear')
```

**How it works:**
- Detects the operating system using `platform.system()`
- Executes `cls` on Windows or `clear` on Unix-based systems
- Provides a clean interface by removing previous output before each refresh

### 4. IP Geolocation Lookup

```python
def get_ip_info(self, ip):
    if ip in self.ip_cache:
        return self.ip_cache[ip]
    
    if ip.startswith(('127.', '192.168.', '10.', '172.')) or ip == '::1':
        info = {'country': 'Local', 'city': 'N/A', 'org': 'Private Network'}
        self.ip_cache[ip] = info
        return info
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
        if response.status_code == 200:
            data = response.json()
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
```

**Step-by-step breakdown:**

1. **Cache Check**: First checks if the IP is already in the cache. If yes, returns cached data immediately (avoids API calls).

2. **Private IP Detection**: Identifies local/private IP ranges:
   - `127.x.x.x` - Loopback (localhost)
   - `192.168.x.x` - Private network (Class C)
   - `10.x.x.x` - Private network (Class A)
   - `172.16-31.x.x` - Private network (Class B)
   - `::1` - IPv6 loopback

3. **API Request**: Makes a GET request to ip-api.com with:
   - 2-second timeout to prevent hanging
   - Parses JSON response to extract country, city, organization, and ISP

4. **Error Handling**: If the API call fails (network issues, rate limits, invalid IP), returns "Unknown" values.

5. **Caching**: All results (success or failure) are cached to prevent repeated lookups for the same IP.

**API Used**: ip-api.com (free tier: 45 requests/minute)

### 5. Service Identification

```python
def get_service_name(self, port):
    services = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-ALT',
        27017: 'MongoDB', 6379: 'Redis'
    }
    return services.get(port, 'UNKNOWN')
```

**How it works:**
- Maps well-known port numbers to their common service names
- Uses dictionary lookup for O(1) performance
- Returns 'UNKNOWN' for unrecognized ports
- Helps identify potential security risks (e.g., Telnet on port 23 is insecure)

**Why this matters:**
- Port 23 (Telnet) = unencrypted, high risk
- Port 3389 (RDP) = often targeted for brute-force attacks
- Port 21 (FTP) = unencrypted file transfer

### 6. Network Connection Retrieval

```python
def get_connections(self):
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                connections.append(conn)
    except (psutil.AccessDenied, PermissionError):
        print(f"{Fore.RED}[!] Permission denied. Run with sudo/admin privileges{Style.RESET_ALL}")
    return connections
```

**Detailed explanation:**

1. **psutil.net_connections(kind='inet')**: Retrieves all IPv4 network connections. Parameters:
   - `kind='inet'`: Only IPv4 connections (excludes IPv6, Unix sockets)
   - Returns connection objects with attributes: laddr, raddr, status, pid

2. **Connection Filtering**: Only captures:
   - `ESTABLISHED` - Active bidirectional connections
   - `LISTEN` - Services waiting for incoming connections

3. **Connection Object Structure**:
   ```python
   conn.laddr    # Local address (ip, port)
   conn.raddr    # Remote address (ip, port) 
   conn.status   # TCP state (ESTABLISHED, LISTEN, etc.)
   conn.pid      # Process ID owning the connection
   conn.type     # Socket type (SOCK_STREAM, SOCK_DGRAM)
   ```

4. **Permission Handling**: Requires elevated privileges. If denied, displays error message and returns empty list.

### 7. Process Name Resolution

```python
def get_process_name(self, pid):
    try:
        if pid:
            process = psutil.Process(pid)
            return process.name()
    except:
        pass
    return "Unknown"
```

**How it works:**
- Takes a Process ID (PID) as input
- Creates a psutil.Process object for that PID
- Retrieves the process name (e.g., "chrome.exe", "sshd", "python3")
- Returns "Unknown" if the process doesn't exist or access is denied

**Use case**: Identifies which application is making network connections (helps detect unauthorized programs).

### 8. Header Display

```python
def print_header(self):
    print(f"\n{Back.BLUE}{Fore.WHITE}{'='*100}{Style.RESET_ALL}")
    print(f"{Back.BLUE}{Fore.WHITE}{' '*35}NETWORK IDS MONITOR{' '*46}{Style.RESET_ALL}")
    print(f"{Back.BLUE}{Fore.WHITE}{'='*100}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Host: {socket.gethostname()}{Style.RESET_ALL}\n")
```

**Color coding:**
- `Back.BLUE` - Blue background for emphasis
- `Fore.WHITE` - White text for high contrast
- `Fore.CYAN` - Cyan for metadata (timestamp, hostname)
- `Style.RESET_ALL` - Resets all styling after each line

**Information displayed:**
- Current timestamp in YYYY-MM-DD HH:MM:SS format
- System hostname for identification

### 9. Active Connections Display

```python
def display_active_connections(self):
    connections = self.get_connections()
    active_conns = [c for c in connections if c.status == 'ESTABLISHED']
    
    if not active_conns:
        print(f"{Fore.YELLOW}No active connections found{Style.RESET_ALL}")
        return
    
    for conn in active_conns[:15]:
        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        process = self.get_process_name(conn.pid)
        
        print(f"{Fore.GREEN}{local:<25} {Fore.MAGENTA}{remote:<25} {Fore.YELLOW}{conn.status:<15} {Fore.CYAN}{str(conn.pid):<8} {Fore.WHITE}{process:<20}{Style.RESET_ALL}")
```

**Functionality:**

1. **Filtering**: List comprehension extracts only `ESTABLISHED` connections (actively transmitting data).

2. **Limit Display**: Shows maximum 15 connections to prevent screen overflow (`:15` slice).

3. **String Formatting**:
   - `{local:<25}` - Left-aligned, 25 characters wide
   - Creates uniform column spacing

4. **Address Handling**: Checks if `laddr` and `raddr` exist before accessing (prevents AttributeError on connections without remote address).

5. **Color Scheme**:
   - Green = Local address (your system)
   - Magenta = Remote address (external system)
   - Yellow = Connection status
   - Cyan = Process ID
   - White = Process name

### 10. Incoming Connections with Geolocation

```python
def display_incoming_connections(self):
    connections = self.get_connections()
    active_conns = [c for c in connections if c.status == 'ESTABLISHED' and c.raddr]
    
    seen_ips = set()
    for conn in active_conns:
        if conn.raddr and conn.raddr.ip not in seen_ips:
            seen_ips.add(conn.raddr.ip)
            ip_info = self.get_ip_info(conn.raddr.ip)
            
            ip_color = Fore.GREEN if ip_info['country'] == 'Local' else Fore.RED
            
            print(f"{ip_color}{conn.raddr.ip:<18} {Fore.YELLOW}{str(conn.raddr.port):<8} {Fore.CYAN}{ip_info['country']:<20} {Fore.MAGENTA}{ip_info['city']:<20} {Fore.WHITE}{ip_info['org'][:29]:<30}{Style.RESET_ALL}")
            
            if len(seen_ips) >= 10:
                break
```

**Key concepts:**

1. **Deduplication**: Uses a `set()` to track seen IPs and avoid showing the same remote IP multiple times.

2. **Geolocation Call**: Calls `get_ip_info()` for each unique remote IP to retrieve country, city, and organization.

3. **Threat Indication**:
   - **Green** = Local IP (safe, internal network)
   - **Red** = External IP (potential threat, requires monitoring)

4. **Display Limit**: Stops after 10 unique IPs to maintain readability and reduce API calls.

5. **String Slicing**: `ip_info['org'][:29]` truncates organization name to 29 characters to prevent line overflow.

**Security insight**: External IPs from unexpected countries may indicate:
- Compromised credentials
- Backdoor connections
- Data exfiltration attempts

### 11. Listening Services Detection

```python
def display_listening_services(self):
    connections = self.get_connections()
    listening = [c for c in connections if c.status == 'LISTEN']
    
    for conn in listening[:20]:
        if conn.laddr:
            service = self.get_service_name(conn.laddr.port)
            process = self.get_process_name(conn.pid)
            
            port_color = Fore.RED if conn.laddr.port in [23, 21, 3389] else Fore.GREEN
            
            print(f"{Fore.CYAN}{conn.laddr.ip:<20} {port_color}{str(conn.laddr.port):<8} {Fore.YELLOW}{service:<15} {Fore.MAGENTA}{str(conn.pid):<8} {Fore.WHITE}{process:<20} {Fore.GREEN}{'LISTENING':<12}{Style.RESET_ALL}")
```

**Analysis:**

1. **LISTEN State**: These are services/applications waiting for incoming connections (servers, daemons, background services).

2. **Security Risk Color-Coding**:
   - **Red ports**: 21 (FTP), 23 (Telnet), 3389 (RDP) - Commonly exploited
   - **Green ports**: All others - Generally safer

3. **Information Displayed**:
   - Local IP the service is bound to (0.0.0.0 = all interfaces, 127.0.0.1 = localhost only)
   - Port number
   - Service name (HTTP, SSH, MySQL, etc.)
   - Process ID
   - Process name

**Why this matters**: Unexpected listening services may indicate:
- Malware establishing a command-and-control channel
- Unauthorized remote access tools
- Misconfigured services exposing attack surface

### 12. Connection Statistics

```python
def display_statistics(self):
    connections = self.get_connections()
    
    stats = {
        'Total Connections': len(connections),
        'Established': len([c for c in connections if c.status == 'ESTABLISHED']),
        'Listening': len([c for c in connections if c.status == 'LISTEN']),
        'Time Wait': len([c for c in connections if c.status == 'TIME_WAIT']),
    }
    
    net_io = psutil.net_io_counters()
    print(f"\n{Fore.WHITE}{'Bytes Sent':<25}: {Fore.CYAN}{self.format_bytes(net_io.bytes_sent)}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{'Bytes Received':<25}: {Fore.CYAN}{self.format_bytes(net_io.bytes_recv)}{Style.RESET_ALL}")
```

**Metrics explained:**

1. **Total Connections**: All active network connections (established + listening + other states).

2. **Established**: Active bidirectional connections currently transmitting data.

3. **Listening**: Services waiting for incoming connections.

4. **Time Wait**: Connections in TCP TIME_WAIT state (recently closed, waiting to ensure all packets are received).

5. **Network I/O Counters**:
   - `bytes_sent`: Total data transmitted since boot
   - `bytes_recv`: Total data received since boot
   - Formatted using `format_bytes()` for human readability

### 13. Byte Formatting

```python
def format_bytes(self, bytes_val):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} PB"
```

**Algorithm:**
- Iterates through units (B → KB → MB → GB → TB)
- Divides by 1024 until value is less than 1024
- Returns formatted string with 2 decimal places
- Example: 1,536,000 bytes → 1.50 MB

### 14. Main Monitoring Loop

```python
def run(self, refresh_interval=5):
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
```

**Execution flow:**

1. **Infinite Loop**: Runs continuously until interrupted.

2. **Screen Refresh Cycle**:
   - Clear terminal
   - Display header with timestamp
   - Show statistics
   - Display all connection types
   - Wait for specified interval

3. **Graceful Exit**: `KeyboardInterrupt` exception catches Ctrl+C and displays exit message.

4. **Refresh Interval**: Configurable parameter (default: 5 seconds). Lower values = more real-time but higher CPU usage.

---

## Security Considerations

### Threat Detection Capabilities

**What This Tool Can Detect:**
1. **Unauthorized Outbound Connections** - Unknown processes communicating externally
2. **Suspicious Listening Ports** - Unexpected services accepting connections
3. **Unusual Geographic Connections** - Traffic from high-risk countries
4. **Port Scanning** - Multiple connection attempts on various ports
5. **Data Exfiltration** - Large outbound data transfers

### Limitations

**What This Tool Cannot Detect:**
- Encrypted payload contents (HTTPS traffic is opaque)
- DNS tunneling or other covert channels
- Kernel-level rootkits hiding connections
- Low-and-slow attacks below detection thresholds

### Best Practices

1. **Run with Elevated Privileges**: Required for full network visibility
2. **Regular Monitoring**: Check for anomalies in connection patterns
3. **Baseline Normal Behavior**: Understand typical connections for your system
4. **Correlate with Logs**: Cross-reference with firewall and system logs
5. **API Rate Limits**: ip-api.com allows 45 requests/minute (free tier)

---

## Troubleshooting

### Common Issues

**1. "Permission denied" Error**
```bash
# Linux/macOS
sudo python3 network_ids.py

# Windows - Run Command Prompt as Administrator
python network_ids.py
```

**2. ModuleNotFoundError**
```bash
pip install psutil colorama requests
```

**3. No Connections Displayed**
- Ensure you have active network activity
- Check firewall settings aren't blocking monitoring
- Verify you're running with administrative privileges

**4. API Rate Limit Exceeded**
- The tool caches IPs to minimize API calls
- Free tier allows 45 requests/minute
- Consider implementing longer cache TTL for high-traffic systems

**5. Colors Not Displaying (Windows)**
- Update to Windows 10+ with modern terminal
- Or use Windows Terminal from Microsoft Store
- colorama should handle this automatically

### Performance Optimization

**For High-Traffic Systems:**
- Increase refresh interval: `ids.run(refresh_interval=10)`
- Reduce display limits in connection loops
- Implement persistent caching with expiration times

**For Low-Resource Systems:**
- Disable geolocation lookups for local IPs (already implemented)
- Increase refresh interval
- Limit number of displayed connections

---

## Advanced Usage

### Custom Refresh Interval
```python
ids = NetworkIDS()
ids.run(refresh_interval=10)  # Refresh every 10 seconds
```

### Logging to File
Add logging functionality by redirecting output:
```bash
python3 network_ids.py | tee network_monitor.log
```

### Integration with SIEM
Parse the output and forward to your Security Information and Event Management (SIEM) system for centralized monitoring.

---

## Contributing

This tool is designed for educational and professional cybersecurity use. Contributions welcome:
- Enhanced threat detection algorithms
- Additional service signatures
- Performance optimizations
- Integration with threat intelligence feeds

---

## License

This tool is provided as-is for cybersecurity research and monitoring purposes. Ensure compliance with local laws and organizational policies when monitoring network traffic.

---

## Disclaimer

This tool is intended for authorized network monitoring only. Users are responsible for ensuring they have proper authorization to monitor network traffic on their systems and networks. Unauthorized network monitoring may violate laws and regulations.

---

## Support

For issues or questions:
- Review this README thoroughly
- Check the troubleshooting section
- Verify all dependencies are correctly installed
- Ensure you're running with appropriate privileges

**Happy Monitoring! Stay Secure! 🔒**