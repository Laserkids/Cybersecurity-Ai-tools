import subprocess
import re
import sys
import socket
import os
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for Windows
init()

# Define risky ports and their associated services
RISKY_PORTS = {
    21: "FTP - Unencrypted file transfer",
    22: "SSH - Potential brute force target",
    23: "Telnet - Unencrypted remote access",
    25: "SMTP - Mail server, spam relay risk",
    53: "DNS - DNS amplification attacks",
    80: "HTTP - Unencrypted web traffic",
    110: "POP3 - Unencrypted email",
    135: "RPC - Windows Remote Procedure Call",
    139: "NetBIOS - Windows file sharing",
    143: "IMAP - Unencrypted email",
    445: "SMB - Windows file sharing, ransomware risk",
    1433: "MSSQL - Database server",
    1521: "Oracle DB - Database server",
    3306: "MySQL - Database server",
    3389: "RDP - Remote Desktop, brute force risk",
    5432: "PostgreSQL - Database server",
    5900: "VNC - Remote desktop access",
    6379: "Redis - In-memory database",
    8080: "HTTP Proxy - Alternative web port",
    27017: "MongoDB - NoSQL database"
}

# Comprehensive port descriptions with usage information
PORT_DESCRIPTIONS = {
    20: {"name": "FTP Data", "use": "File transfer data channel. Use FTP client to transfer files."},
    21: {"name": "FTP Control", "use": "File transfer control. Connect with FTP client (FileZilla, WinSCP) to upload/download files."},
    22: {"name": "SSH", "use": "Secure remote access. Use SSH client (PuTTY, OpenSSH) for secure terminal access and file transfer (SFTP)."},
    23: {"name": "Telnet", "use": "Unencrypted remote access. Connect with telnet client for terminal access (insecure, avoid if possible)."},
    25: {"name": "SMTP", "use": "Email sending. Configure email client or use telnet/netcat to send emails through mail server."},
    53: {"name": "DNS", "use": "Domain name resolution. Use nslookup or dig commands to query DNS records."},
    67: {"name": "DHCP Server", "use": "Dynamic IP assignment. DHCP server assigns IP addresses to network devices."},
    68: {"name": "DHCP Client", "use": "DHCP client port for receiving IP configuration from DHCP server."},
    69: {"name": "TFTP", "use": "Trivial File Transfer. Use TFTP client to transfer files (often for network device configs)."},
    80: {"name": "HTTP", "use": "Web server. Access via web browser or curl/wget for web content and APIs."},
    110: {"name": "POP3", "use": "Email retrieval. Configure email client to download emails from server."},
    123: {"name": "NTP", "use": "Time synchronization. Query with ntpdate or w32tm to sync system time."},
    135: {"name": "MS RPC", "use": "Windows RPC services. Used by Windows for various remote operations and WMI queries."},
    137: {"name": "NetBIOS Name", "use": "Windows name resolution. Query with nbtstat to resolve NetBIOS names."},
    138: {"name": "NetBIOS Datagram", "use": "Windows datagram service for browsing and messaging."},
    139: {"name": "NetBIOS Session", "use": "Windows file sharing. Access with net use command or file explorer (\\\\ip\\share)."},
    143: {"name": "IMAP", "use": "Email access. Configure email client for advanced email management with server-side folders."},
    161: {"name": "SNMP", "use": "Network monitoring. Query with snmpwalk/snmpget to monitor network devices."},
    389: {"name": "LDAP", "use": "Directory services. Query Active Directory or LDAP servers for user/computer information."},
    443: {"name": "HTTPS", "use": "Secure web server. Access via web browser for encrypted web content and secure APIs."},
    445: {"name": "SMB", "use": "Windows file sharing. Access with net use, file explorer (\\\\ip\\share), or smbclient."},
    465: {"name": "SMTPS", "use": "Secure email sending. Configure email client for encrypted SMTP communication."},
    514: {"name": "Syslog", "use": "System logging. Send/receive system logs from network devices and servers."},
    587: {"name": "SMTP Submission", "use": "Email submission. Configure email client to send emails with authentication."},
    631: {"name": "IPP", "use": "Network printing. Access printer web interface or send print jobs via network."},
    993: {"name": "IMAPS", "use": "Secure IMAP. Configure email client for encrypted email access."},
    995: {"name": "POP3S", "use": "Secure POP3. Configure email client for encrypted email download."},
    1433: {"name": "MS SQL Server", "use": "Database server. Connect with SQL Server Management Studio or sqlcmd to manage databases."},
    1521: {"name": "Oracle DB", "use": "Oracle database. Connect with SQL*Plus or Oracle SQL Developer for database operations."},
    2049: {"name": "NFS", "use": "Network File System. Mount remote Linux/Unix filesystems with mount command."},
    3306: {"name": "MySQL", "use": "MySQL database. Connect with MySQL Workbench or mysql command line client."},
    3389: {"name": "RDP", "use": "Remote Desktop. Use mstsc.exe (Remote Desktop Connection) for Windows GUI access."},
    5060: {"name": "SIP", "use": "VoIP signaling. Used by VoIP phones and softphones for call setup."},
    5432: {"name": "PostgreSQL", "use": "PostgreSQL database. Connect with pgAdmin or psql command line for database operations."},
    5900: {"name": "VNC", "use": "Remote desktop. Use VNC viewer (RealVNC, TightVNC) for graphical remote access."},
    6379: {"name": "Redis", "use": "In-memory database. Connect with redis-cli for key-value data operations and caching."},
    8080: {"name": "HTTP Alternate", "use": "Alternative web server port. Access via web browser or curl for web services and proxies."},
    8443: {"name": "HTTPS Alternate", "use": "Alternative secure web port. Access via web browser for secure web services."},
    9090: {"name": "Web Admin", "use": "Common web administration panel. Access via browser for various admin interfaces."},
    27017: {"name": "MongoDB", "use": "NoSQL database. Connect with MongoDB Compass or mongo shell for document database operations."},
}

def validate_ip(ip_address):
    """Validate if the IP address format is correct"""
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False

def check_nmap_installed():
    """Check if nmap is installed on the system"""
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def run_nmap_scan(target_ip):
    """Run nmap scan on the target IP"""
    print(f"\n{Fore.CYAN}[*] Starting nmap scan on {target_ip}...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] This may take a minute...{Style.RESET_ALL}\n")
    
    try:
        # Run nmap with service detection
        result = subprocess.run(
            ["nmap", "-sV", "-T4", target_ip],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}[!] Scan timed out. Target may be unresponsive.{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Error running nmap: {e}{Style.RESET_ALL}")
        return None

def parse_nmap_output(nmap_output):
    """Parse nmap output and extract open ports"""
    open_ports = []
    
    # Regex to match port lines
    port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?'
    
    for line in nmap_output.split('\n'):
        match = re.search(port_pattern, line)
        if match:
            port_num = int(match.group(1))
            protocol = match.group(2)
            service = match.group(3)
            version = match.group(4).strip() if match.group(4) else ""
            
            open_ports.append({
                'port': port_num,
                'protocol': protocol,
                'service': service,
                'version': version,
                'risky': port_num in RISKY_PORTS
            })
    
    return open_ports

def get_output_path():
    """Get output file path from user"""
    print(f"\n{Fore.CYAN}[*] Output File Configuration{Style.RESET_ALL}")
    save_to_file = input(f"{Fore.YELLOW}Save results to file? (y/n): {Style.RESET_ALL}").strip().lower()
    
    if save_to_file != 'y':
        return None
    
    folder_path = input(f"{Fore.YELLOW}Enter folder path (press Enter for current directory): {Style.RESET_ALL}").strip()
    
    if not folder_path:
        folder_path = os.getcwd()
    
    if not os.path.exists(folder_path):
        print(f"{Fore.RED}[!] Folder does not exist. Using current directory.{Style.RESET_ALL}")
        folder_path = os.getcwd()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"nmap_scan_{timestamp}.txt"
    full_path = os.path.join(folder_path, filename)
    
    print(f"{Fore.GREEN}[+] Output will be saved to: {full_path}{Style.RESET_ALL}")
    return full_path

def write_to_file(filepath, target_ip, open_ports):
    """Write scan results to file"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write(f"NMAP PORT SCAN RESULTS\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target IP: {target_ip}\n")
            f.write("="*70 + "\n\n")
            
            if not open_ports:
                f.write("No open ports detected or host is down.\n")
                return
            
            f.write(f"Total Open Ports: {len(open_ports)}\n\n")
            
            # Write all open ports summary
            f.write("-"*70 + "\n")
            f.write(f"{'PORT':<10} {'PROTOCOL':<12} {'SERVICE':<15} {'STATUS'}\n")
            f.write("-"*70 + "\n")
            
            risky_count = 0
            for port_info in open_ports:
                port_str = f"{port_info['port']}/{port_info['protocol']}"
                status = "[RISKY]" if port_info['risky'] else "[SAFE]"
                if port_info['risky']:
                    risky_count += 1
                f.write(f"{port_str:<10} {port_info['protocol']:<12} {port_info['service']:<15} {status}\n")
            
            # Write detailed port information
            f.write("\n" + "="*70 + "\n")
            f.write("DETAILED PORT INFORMATION\n")
            f.write("="*70 + "\n\n")
            
            for port_info in open_ports:
                f.write(f"Port {port_info['port']}/{port_info['protocol']} - {port_info['service']}\n")
                f.write("-"*70 + "\n")
                
                if port_info['version']:
                    f.write(f"Version: {port_info['version']}\n")
                
                # Get port description
                port_desc = PORT_DESCRIPTIONS.get(port_info['port'])
                if port_desc:
                    f.write(f"Service: {port_desc['name']}\n")
                    f.write(f"Usage: {port_desc['use']}\n")
                else:
                    f.write(f"Service: {port_info['service']}\n")
                    f.write(f"Usage: Standard {port_info['service']} service\n")
                
                # Write risk information
                if port_info['risky']:
                    risk_desc = RISKY_PORTS.get(port_info['port'], "Unknown risk")
                    f.write(f"WARNING RISK: {risk_desc}\n")
                
                f.write("\n")
            
            # Write risky ports summary
            if risky_count > 0:
                f.write("="*70 + "\n")
                f.write(f"WARNING RISKY PORTS SUMMARY: {risky_count} risky port(s) detected\n")
                f.write("="*70 + "\n\n")
                
                for port_info in open_ports:
                    if port_info['risky']:
                        risk_desc = RISKY_PORTS.get(port_info['port'], "Unknown risk")
                        f.write(f"- Port {port_info['port']}/{port_info['protocol']}: {risk_desc}\n")
            else:
                f.write("="*70 + "\n")
                f.write("SUCCESS: No commonly risky ports detected.\n")
                f.write("="*70 + "\n")
        
        print(f"\n{Fore.GREEN}[+] Results saved to: {filepath}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error writing to file: {e}{Style.RESET_ALL}")

def display_results(target_ip, open_ports):
    """Display scan results with risk assessment"""
    print(f"\n{'='*70}")
    print(f"{Fore.GREEN}SCAN RESULTS FOR: {target_ip}{Style.RESET_ALL}")
    print(f"{'='*70}\n")
    
    if not open_ports:
        print(f"{Fore.YELLOW}[*] No open ports detected or host is down.{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}Total Open Ports: {len(open_ports)}{Style.RESET_ALL}\n")
    
    # Display all open ports summary
    print(f"{Fore.CYAN}{'PORT':<10} {'PROTOCOL':<12} {'SERVICE':<15} {'VERSION'}{Style.RESET_ALL}")
    print("-" * 70)
    
    risky_count = 0
    for port_info in open_ports:
        port_str = f"{port_info['port']}/{port_info['protocol']}"
        
        if port_info['risky']:
            risky_count += 1
            print(f"{Fore.RED}{port_str:<10}{Style.RESET_ALL} ", end="")
        else:
            print(f"{Fore.GREEN}{port_str:<10}{Style.RESET_ALL} ", end="")
        
        print(f"{port_info['protocol']:<12} {port_info['service']:<15} {port_info['version']}")
    
    # Display detailed port information
    print(f"\n{'='*70}")
    print(f"{Fore.CYAN}DETAILED PORT INFORMATION{Style.RESET_ALL}")
    print(f"{'='*70}\n")
    
    for port_info in open_ports:
        # Header for each port
        if port_info['risky']:
            print(f"{Fore.RED}Port {port_info['port']}/{port_info['protocol']} - {port_info['service']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}Port {port_info['port']}/{port_info['protocol']} - {port_info['service']}{Style.RESET_ALL}")
        
        print("-" * 70)
        
        if port_info['version']:
            print(f"  Version: {port_info['version']}")
        
        # Get and display port description
        port_desc = PORT_DESCRIPTIONS.get(port_info['port'])
        if port_desc:
            print(f"  Service: {port_desc['name']}")
            print(f"  {Fore.CYAN}What you can do:{Style.RESET_ALL} {port_desc['use']}")
        else:
            print(f"  Service: {port_info['service']}")
            print(f"  {Fore.CYAN}What you can do:{Style.RESET_ALL} Standard {port_info['service']} service operations")
        
        # Display risk information
        if port_info['risky']:
            risk_desc = RISKY_PORTS.get(port_info['port'], "Unknown risk")
            print(f"  {Fore.RED}⚠ RISK:{Style.RESET_ALL} {risk_desc}")
        
        print()
    
    # Display risky ports section
    if risky_count > 0:
        print(f"{'='*70}")
        print(f"{Fore.RED}⚠ RISKY PORTS DETECTED: {risky_count}{Style.RESET_ALL}")
        print(f"{'='*70}\n")
        
        for port_info in open_ports:
            if port_info['risky']:
                risk_desc = RISKY_PORTS.get(port_info['port'], "Unknown risk")
                print(f"{Fore.RED}• Port {port_info['port']}/{port_info['protocol']}:{Style.RESET_ALL} {risk_desc}")
        print()
    else:
        print(f"{'='*70}")
        print(f"{Fore.GREEN}✓ No commonly risky ports detected.{Style.RESET_ALL}")
        print(f"{'='*70}\n")
    
    print(f"{'='*70}\n")

def main():
    print(f"{Fore.CYAN}")
    print("=" * 70)
    print("           NMAP PORT SCANNER - WINDOWS 11")
    print("=" * 70)
    print(f"{Style.RESET_ALL}\n")
    
    # Check if nmap is installed
    if not check_nmap_installed():
        print(f"{Fore.RED}[!] ERROR: nmap is not installed or not in PATH.{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Please install nmap from: https://nmap.org/download.html{Style.RESET_ALL}")
        sys.exit(1)
    
    # Get target IP from user
    target_ip = input(f"{Fore.YELLOW}Enter IP address to scan: {Style.RESET_ALL}").strip()
    
    if not target_ip:
        print(f"{Fore.RED}[!] No IP address provided.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Validate IP address
    if not validate_ip(target_ip):
        print(f"{Fore.RED}[!] ERROR: Invalid IP address format.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] The IP address '{target_ip}' is not recognized as a valid IP address.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Please enter a valid IPv4 address (e.g., 192.168.1.1){Style.RESET_ALL}")
        sys.exit(1)
    
    # Get output file path
    output_path = get_output_path()
    
    # Run the scan
    nmap_output = run_nmap_scan(target_ip)
    
    if nmap_output:
        # Parse and display results
        open_ports = parse_nmap_output(nmap_output)
        display_results(target_ip, open_ports)
        
        # Save to file if requested
        if output_path:
            write_to_file(output_path, target_ip, open_ports)
    
    input(f"\n{Fore.CYAN}Press Enter to exit...{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
