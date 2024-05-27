from scapy.all import *
import os
import socket
import subprocess
import threading
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import box
import re
import subprocess

console = Console()

# Function to print the ASCII art banner for "Firewall"
def print_banner():
    banner_text = """
______  _____ ______  _____  _    _   ___   _      _
|  ___||_   _|| ___ \|  ___|| |  | | / _ \ | |    | |
| |_     | |  | |_/ /| |__  | |  | |/ /_\ \| |    | |
|  _|    | |  |    / |  __| | |/\| ||  _  || |    | |
| |     _| |_ | |\ \ | |___ \  /\  /| | | || |____| |____
\_|     \___/ \_| \_|\____/  \/  \/ \_| |_/\_____/\_____/
    """
    console.print(banner_text, style="bold purple")

# Function to resolve a domain to an IP address
def resolve_domain(domain):
    process = subprocess.run(['dig', '+short', domain], capture_output=True, text=True)
    ip_addresses = process.stdout.strip().split('\n')
    return ip_addresses[0] if ip_addresses else None

# Function to get the local IP address
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# Automatically detect the IP to monitor
target_ip = get_local_ip()
blocked_ips = {}
stop_sniffer = threading.Event()

# Initialize the stop event for the sniffer thread
stop_sniffer = threading.Event()

def block_ip(ip, domain=None):
    if ip not in blocked_ips:
        blocked_ips[ip] = domain
        command = f"iptables -A INPUT -s {ip} -j DROP"
        os.system(command)
        domain_info = f" ({domain})" if domain else ""
        console.print(f"\n[bold red][*][/bold red] Blocked IP [bold red]{ip}[/bold red]{domain_info}")

def unblock_ip(ip):
    if ip in blocked_ips:
        domain = blocked_ips[ip]
        del blocked_ips[ip]
        command = f"iptables -D INPUT -s {ip} -j DROP"
        os.system(command)
        domain_info = f" ({domain})" if domain else ""
        console.print(f"\n[bold green][*][/bold green] Unblocked IP [bold green]{ip}[/bold green]{domain_info}")

def display_blocked_ips():
    table = Table(title="\nBlocked IPs", title_style="bold red", box=box.SQUARE_DOUBLE_HEAD)
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("Domain", style="red", no_wrap=True)

    for ip, domain in blocked_ips.items():
        domain_display = domain if domain else "N/A"
        table.add_row(ip, domain_display)

    console.print(table)

def packet_callback(packet):
    if stop_sniffer.is_set():
        return

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # Default values for ports
        src_port = dst_port = "N/A"
        proto = None

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            proto = 'TCP'
            # Checking for HTTP and HTTPS based on port numbers
            if src_port == 80 or dst_port == 80:
                proto = 'HTTP'
            elif src_port == 443 or dst_port == 443:
                proto = 'HTTPS'
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            proto = 'UDP'
        elif ICMP in packet:
            proto = 'ICMP'
        elif ARP in packet:
            proto = 'ARP'
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst

        pkt_len = len(packet)
        ttl = packet[IP].ttl

        # Initially, not a blocked packet
        blocked_packet = False
        style = "bold yellow"

        # Check if the IP is in the blocked IPs list
        if src_ip in blocked_ips or dst_ip in blocked_ips:
            blocked_packet = True
            style = "red"

        # Check against user rules
        for rule in user_rules:
            if rule["action"] == "block":
                rule_proto = rule["protocol"] if rule["protocol"] != "" else proto
                match_src_ip = (src_ip == rule["src_ip"] or rule["src_ip"] == "")
                match_dst_ip = (dst_ip == rule["dst_ip"] or rule["dst_ip"] == "")
                match_src_port = (str(src_port) == rule["src_port"] or rule["src_port"] == "")
                match_dst_port = (str(dst_port) == rule["dst_port"] or rule["dst_port"] == "")
                match_proto = (proto == rule_proto or rule_proto is None)

                if match_src_ip and match_dst_ip and match_src_port and match_dst_port and match_proto:
                    blocked_packet = True
                    style = "red"
                    break  # No need to check other rules if one is matched

        console.print(f"[*] [bold {style}]Source IP:[/bold {style}] {src_ip}, [bold {style}]Destination IP:[/bold {style}] {dst_ip}, [bold {style}]Protocol:[/bold {style}] {proto} [bold {style}]Source Port:[/bold {style}] {src_port}, [bold {style}]Destination Port:[/bold {style}] {dst_port} [bold {style}]Packet Length:[/bold {style}] {pkt_len}, [bold {style}]TTL:[/bold {style}] {ttl}")



def add_rule():
    src_ip = Prompt.ask("\nEnter Source IP (leave empty for any)", default="")
    dst_ip = Prompt.ask("Enter Destination IP (leave empty for any)", default="")
    src_port = Prompt.ask("Enter Source Port (leave empty for any)", default="")
    dst_port = Prompt.ask("Enter Destination Port (leave empty for any)", default="")
    protocol = Prompt.ask("Enter Protocol ", choices=["TCP", "UDP", "ICMP", "HTTP", "HTTPS"], default="TCP")
    action = Prompt.ask("Enter Action (allow/block)", choices=["allow", "block"], default="allow")

    rule = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol.upper(),
        "action": action
    }

    return rule

user_rules = []

def apply_rule(rule):

    global user_rules

    cmd = ["iptables", "-A", "INPUT"]

    if rule["action"] == "allow":
        action_cmd = "-jACCEPT"
    else:
        action_cmd = "-jDROP"

    if rule["src_ip"]:
        cmd.extend(["-s", rule["src_ip"]])

    if rule["dst_ip"]:
        cmd.extend(["-d", rule["dst_ip"]])

    if rule["src_port"]:
        cmd.extend(["--sport", rule["src_port"]])

    if rule["dst_port"]:
        cmd.extend(["--dport", rule["dst_port"]])

    if rule["protocol"] == "TCP":
        cmd.extend(["-p", "tcp"])
    elif rule["protocol"] == "UDP":
        cmd.extend(["-p", "udp"])
    elif rule["protocol"] == "ICMP":
        cmd.extend(["-p", "icmp"])
    elif rule["protocol"] == "HTTP":
        cmd.extend(["-p", "tcp", "--dport", "80"])
    elif rule["protocol"] == "HTTPS":
        cmd.extend(["-p", "tcp", "--dport", "443"])

    cmd.extend([action_cmd])

    subprocess.run(cmd)

    user_rules.append(rule)

    console.print(f"\n[bold green]Rule added successfully:[/bold green]\n{rule}")

def display_user_rules():
    table = Table(title="\nUser-added Rules", title_style="bold green", box=box.SQUARE_DOUBLE_HEAD)
    table.add_column("Source IP", style="cyan", no_wrap=True)
    table.add_column("Destination IP", style="cyan", no_wrap=True)
    table.add_column("Source Port", style="cyan", no_wrap=True)
    table.add_column("Destination Port", style="cyan", no_wrap=True)
    table.add_column("Protocol", style="cyan", no_wrap=True)
    table.add_column("Action", style="cyan", no_wrap=True)

    for rule in user_rules:
        action_style = "red" if rule["action"] == "block" else "green"
        table.add_row(
            rule["src_ip"],
            rule["dst_ip"],
            rule["src_port"],
            rule["dst_port"],
            rule["protocol"],
            f"[bold {action_style}]{rule['action']}[/bold {action_style}]"
        )


    console.print(table)

def remove_rule():
    if not user_rules:
        console.print("[bold red]No rules to remove.[/bold red]")
        return

    display_user_rules()
    rule_index = Prompt.ask("\nEnter the index of the rule to remove", default="0")

    try:
        rule_index = int(rule_index)
        if 1 <= rule_index <= len(user_rules):
            removed_rule = user_rules.pop(rule_index - 1)
            # Remove the rule from iptables
            cmd = ["iptables", "-D", "INPUT"]

            if removed_rule["src_ip"]:
                cmd.extend(["-s", removed_rule["src_ip"]])

            if removed_rule["dst_ip"]:
                cmd.extend(["-d", removed_rule["dst_ip"]])

            if removed_rule["src_port"]:
                cmd.extend(["--sport", removed_rule["src_port"]])

            if removed_rule["dst_port"]:
                cmd.extend(["--dport", removed_rule["dst_port"]])

            if removed_rule["protocol"] == "TCP":
                cmd.extend(["-p", "tcp"])
            elif removed_rule["protocol"] == "UDP":
                cmd.extend(["-p", "udp"])
            elif removed_rule["protocol"] == "ICMP":
                cmd.extend(["-p", "icmp"])
            elif removed_rule["protocol"] == "HTTP":
                cmd.extend(["-p", "tcp", "--dport", "80"])
            elif removed_rule["protocol"] == "HTTPS":
                cmd.extend(["-p", "tcp", "--dport", "443"])

            if removed_rule["action"] == "allow":
                action_cmd = "-jACCEPT"
            else:
                action_cmd = "-jDROP"

            cmd.extend([action_cmd])

            subprocess.run(cmd)
            
            console.print(f"[bold green]Rule removed successfully:[/bold green]\n{removed_rule}")
        else:
            console.print("[bold red]Invalid rule index.[/bold red]")
    except ValueError:
        console.print("[bold red]Invalid input. Please enter a valid index.[/bold red]")


def start_sniffer():
    global stop_sniffer
    if stop_sniffer.is_set():
        console.print("[bold green]\n[*] Starting packet sniffer...[/bold green]")
        stop_sniffer.clear()
        console.print("[bold green]\n[*] Sniffer Started[/bold green]")
        threading.Thread(target=lambda: sniff(prn=packet_callback, store=0, stop_filter=lambda x: stop_sniffer.is_set())).start()
    else:
        console.print("[bold red]\n[*] Sniffer is already running.[/bold red]")

def stop_sniffer_function():
    global stop_sniffer
    if not stop_sniffer.is_set():
        console.print("[bold green]\n[*] Stopping the sniffer...[/bold green]")
        stop_sniffer.set()
        console.print("[bold green]\n[*] Sniffer Stopped[/bold green]")
    else:
        console.print("[bold red]\n[*] Sniffer is not running.[/bold red]")

stop_sniffer.set()

def user_interface():
    print_banner()
    while True:
        console.print("\n")
        console.print("[bold yellow]1.[/] Start Sniffer", style="bold yellow")
        console.print("[bold yellow]2.[/] Stop Sniffer", style="bold yellow")
        console.print("[bold yellow]3.[/] Block IP or Domain", style="bold yellow")
        console.print("[bold yellow]4.[/] Unblock IP", style="bold yellow")
        console.print("[bold yellow]5.[/] Show Blocked IPs", style="bold yellow")
        console.print("[bold yellow]6.[/] Add Rule", style="bold yellow")
        console.print("[bold yellow]7.[/] Show User-added Rules", style="bold yellow")  # Option to display user-added rules
        console.print("[bold yellow]8.[/] Remove Rule", style="bold yellow")  # Option to remove a user-added rule
        console.print("[bold yellow]9.[/] Exit", style="bold yellow")

        choice = Prompt.ask("\nEnter your choice", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"], default="1")

        if choice == '1':
            start_sniffer()
        elif choice == '2':
            stop_sniffer_function()
        elif choice == '3':
            target = Prompt.ask("\nEnter IP or Domain to block")
            # Check if it's an IP or domain
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
                block_ip(target)
            else:
                ip = resolve_domain(target)
                if ip:
                    block_ip(ip, target)
                else:
                    console.print("[bold red]\nCould not resolve domain.[/bold red]")
        elif choice == '4':
            target = Prompt.ask("\nEnter IP to unblock")
            unblock_ip(target)
        elif choice == '5':
            display_blocked_ips()
        elif choice == '6':
            rule = add_rule()
            apply_rule(rule)
        elif choice == '7':
            display_user_rules()
        elif choice == '8':
            remove_rule()
        elif choice == '9':
            if not stop_sniffer.is_set():
                stop_sniffer.set()
            break
        else:
            console.print("[bold red]\nInvalid choice.[/bold red]")

# Start the user interface
user_interface()
