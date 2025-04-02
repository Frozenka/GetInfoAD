#!/usr/bin/env python3
import os
import subprocess
import sys
import argparse
import re
import shutil
from termcolor import colored
from collections import defaultdict

def install_glow_if_missing():
    if not shutil.which("glow"):
        print(colored("✨ 'glow' is not installed. Installing via snap...", "yellow"))
        try:
            subprocess.run("snap install glow", shell=True, check=True)
            print(colored("✅ 'glow' successfully installed.", "green"))
        except subprocess.CalledProcessError:
            print(colored("❌ Failed to install 'glow'. Please install it manually.", "red"))
            sys.exit(1)

def check_env_vars():
    env = {}
    for var in ["IP", "USER", "PASSWORD"]:
        env[var] = os.getenv(var)
    return env

def banner():
    print()
    print(colored("╔" + "═"*58 + "╗", "cyan"))
    print(colored("║       🔍 GetInfoAD - Active Directory (with NXC)        ║", "green", attrs=["bold"]))
    print(colored("╚" + "═"*58 + "╝", "cyan"))
    print()

def show_env(env):
    print(colored("🌐 Environment variables:", "yellow", attrs=["bold"]))
    for key, value in env.items():
        if value:
            display = colored("✅", "green") + f" {key} = " + colored(value, "cyan")
        else:
            display = colored("❌", "red") + f" {key} is not set"
        print("   " + display)
    print()

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, executable="/bin/bash", check=True, capture_output=True, text=True)
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
    command = '''nxc smb $IP -u $USER -p $PASSWORD --users | awk '/^SMB/ && $5 !~ /^([-]|DefaultAccount|WDAGUtilityAccount|Guest|krbtgt|-Username-|\[\*\]|\[\+\])$/ { print $5 }' '''
    print(colored("▶️  Retrieving domain users...", "cyan"))
    return sorted(set(run_command(command)))

def get_machines(with_versions=False):
    command = '''nxc smb $IP -u $USER -p $PASSWORD'''
    print(colored("▶️  Retrieving computeurs...", "cyan"))
    lines = run_command(command)
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
    print(colored("▶️  Retrieving domain groups...", "cyan"))
    lines = run_command(command)
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
    print(colored("▶️  Retrieving logged-on users...", "cyan"))
    lines = run_command(command)
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
    print(colored("▶️  Retrieving network interfaces...", "cyan"))
    lines = run_command(command)
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
    print(colored("▶️  Retrieving password policy...", "cyan"))
    lines = run_command(command)
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
    result = run_command(command)
    for line in result:
        match = re.search(r'\(domain:([^)]+)\)', line)
        if match:
            return match.group(1).strip()
    return "UnknownDomain.local"

def full_report():
    domain = get_domain_name()
    print(colored(f"📘 Generating report for domain {domain}...", "cyan"))

    users = get_users()
    machines = get_machines()
    machines_os = get_machines(with_versions=True)
    groups = get_groups()
    loggedon = get_loggedon_users()
    interfaces = get_interfaces()
    passpol = get_passpol()

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
        md.append("## 👨‍💻 Logged-on Users")
        for host, info in loggedon.items():
            md.append(f"### Logged-on {host} ({info['ip']})")
            if info["users"]:
                for user in info["users"]:
                    md.append(f"- {user}")
            else:
                md.append("_No users currently logged on._")
        md.append("")

    if interfaces:
        md.append("## 🌐 Network Interfaces\n```")
        md.extend(interfaces)
        md.append("```\n")

    if passpol:
        md.append("## 🔐 Password Policy\n```")
        md.extend(passpol)
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
    args = parser.parse_args()

    # Default to --full if no args provided
    if not any(vars(args).values()):
        args.full = True

    install_glow_if_missing()
    banner()
    env = check_env_vars()
    show_env(env)

    if None in env.values():
        print(colored("💡 Please define all required environment variables before running this script.", "yellow", attrs=["bold"]))
        print(colored("Exemple : exegol-history add creds -u 'MyUser' -p 'Password123' ; exegol-history apply creds", "cyan"))
        sys.exit(1)

    if args.users:
        results = get_users()
        print("\n".join(results))
        ask_to_save(results, "users.txt")

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
