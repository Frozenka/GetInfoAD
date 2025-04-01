#!/usr/bin/env python3
import os
import subprocess
import sys
import argparse
import re
from termcolor import colored

def check_env_vars():
    env = {}
    for var in ["IP", "USER", "PASSWORD"]:
        env[var] = os.getenv(var)
    return env

def banner():
    print()
    print(colored("╔════════════════════════════════════════════════════╗", "cyan"))
    print(colored("║    🔍 GetInfoAD - Active Directory (with NXC)           ║", "green", attrs=["bold"]))
    print(colored("╚════════════════════════════════════════════════════╝", "cyan"))
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

def warning(mode):
    if mode == "users":
        print(colored("👥 This mode queries SMB to enumerate domain user accounts.", "blue"))
    elif mode == "machines":
        print(colored("🖥️  This mode extracts machine names via SMB on the domain.", "blue"))
    print()

def get_users():
    command = '''nxc smb $IP -u $USER -p $PASSWORD --users | awk '/^SMB/ && $5 !~ /^(DefaultAccount|WDAGUtilityAccount|Guest|krbtgt|-Username-|\\[\\*\\]|\\[\\+\\])$/ { print $5 }' '''
    try:
        print(colored("▶️  Retrieving domain users...\n", "cyan"))
        result = subprocess.run(command, shell=True, executable="/bin/bash", check=True, capture_output=True, text=True)
        users = sorted(set(result.stdout.strip().splitlines()))
        return users
    except subprocess.CalledProcessError as e:
        print(colored("❌ Failed to retrieve users:", "red"))
        print(colored(e.stderr.strip(), "red"))
        sys.exit(1)

def get_machines(with_versions=False):
    command = '''nxc smb $IP -u $USER -p $PASSWORD'''
    try:
        print(colored("▶️  Retrieving computeurs...\n", "cyan"))
        result = subprocess.run(command, shell=True, executable="/bin/bash", check=True, capture_output=True, text=True)
        lines = result.stdout.strip().splitlines()
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
    except subprocess.CalledProcessError as e:
        print(colored("❌ Failed to retrieve machines:", "red"))
        print(colored(e.stderr.strip(), "red"))
        sys.exit(1)

def get_domain_name():
    command = '''nxc smb $IP -u $USER -p $PASSWORD'''
    try:
        result = subprocess.run(command, shell=True, executable="/bin/bash", check=True, capture_output=True, text=True)
        match = re.search(r'\(domain:([^)]+)\)', result.stdout)
        return match.group(1).strip() if match else "UnknownDomain.local"
    except:
        return "UnknownDomain.local"

def ask_to_save(data, default_name):
    choice = input(colored("\n💾 Do you want to save this list to a file? (y/n) > ", "yellow")).strip().lower()
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
        print(colored("📭 List not saved.", "yellow"))

def full_report():
    domain = get_domain_name()
    print(colored(f"📘 Generating report for domain {domain}...\n", "cyan"))

    users = get_users()
    machines = get_machines(with_versions=False)
    machines_os = get_machines(with_versions=True)

    md = []
    md.append(f"# Active Directory Report - {domain}\n")

    md.append(f"## Domain Users\n")
    for user in users:
        md.append(f"- {user}")
    md.append("")

    md.append(f"## Domain Machines\n")
    for host in machines.keys():
        md.append(f"- {host}")
    md.append("")

    md.append(f"## OS\n")
    for host, osinfo in machines_os.items():
        md.append(f"- {host} — {osinfo}")
    md.append("")

    markdown_output = "\n".join(md)
    filename = "report.md"

    try:
        with open(filename, "w") as f:
            f.write(markdown_output + "\n")
        print(colored(f"✅ Report saved to: {filename}", "green", attrs=["bold"]))
        print(colored(f"✨ Opening report...\n", "magenta"))
        os.system(f"glow {filename}")
    except Exception as e:
        print(colored("❌ Error while saving or opening the report:", "red"), e)


def main():
    parser = argparse.ArgumentParser(description="Active Directory enumeration via SMB")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--users", action="store_true", help="List domain users")
    group.add_argument("-m", "--machines", action="store_true", help="List exposed machine names")
    group.add_argument("-o", "--os", action="store_true", help="List machines with their operating system")
    group.add_argument("-f", "--full", action="store_true", help="Show users + machines + OS in Markdown format")
    args = parser.parse_args()

    banner()
    env = check_env_vars()
    show_env(env)

    if None in env.values():
        print(colored("💡 Please define all required environment variables before running this script.", "yellow", attrs=["bold"]))
        print(colored("Exemple : exegol-history add creds -u 'MyUser' -p 'Password123' ; exegol-history apply creds", "cyan"))
        sys.exit(1)

    if args.users:
        warning("users")
        results = get_users()
        print("\n".join(results))
        ask_to_save(results, "users.txt")

    elif args.machines:
        warning("machines")
        results = get_machines()
        print("\n".join(results.keys()))
        ask_to_save(list(results.keys()), "machines.txt")

    elif args.os:
        results = get_machines(with_versions=True)
        print(colored("🧾 Machines with OS:", "cyan"))
        output = [f"{host} — {osinfo}" for host, osinfo in results.items()]
        print("\n".join(output))
        ask_to_save(output, "machines_with_os.txt")

    elif args.full:
        full_report()

if __name__ == "__main__":
    main()
