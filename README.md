# GetInfoAD
**GetInfoAD** is a fast and flexible Active Directory enumeration tool built around [NXC](https://github.com/microfrosty/nxc). It was designed primarily for use with [Exegol](https://github.com/ShutdownRepo/Exegol) and integrates seamlessly with its credential and environment variable management.

![image](https://github.com/user-attachments/assets/502c9873-c7ae-47be-8430-5a5af9dfc3c9)

## Features
- List domain users
- Enumerate domain machines and their operating systems
- Retrieve LDAP domain groups
- Detect currently logged-on users on each host
- Get network interface information per machine
- Dump password policy
- Generates a clear Markdown report (report.md)
- Perform AS-REP Roasting to extract hashes
- Crack AS-REP hashes 

![Enregistrement 2025-04-02 104050-VEED](https://github.com/user-attachments/assets/116892ab-a658-448a-ae9f-b3df71b6cbbe)

## Usage
Run the tool with full report mode:
```bash
getinfoAD
```

Other options:
```bash
 getinfoAD -u         # List users
 getinfoAD -m         # List machines
 getinfoAD -o         # List machines with OS
 getinfoAD --groups   # List LDAP groups
 getinfoAD -a         # Asreproasting + crack
```

## Requirements
- Exegol

## Installation
### Quick Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/Frozenka/GetInfoAD/main/setup.sh | sudo bash
```

This script will:
- Clone the tool to `/opt/getinfoad`
- Make it executable
- Add an alias `getinfoAD='python3 /opt/getinfoad/getinfoAD.py '

After installation:
```bash
getinfoAD
```

### Manual Installation
```bash
git clone https://github.com/Frozenka/GetInfoAD.git /opt/getinfoad
chmod +x /opt/getinfoad/getinfoAD.py
echo "alias getinfoAD='python3 /opt/getinfoad/getinfoAD.py '"
source ~/.bashrc
```

Example with Exegol:
```bash
exegol-history add creds -u 'user' -p 'password'
exegol-history apply creds
getinfoAD
```

## Output Example (excerpt)
```
## 👤 Domain Users
adam.jones
annette.jackson
...

## 💻 Domain Machines
DC01
WS01

## 📊 Operating Systems
DC01  — Windows Server 2019
WS01  — Windows Server 2019

## 👨‍💻 Logged-on Users
### Logged-on WS01 (10.129.205.26)
INLANEFREIGHT\jefferson.matts
```
