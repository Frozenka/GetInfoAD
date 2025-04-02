# GetInfoAD

**GetInfoAD** is a fast and flexible Active Directory enumeration tool built around [NXC](https://github.com/microfrosty/nxc). It was designed primarily for use with [Exegol](https://github.com/ShutdownRepo/Exegol) and integrates seamlessly with its credential and environment variable management.

## Features

- List domain users
- Enumerate domain machines and their operating systems
- Retrieve LDAP domain groups
- Detect currently logged-on users on each host
- Get network interface information per machine
- Dump password policy
- Generates a clear Markdown report (`report.md`)

## Requirements

- Python 3.x
- `nxc` binary available in `$PATH`

## Installation
### Quick Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/Frozenka/GetInfoAD/main/setup.sh | sudo bash
```

This script will:
- Clone the tool to `/opt/getinfoad`
- Make it executable
- Add an alias `getinfoAD='python3 /opt/getinfoad/getinfoAD.py -f'` to your `.bashrc`
- Install required Python packages 

After installation:
```bash
source ~/.bashrc
getinfoAD
```

### Manual Installation
```bash
git clone https://github.com/Frozenka/GetInfoAD.git /opt/getinfoad
chmod +x /opt/getinfoad/getinfoAD.py
echo "alias getinfoAD='python3 /opt/getinfoad/getinfoAD.py -f'" >> ~/.bashrc
source ~/.bashrc
```

## Usage

Run the tool with full report mode:
```bash
getinfoAD
```

Other options:
```bash
 getinfoAD.py -u         # List users
 getinfoAD.py -m         # List machines
 getinfoAD.py -o         # List machines with OS
 getinfoAD.py --groups   # List LDAP groups
```

Example with Exegol:
```bash
exegol-history add creds -u 'user' -p 'password'
exegol-history apply creds
export IP=10.129.205.0/24
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
