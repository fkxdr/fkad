# fkad

![fkad screenshot](https://github.com/user-attachments/assets/8fa1fc4b-43c1-4789-8184-0138bd81d0b1)

`fkad` is a small offensive helper script designed for Exegol docker containers and pentesting instances. It automates common enumeration and sanity checks and prepares artifacts for follow-up toolkits.

## Features

* Run BloodHound collector and gather JSON artifacts
* Parse artifacts with GriffonAD 
* LDAP/SMB/MSRPC checks
* Unconstrained Delegation checks
* ADCS/PKI scans via Certipy
* Password policy dumps

## Quick install & run

```bash
wget https://raw.githubusercontent.com/fkxdr/fkad/refs/heads/main/fkad.sh
chmod +x fkad.sh
./fkad.sh -u <user> -p '<password>' -d <dc-ip>
```

Example:

```bash
./fkad.sh -u pentest1 -p 'Pentestpassword123' -d 10.10.2.13
```

## Output / Report

`fkad` creates a timestamped output directory within the workspace:

```
/workspace/fkad_<domain>_YYYYMMDD_HHMMSS
```

Inside you will find:

* `domain_users.txt` - active users enumerated from the domain
* `owned.txt` - single-line credential entry used by GriffonAD (format: `SAM:TYPE:SECRET` for users; computers require hex secret).
* `*.json` - BloodHound JSON files.
* `griffon_output.txt` / `griffon_paths.txt` — GriffonAD results

> When copying the Griffon commands printed in shell, prefer the one with expanded filenames if your shell rejects unexpanded globs.

## Requirements

* `bloodhound-python` (or `bloodhound.py`) for collecting JSONs.
* `ldapsearch`, `nxc` tool (or equivalent SMB/LDAP discovery) installed and in `$PATH`.
* `python3` for running GriffonAD if available.
* Optional: `certipy`, `krbrelayx`, `kerbrute` for extended checks and follow-ups.

## Security / Legal

This tool is for authorized security testing, research, and defensive validation only. Do not use it against systems you do not own or do not have explicit permission to test. The author is not responsible for misuse.

## Credits

Built to glue common AD tooling and automate mundane enumeration tasks:

* BloodHound / bloodhound-python
* GriffonAD (for attack path analysis)
* Certipy (ADCS checks)
* krbrelayx (DNS tests)
* kerbrute (password spraying helper)
