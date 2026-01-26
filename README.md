# fkad

![fkad](https://github.com/user-attachments/assets/b1e3375e-75f1-46e2-9616-4c469f9fe5b1)


`fkad` is a small offensive helper script designed for exegol docker containers and pentesting instances. It automates common enumeration and sanity checks and prepares artifacts for follow-up toolkits.

## Quick install & run

```bash
wget https://raw.githubusercontent.com/fkxdr/fkad/refs/heads/main/fkad.sh
chmod +x fkad.sh
./fkad.sh -u <user> -p '<password>' -d <dc-ip/domain.com>
```

<img width="2208" height="1166" alt="screen" src="https://github.com/user-attachments/assets/c5742863-ab7e-400a-a386-f3556759f57c" />

Example:

```bash
./fkad.sh -u pentest1 -p 'Pentestpassword123' -d 10.10.2.13
./fkad.sh -u pentest1 -p 'Pentestpassword123' -d domain.com
```

> [!NOTE]
> The `-d` parameter accepts either a DC IP address or a domain name. If a domain is provided, it will be automatically resolved to the DC IP.

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

> [!NOTE]
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

* [Ghost SPNs - Semperis](https://www.semperis.com/blog/exploiting-ghost-spns-and-kerberos-reflection-for-smb-server-privilege-elevation)
* BloodHound / bloodhound-python
* GriffonAD (for attack path analysis)
* Certipy (ADCS checks)
* krbrelayx (DNS tests)
* [kebrute - ropnop](https://github.com/ropnop/kerbrute)
