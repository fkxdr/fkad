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

## Follow-Up Enumeration

For most assessments it makes sense to follow up enumeration on a provided device. This includes, but is not limited to:

- [ ] Pingcastle
- [ ] fkmde - Microsoft Defender
```ps
Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/fkxdr/fkmde/refs/heads/main/fkmde.ps1')
```
- [ ] ScriptSentry - Logonscripts
```
TODO
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
