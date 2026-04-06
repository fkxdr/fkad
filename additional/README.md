# Additional Tooling

`fkmde.ps1` enumerates Microsoft Defender exclusion paths by abusing `MpCmdRun.exe` to scan each subfolder and flagging directories that are silently skipped.

```powershell
fkmde.ps1 <path> [depth]
```
