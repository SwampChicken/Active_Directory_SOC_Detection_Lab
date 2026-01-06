# List of created alerts before the incident occurred

## Brute Force Detection

SPL:
```
index=wineventlog EventCode=4625
| stats count by TargetUserName, IpAddress
| where count >= 5
```

Detects multiple failed login attempts against a single account.

## Brute Force Followed by Successful Logon

SPL:
```
index=wineventlog (EventCode=4624 OR EventCode=4625)
| stats 
    count(eval(EventCode=4625)) as failures, 
    count(eval(EventCode=4624)) as success,
    earliest(_time) as start, 
    latest(_time) as end 
    by IpAddress, TargetUserName
| where failures >= 5 AND success > 0 AND end > start
| table IpAddress, TargetUserName, failures, success
```

Correlates series of failed logins with a sudden success from the same IP, strongly suggests a successful account takeover.

## Defense Evasion - log wiping

SPL:
```
index="wineventlog" EventCode=1102
| table _time, Computer, SubjectUserName, SubjectDomainName

```

Detects attempts to clear windows security event log.

## Discovery Commands Detection

SPL:
```
index="wineventlog" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*ipconfig*" OR CommandLine="*systeminfo*" OR CommandLine="*net group*"
| table _time, host, User, Image, CommandLine, ParentImage
```

Monitors for reconnaissance commands that are typically used by attackers immediately after gaining acccess.

## Identity or Group Modification

SPL:
```
index="wineventlog" EventCode IN (4720, 4724, 4728, 4732)
| eval Activity=case(
    EventCode=4720, "New account created",
    EventCode=4724, "User Password Reset",
    EventCode=4728, "Member Added to Global Group",
    EventCode=4732, "Member Added to Local Group")
| table _time, Activity, SubjectUserName, TargetUserName, Group_Name
| sort -_time
```

Tracks Critical changes to users and groups.

## Malicious PowerShell Command Detected

SPL:
```
index="wineventlog" source="*Sysmon/Operational" EventCode=1 
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\powershell_ise.exe")
| where match(CommandLine, "(?i)(-enc|base64|IEX|DownloadString|WebClient|Invoke-Shellcode|BitTransfer)")
| table _time, host, User, Image, CommandLine
| sort -_time
```

Searches for PowerShell activity involving encoded commands or web downloads.

## New Scheduled Task Created

SPL:
```
index="wineventlog" EventCode=4698 
| xmlkv
| search NOT TaskName="\\CreateExplorerShellUnelevatedTask"
| table _time, host, TaskName, Author, Command
```

Detects creation of new scheduled tasks.

## Suspicious Kerberos RC4 Ticket Request

SPL:
```
index="wineventlog" EventCode=4769 TicketOptions="0x40810000" TicketEncryptionType="0x17"
| xmlkv
| table _time, host, TargetUserName, ServiceName, IpAddress, TicketEncryptionType
```

Detects Kerberoasting attempts by looking ofr service ticket requests using weak RC4 encryption.
