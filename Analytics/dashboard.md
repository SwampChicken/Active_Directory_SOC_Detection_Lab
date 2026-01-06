# SOC Analyst View Dashboard

This dashboard was created before the incident and designed to track entire attack lifecycle, from initial brute force attempts to lateral movement and persistence. It allows an analyst to quickly correlate authentication failures with suspicious process executions.

## Key Panels

**Failed Authentication:** Tracks Event ID 4625 to identify brute force attacks.

**Successful Logons:** Monitors interactive and network logons while filtering out system accounts.

**Account and group changes:** Provides real-time visibilty into unauthorized privilege escalations

**Suspicious PowerShell:** Hunts for obfuscated commands and web-based downloads.

**Kerberos Activity:** Highlights potential Kerberoasting by filtering for requests using weak RC4 encryption

**Lateral Movement:** Monitors sysmon event id 3 for connection over sensitive ports like 445(smb) and 5985(winrm).

[View Full Dashboard XML Source Code](./soc_analyst_view.xml)

## Dashboard Visualization
![dashboard 1](../images/dashboard1.png)
![dashboard 2](../images/dashboard2.png)
![dashboard 3](../images/dashboard3.png)
