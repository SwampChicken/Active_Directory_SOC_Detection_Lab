# Active Directory SOC Detection Lab

## Overview

This project simulates a real-world security incident in a Windows Active Directory environment from a SOC Analyst perspective.

The scenario focuses on detection, investigation, and incident response to a phishing-based attack that resulted in:
- Initial user compromise
- Malicious PowerShell execution
- Command and Control communication
- Credential abuse and privilege escalation
- Persistence mechanisms
- Data exfiltration
- Log tampering for defense evasion

All activity was centrally logged and analyzed using Splunk, allowing full reconstruction of the attack timeline and evaluation of detection coverage.

## Lab Architecture

The lab environment was designed to be similar to a small enterprise Active Directory setup monitored by a centralized SIEM.

- **Domain Controller:** Windows Server 2022 VM
- **Workstation** Windows 10 VM (initially compromised via phishing)
- **Attacker Machine:** Kali Linux VM
- **SIEM:** Splunk Enterprise running on the host machine
- **Telemetry**:
    -  Wndows Security Event Logs
    -   Sysmon
- **Networking:** Virtual machines were connected using Bridged networking, allowing them to communicate directly with each other and the host machine.
