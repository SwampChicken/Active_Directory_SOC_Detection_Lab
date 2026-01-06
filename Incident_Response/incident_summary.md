# Incident Summary

## Executive Incident Brief

A phishing-based attack led to compromise of a windows workstation user followed by: malicious PowerShell execution, C2 establishmnet, credential abuse, privilege escalation, persistence, data exfiltration, and defense evasion

This incident let to full AD domain compromise and was detected through Splunk SIEM monitoring.

## 1. Incident Profile
 - **Incident ID:** 2026-01-05-AD-COMPROMISE
 - **Status:** Closed / Resolved
 - **Severity:** Critical
 - **Incident Type:** Unauthorized Access / Data Exfiltration / Persistence
 - **Assigned Analyst:** Adrian Stecuła


## 2. Scope of Compromise
 - **Impacted Hosts:** WIN-10VICTIM (Initial Entry Point), DC-01.soc.lab (Domain Controller)
 - **Impacted Accounts:** soclab\m.victim (Compromised via Phishing/C2), soclab\Administrator (Compromised via Credential Theft), soclab\sql_svc (Targeted via Kerberoasting)

## 3. High-Level Impact Assesment
- **Confidentiality:** HIGH. Sensitive financial data was successfullly exfiltrated via HTTP POST.
- **Integrity:** HIGH. Attacker Modified Active Directory group memberships and installed a persistent system service.
- **Availability:** LOW. No systems were taken offline, but installation of a crypto-miner suggests resource hijacking.

## 4. Detection Summary
 - **Primary Detection Source:** Splunk SIEM / Sysmon / EventViewer
 - **Initial Trigger:** Malicious Powershell Encoded Command Execution (21:53).
 - **Dwell Time:** The attacker operated for approximately 3 hours and 30minutes from initial access to log wiping.
