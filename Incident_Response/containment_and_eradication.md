# Containment and Eradication

## Objective

Goal of this phase is to contain the threat, prevent further attacker activity, remove persistence mechanisms and restore the environment to trusted state.
All Actions below represent recommended incident response steps in a real SOC environment, no EDR solution was used in this scenario.

## 1. Immediate Containment Actions

 - Initially compromised workstation (WIN10-VICTIM) should be isolated from the network to prevent further c2 communication and lateral movement.
 - Block Attacker Infrastructure - Implement firewall rules to block all traffic to and from IP 192.168.33.33 and monitor for any attempts to connect to port 4444.
 - Immadiately disable soclab\m.victim, soclab\Administrator, and unauthorized soclab\svc_backup accounts.

## 2. Containment of Lateral Movement
 - Review and revert all recent changes to Domain Admins and local Administrators groups.
 - Force a password reset for soclab\sql_svc account to invalidate any tickets obtained by Kerberoasting, perform double rotation of KRBTGT account password to invalidate all active kerberos tickets across the domain.

## 3. Eradication of Persistence Mechanisms
 - Delete WinCryptoMIner service from domain controller using sc.exe delete.
 - Delete svc_backup account created by attacker
 - Scan all domain systems for unauthorized scheduled tasks, registry run keys or new local user accounts created during attacker's dwell time.

## 4. Malware and Artifact Removal
 - Remove all malicious PowerShell scripts and finance_leak.zip archive from local drives.
 - Securely delete passwords.txt file from m.victim desktop and conduct a scan for other plaintext credential files in entire environment.
 - Reimagee WIN-10VICTIM to ensure no hidden persistence or secondary payloads remain on the host.

## 5. Recovery and Hardening
 - Enforce mandatory password change for all administrative and service accounts using strong, unique passwords.
 - Deploy Microsoft LAPS to manage local administrator passwords, preventing the reuse of credentials across the domain.
 - Recommend implementation of MFA for all privileged accoutns to mitigate the impact ofr future credential theft.

## 6. Monitoring and Validation
 - Maintain high-verbosity logging for PowerShell Script Block Logging and Sysmon process creation.
 - Monitor Splunk for any recurring Kerberos RC4 ticket requests or unauthorized group modifications
 - Verify that no new outbound connections to C2 IP or unauthorized administrative logons occur within next 48 hours

## Incident Closure Criteria

Incident will be considered resolved once all persistence mechanisms are removed, all compromised credentials are reset and environment is validated as clean through 48 hours of continous monitoring without further alerts.
