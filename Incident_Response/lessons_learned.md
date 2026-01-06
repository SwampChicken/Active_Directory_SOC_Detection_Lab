# Lessons Learned

This document outlines the key takeaways to prevent recurrence and improve future detection capabilities.

## 1. Key Vulnerabilities Identified
 - Plaintext Credential Storage - discovery of passwords.txt led to domain-wide escalation
 - Weak Kerberos Encryption - environment allowed RC4 encryption for Kerberos tickets making it vulnerable to Kerberoasting attacks.
 - Lack of LAPS - reuse of local administrator credentials allowed for easier lateral movement once initial account was compromised

## 2. Detection Performance Evaluation
 - **Successes:**
    - Powershell Telemetry - sysmon and script block logging were crucial in identifying c2 channel and exfiltation attempt.
    - High-Fidelity alerting - preconfigured alerts for event id 1102 (Log Wiping) and 4732 (Privileged Group Changes) provided immediate notification of critical attacker actions.
 - **Gaps:**
    - Dashboard Misconfiguration - primary SOC dashboard failed to correlate multi-stage attack effecitvely forcing reliance on manual SPL hunting.
    - Alerts misconfiguration - some alerts had gaps in their configuration and didnt detect suspicious activities

## 3. Hardening
 - Implement LAPS
 - Conduct security awareness training focusing on risks of storing passwords in unencrypted local files
 - Disable RC4 encryption for Kerberos and enforce AES256 to mitigate Kerberoasting risks
 - Update SOC dashboard to include kill chain visualization
 - Tune up alert rules so they detect more suspicious actions

## 4. Conclusion

While detection mechanisms successfullly captured attacker's TTPs, this incident shows that visibility is only as good as analyst's ability to act on it, transition from misconfigured dashboard to manual investigation was deciding factor in resolving this case.
