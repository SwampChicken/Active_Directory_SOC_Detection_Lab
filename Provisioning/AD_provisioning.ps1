 
<#
.SYNOPSIS
    Active Directory SOC Lab Environment Provisioning Script.

.DESCRIPTION
    This script automates the creation of the SOC_Lab Organizational Unit
    and initializes specific user accounts designed for security monitoring
    and attack simulation (Phishing, Kerberoasting, Privilege Escalation).
#>

$domainDN = "DC=soclab"
$ouName = "SOC_Lab"
$ouPath = "OU=$ouName,$domainDN"

$commonPassword = ConvertTo-SecureString "REDACTED_COMMON_PASSWORD" -AsPlainText -Force
$adminPassword = ConvertTo-SecureString "REDACTED_ADMIN_PASSWORD" -AsPlainText -Force

if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'")) {
    Write-Host "[+] Creating OU: $ouName" -ForegroundColor Green
    New-ADOrganizationalUnit -Name $ouName -Path $domainDN
}

function New-SOCUser {
    param($SamName, $DisplayName, $UPN, $Password, $Description)

    if (-not (Get-ADUser -Filter "SamAccountName -eq '$SamName'")) {
        New-ADUser -Name $DisplayName `
                   -SamAccountName $SamName `
                   -UserPrincipalName $UPN `
                   -Path $ouPath `
                   -AccountPassword $Password `
                   -Enabled $true `
                   -Description $Description
    } else {
        Write-Host "User $SamName already exists."
    }
}

New-SOCUser -SamName "m.victim" -DisplayName "Mark Victim" -UPN "m.victim@soclab" -Password $commonPassword -Description "Standard User for Phishing Scenarios"

New-SOCUser -SamName "t.admin" -DisplayName "Thomas Admin" -UPN "t.admin@soclab" -Password $adminPassword -Description "Domain Admin for Post-Exploitation Scenarios"

New-SOCUser -SamName "sql_svc" -DisplayName "SQL Service" -UPN "sql_svc@soclab" -Password $commonPassword -Description "Service Account for Kerberoasting Scenarios"

Add-ADGroupMember -Identity "Domain Admins" -Members "t.admin" -ErrorAction SilentlyContinue

setspn -A MSSQLSvc/sqlserver.soclab:1433 sql_svc
