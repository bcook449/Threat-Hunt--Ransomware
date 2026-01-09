# Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- Microsoft Sentinel
- Kusto Query Language (KQL)

##  Scenario
<img width="1469" height="987" alt="image" src="https://github.com/user-attachments/assets/5fd5a913-270d-47c0-82d9-162edd13abdd" />

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table
Searched for any indicators of the threat actor using SSH to pivot to critical infrastructure and eliminate recovery options before ransomware was deployed. It was discovered that on `2025-11-25T05:39:10.889728Z`, the attacker pivoted to the backup-admin PC at 10.1.0.189. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "ssh"
| sort by TimeGenerated asc 
| project TimeGenerated, DeviceName, ProcessCommandLine
```
<img width="2005" height="93" alt="image" src="https://github.com/user-attachments/assets/9ebcf31f-a3ba-4ffa-912d-8e371d9f6413" />

### 2. Searched the `DeviceLogonEvents` Table 
Searched for any logon attempts and any artifacts of anyone tyring to access the backup server to establish where the attack originated. On `2025-11-25T05:39:22.191096Z`, 10.1.0.108 successfully logged on to the backup server under the backup-admin account. 

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName contains "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where LogonType == "Network"
| sort by TimeGenerated asc 
| project TimeGenerated, AccountDomain, AccountName, ActionType, RemoteIP
```
<img width="2598" height="80" alt="image" src="https://github.com/user-attachments/assets/1aa03c8b-e943-48cf-8874-bc62fd5a85ce" />

### 3. Searched the  `DeviceProcessEvents` Table

Searched for any indication that the file system was enumerated by the threat actor. On `2025-11-24T14:13:34.757374Z`, the threat actor listed the backups under the backup-admin account. On `2025-11-24T14:16:06.546964Z`, the backup archives were also found and accessed by the threat actor. The attacker also enumerated local accounts on `2025-11-24T14:16:08.673485Z`, with evidence to follow.

**Queries used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where FileName == "ls"
| sort by TimeGenerated asc 
| project  TimeGenerated, AccountDomain, AccountName, ProcessCommandLine
```
<img width="2111" height="65" alt="image" src="https://github.com/user-attachments/assets/ceda270b-2854-4e01-86a3-1f520f9b1275" />

```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where FileName == "find"
| sort by TimeGenerated asc 
| project TimeGenerated, AccountDomain, AccountName, ProcessCommandLine
```
<img width="2106" height="71" alt="image" src="https://github.com/user-attachments/assets/2b58980d-e7fd-4685-90fe-d1173d12ad0b" />

```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where FileName == "cat"
| where ProcessCommandLine contains "/etc/passwd"
| project TimeGenerated, InitiatingProcessAccountName, ProcessCommandLine
```
<img width="1860" height="86" alt="image" src="https://github.com/user-attachments/assets/2daf8135-ae71-46df-a104-a061a7a09089" />


