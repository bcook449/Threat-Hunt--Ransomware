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
