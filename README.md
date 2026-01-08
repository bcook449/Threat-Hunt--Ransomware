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

