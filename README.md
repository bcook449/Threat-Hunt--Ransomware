# Threat Hunt Report: Ransomware

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

Searched for any indication that the file system was enumerated by the threat actor. On `2025-11-24T14:13:34.757374Z`, the threat actor listed the backups under the backup-admin account. On `2025-11-24T14:16:06.546964Z`, the backup archives were also found and accessed by the threat actor. The attacker also enumerated local accounts on `2025-11-24T14:16:08.673485Z`, with evidence to follow. The attacker also issued a command to reveal scheduled jobs on the system. This occurred on `2025-11-24T14:16:08.703052Z`.

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

  
  ```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine contains "cron"
| where FileName == "cat"
| sort by TimeGenerated asc 
| project  TimeGenerated, AccountDomain, AccountName, ProcessCommandLine
```
<img width="2212" height="72" alt="image" src="https://github.com/user-attachments/assets/f6ee5069-f51d-448c-832e-0bcdbb50414f" />

### 4. Searched the  `DeviceProcessEvents` Table
Searched the DeviceProcessEvents table to inquire whether threat actor downloaded any external tools to assist in their attack. On `2025-11-25T05:45:34.259149Z`, the threat actor utilized the curl command under root priveleges to download an external tool from `hxxps[://]litter[.]catbox[.]moe/io523y[.]7z`.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where FileName == "curl"
| project TimeGenerated, AccountDomain,AccountName, ProcessCommandLine
```
<img width="2558" height="156" alt="image" src="https://github.com/user-attachments/assets/df38c633-9aa0-4eda-956d-f102a6610200" />

### 5. Searched the  `DeviceProcessEvents` Table
On `2025-11-24T14:14:14.217788Z`, the threat actor was able access user credentials in a text file via the backup server, continuing to utilize the backup-admin priveleges. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where FileName == "cat"
| where ProcessCommandLine endswith ".txt"
| project TimeGenerated, AccountName, AccountDomain, DeviceName, ProcessCommandLine
```
<img width="2833" height="220" alt="image" src="https://github.com/user-attachments/assets/9d369cdb-d539-4ebe-b2bc-3d795e673c8d" />

### 6. Searched the `DeviceProcessEvents` Table
Began searching for indicators that threat actor began inhibiting recovery solutions and backups. On `2025-11-25T05:47:02.660493Z` the threat actor deleted the backup archives via the command line from the backup server. On `2025-11-25T05:47:03.652647Z`, the threat actor stopped the cron service, disabling scheduled tasks. On `2025-11-25T05:47:03.684715Z`, the threat actor disabled the cron service from the backup server. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where FileName == "rm"
| where ProcessCommandLine contains "backups"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<img width="2914" height="80" alt="image" src="https://github.com/user-attachments/assets/7ef1e301-a0b8-493d-a384-ad51e0da9080" />

```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where FileName == "systemctl"
| where ProcessCommandLine contains "stop"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<img width="1979" height="243" alt="image" src="https://github.com/user-attachments/assets/0d1f8409-030e-4989-a272-a0b91da296ac" />

```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where FileName == "systemctl"
| where ProcessCommandLine contains "disable"
| sort by TimeGenerated asc 
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<img width="2092" height="148" alt="image" src="https://github.com/user-attachments/assets/2fa26f62-80b6-46e4-89b1-780a87d3df1c" />

### 7. Searched the  `DeviceProcessEvents` Table
Began searching for indicators of lateral movement and remote execution of malicious payloads across the network. On `2025-11-25T06:05:46.6079265Z` PSExec was utilzed to forcibly install `silentlynx.exe` on IP `10.1.0.204` udner stolen credentials. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName contains "psexec"
| sort by TimeGenerated asc 
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
<img width="2907" height="153" alt="image" src="https://github.com/user-attachments/assets/9757b8a5-09c0-4496-b3dd-d024d3cc24d1" />

### 8. Searched the  `DeviceProcessEvents` Table
Ransomware will stop backup services in order to prevent recovery while the company's data is being encrypted. Began searching Window's shadow copy service to inquire whether this has been corrupted by threat acotr. The shadow copy service allows point-in-time snapshots of files and volumes, even while is use. On `2025-11-25T06:04:53.2550438Z`, the threat actor stopped the shadow copy service. On `2025-11-25T06:04:54.0244502Z`, the threat actor stopped the Windows Backup Engine service. SQL server keeps files open and locked which would inhibit encryption. On `2025-11-25T06:04:57.2127196Z`, the treat actor disabled the SQL server. On `2025-11-25T05:58:55.8089392Z`, the attacker deleted all shadow copies(restore points) to further prevent recovery. On `2025-11-25T05:59:56.1202753Z`, the attacker also resized Windows shadow service to limit storage availability for recovery. Windows recovery features enable system repair after corruption. On `2025-11-25T06:04:59.5579336Z`, the Windows Recovery Environment was disabled for the default boot entry, make recovery much harder. The Windows backup catalog was also deleted by the threat actor on `2025-11-25T06:04:59.7181241Z`.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "vss"
| sort by TimeGenerated asc
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<img width="2061" height="74" alt="image" src="https://github.com/user-attachments/assets/1856ddb1-2b86-4253-a474-853cdc01be1e" />

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "wbengine"
| sort by TimeGenerated asc
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<img width="2035" height="87" alt="image" src="https://github.com/user-attachments/assets/c311f4ee-c636-471f-b3db-f20cc2f61345" />

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "taskkill"
| sort by TimeGenerated asc
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<img width="2152" height="78" alt="image" src="https://github.com/user-attachments/assets/4a657e06-42fb-4a3d-8c49-421cfcade494" />

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "shadows"
| sort by TimeGenerated asc
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<img width="2310" height="130" alt="image" src="https://github.com/user-attachments/assets/8486d426-0d21-423c-9529-af93795b1af2" />

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "shadowstorage"
| sort by TimeGenerated asc
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<img width="2659" height="131" alt="image" src="https://github.com/user-attachments/assets/1c7537a4-7b37-46f3-a694-c2ed820476ec" />

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "bcdedit"
| sort by TimeGenerated asc
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<img width="2374" height="84" alt="image" src="https://github.com/user-attachments/assets/0362aae1-4bd1-4fae-85d0-0e40fce41dc9" />

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "catalog"
| sort by TimeGenerated asc
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<img width="2195" height="145" alt="image" src="https://github.com/user-attachments/assets/54a326ba-7c8b-4ea4-81f3-559b15a2bf3c" />














