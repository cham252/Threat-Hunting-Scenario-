<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# 🧅 Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Tools
- **Operating System:** Windows 10 (Azure Virtual Machine)  
- **EDR Platform:** Microsoft Defender for Endpoint  
- **Language:** Kusto Query Language (KQL)  
- **Browser:** Tor Browser v14.5.8  

---

## Scenario
Management suspected that a user was installing and using the Tor Browser to bypass network security controls.  
Unusual encrypted traffic patterns and connections to known Tor entry nodes were detected in network telemetry.  
The goal was to confirm any unauthorized use of Tor, collect Indicators of Compromise (IoCs), and provide actionable evidence for remediation.

---

## Investigation Plan
- Review **DeviceFileEvents** for Tor-related file activity (`tor.exe`, `firefox.exe`, `tor-browser.exe`).  
- Check **DeviceProcessEvents** for process creation events tied to Tor executables or installers.  
- Query **DeviceNetworkEvents** for outbound Tor network connections over ports `9001`, `9030`, `9150`, and `443`.

---

## 1. File Discovery (`DeviceFileEvents`)

**Query:**
```kql
DeviceFileEvents
| where DeviceName == "cham-threat-hun"
| where InitiatingProcessAccountName == "vmlabuser"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
```
**Findings:**
 Between **Oct 16, 2025 07:57 AM** and **08:20 AM,** multiple Tor-related files were created in the user’s Desktop directory.
 Notable files:
-	Tor Browser.lnk
-	tor.exe
-	tor.txt
-	Torbutton.txt
-	Tor-Launcher.txt
-	storage.sqlite and other .sqlite database files
<img width="1212" alt="image" src="https://github.com/cham252/Threat-Hunting-Scenario-/blob/main/scan1.png">

---

### 2. Tor Browser Installation (DeviceProcessEvents)
**Query:**

```kql

DeviceProcessEvents
| where DeviceName == "cham-threat-hun"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.8.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
**Finding:**
At **Oct 16, 2025 07:59 AM,** user vmlabuser executed:
tor-browser-windows-x86_64-portable-14.5.8.exe /S
from the **Downloads** folder.
This triggered a **silent installation** of Tor Browser v14.5.8 without any visible prompts.

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

### 3. Process Execution (DeviceProcessEvents)
**Query:**

```kql
DeviceProcessEvents
| where DeviceName == "cham-threat-hun"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
**Finding:**
By **08:23 AM,** multiple instances of firefox.exe and tor.exe were launched, indicating successful Tor Browser startup.
Executable path observed:
C:\Users\vmlabuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Network Connections (DeviceNetworkEvents)

**Query:**

```kql
DeviceNetworkEvents
| where DeviceName == "cham-threat-hun"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe","firefox.exe")
| where RemotePort in ("9001","9030","9050","9150","80","443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
**Findings:**
Between **08:17–08:24 AM,** tor.exe and firefox.exe established outbound Tor network connections:
| Timestamp | Remote IP | Port | Process | Connection Type |
|------------|------------|------|----------|----------------|
| 08:24 AM | 140.235.237.13 | 9001 | tor.exe | Tor Relay |
| 08:24 AM | 45.141.153.214 | 443 | tor.exe | HTTPS |
| 08:17 AM | 127.0.0.1 | 9150 | firefox.exe | Local SOCKS Proxy |
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## 5. Chronological Timeline

| Time (UTC-4) | Event | Process | Action |
|---------------|--------|----------|---------|
| 07:57 AM | `MpCopyAccelerator.exe` deleted | System | FileDeleted |
| 07:59 AM | Tor Browser silent install executed | `tor-browser-windows-x86_64-portable-14.5.8.exe` | ProcessCreated |
| 08:00–08:09 AM | Tor-related files extracted to Desktop | vmlabuser | FileCreated |
| 08:17–08:24 AM | Outbound Tor connections established | tor.exe | ConnectionSuccess |

---

### 6. File Creation — TOR Shopping List

- **Timestamp:** `2025-10-16T08:20:37.0000000Z`  
- **Event:** The user `vmlabuser` created several Tor-related files, including `tor.txt`, `Torbutton.txt`, and `Tor-Launcher.txt` on the desktop, which appear to contain notes and configuration data related to Tor Browser usage.  
- **Action:** File creation detected.  
- **File Path:** `C:\Users\vmlabuser\Desktop\Tor Browser\`  

---

## Summary

The user “vmlabuser” on the “cham-threat-hun” device installed and executed the Tor Browser. System logs confirm that the user launched the application, established outbound connections to Tor network nodes, and created several Tor-related files within their desktop directory. This behavior demonstrates intentional installation and use of anonymization software, indicating an attempt to bypass standard network monitoring and security controls. The activity represents a high-risk security policy violation requiring immediate review and remediation.


---

### Next Steps

1. **System Remediation:**  
   - Remove the Tor Browser directory from `C:\Users\vmlabuser\Desktop\Tor Browser\`.  
   - Run a full endpoint scan using Microsoft Defender for Endpoint to verify that no persistence mechanisms or hidden Tor services remain.

2. **Network Control:**  
   - Block outbound connections on TCP ports **9001**, **9030**, and **9150** at the perimeter firewall.  
   - Review network egress logs for additional Tor relay IPs or hidden service traffic patterns.

3. **User Accountability:**  
   - Conduct an interview with the user `vmlabuser` to determine intent and educate on acceptable-use policies.  
   - Reinforce corporate guidelines prohibiting anonymization tools on managed systems.

4. **Monitoring & Detection:**  
   - Implement advanced hunting queries to detect silent installers using the `/S` flag.  
   - Add continuous detection rules for processes `tor.exe`, `firefox.exe`, and connections to known Tor nodes.

5. **Compliance & Reporting:**  
   - Document this incident for internal audit and policy review.  
   - Recommend periodic validation of security policies against anonymizing and tunneling tools.

---

**Status:** Under review by SOC and Information Security teams.  
**Priority:** High — potential policy violation involving anonymization software.
---
