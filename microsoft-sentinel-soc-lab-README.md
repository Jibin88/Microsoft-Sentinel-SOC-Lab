# Microsoft Sentinel -- Windows Failed Logon Detection SOC Lab

## Project Overview

A hands-on SOC lab built with Microsoft Sentinel to monitor Windows
security events and detect repeated failed logon attempts.

## Objectives

-   Build an isolated SOC lab using VirtualBox.
-   Generate controlled failed authentication attempts.
-   Monitor Windows Security Event ID 4625.
-   Collect Windows security events using Azure Monitor Agent (AMA).
-   Configure a Data Collection Rule (DCR).
-   Send events to Log Analytics and Microsoft Sentinel.
-   Write KQL detection queries.
-   Create a scheduled Microsoft Sentinel Analytics Rule.
-   Verify Analytics Rule execution through Sentinel health monitoring.

## Lab Architecture

``` text
Kali Linux
192.168.56.101
     |
     | Controlled SMB authentication failures
     v
Windows 10 VM
192.168.56.102
     |
     | Event ID 4625
     v
Azure Monitor Agent
     |
     v
Data Collection Rule
     |
     v
Log Analytics Workspace
     |
     v
Microsoft Sentinel
     |
     v
KQL Detection
     |
     v
Scheduled Analytics Rule
```

## Technologies Used

-   Microsoft Sentinel
-   KQL
-   Azure Monitor Agent
-   Azure Arc
-   Data Collection Rules
-   Log Analytics
-   Windows Event Logs
-   Kali Linux
-   Windows 10
-   VirtualBox
-   SMB

## Detection Scenario

Windows Security Event ID 4625 is generated when an account fails to log
on.

Controlled failed SMB authentication attempts were generated from Kali
Linux against the Windows lab VM:

``` bash
for i in {1..5}; do smbclient -L //192.168.56.102 -U 'socuser%WrongPass123!'; done
```

Expected result:

``` text
NT_STATUS_LOGON_FAILURE
```

## KQL Detection

``` kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count()
    by Computer, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
| order by TimeGenerated desc
```

This detects three or more failed logon events from the same computer
and source IP within a five-minute window.

## Investigation Data

Example fields observed during the lab:

``` text
Event ID       : 4625
Target User    : socuser
Source IP      : 192.168.56.101
Logon Type     : 3
Workstation    : KALI
Authentication : NTLM
```

## Azure Configuration

### Azure Arc

The Windows victim VM was onboarded to Azure Arc as:

``` text
DESKTOP-9LVMV9D
```

### Azure Monitor Agent

Azure Monitor Agent was deployed through the Azure Arc machine
extensions.

### Data Collection Rule

The DCR:

``` text
dcr-windows-securityevents
```

was configured to collect Windows Security Event ID 4625.

The relevant XPath was:

``` text
Security!*[System[(EventID=4625)]]
```

Destination:

``` text
soc-log-workspace
```

## Microsoft Sentinel Analytics Rule

Rule name:

``` text
SOC - Multiple Failed Logons 4625
```

Configuration:

``` text
Type          : Scheduled
Severity      : Medium
Frequency     : 5 minutes
Lookback      : 10 minutes
Detection     : 3+ failed logons
Tactic        : Credential Access
Technique     : T1110
```

The scheduled rule was created and its execution was verified through
Sentinel health monitoring.

## Validation

Successfully demonstrated:

-   Isolated Kali-to-Windows lab networking.
-   Controlled failed SMB authentication.
-   Windows Event ID 4625 generation.
-   Azure Arc onboarding.
-   Azure Monitor Agent deployment.
-   DCR configuration.
-   4625 events visible in Microsoft Sentinel.
-   KQL detection logic.
-   Scheduled Analytics Rule creation.
-   Successful scheduled rule execution.

**Note:** Final alert/incident generation was not included as a verified
result. The documentation intentionally reflects only the components
that were successfully validated.

## Suggested Repository Structure

``` text
microsoft-sentinel-soc-lab/
├── README.md
├── KQL/
│   └── failed-logon-detection.kql
├── screenshots/
│   ├── 01-virtualbox-lab.png
│   ├── 02-kali-smb-failures.png
│   ├── 03-windows-event-4625.png
│   ├── 04-azure-arc.png
│   ├── 05-ama.png
│   ├── 06-dcr.png
│   ├── 07-sentinel-events.png
│   ├── 08-kql-detection.png
│   ├── 09-analytics-rule.png
│   └── 10-sentinel-health.png
└── documentation/
    └── project-report.pdf
```

## Skills Demonstrated

-   SIEM Monitoring
-   Microsoft Sentinel
-   KQL
-   Windows Event Log Analysis
-   Event ID 4625 Investigation
-   Azure Monitor Agent
-   Azure Arc
-   Data Collection Rules
-   Log Analytics
-   Security Event Detection
-   Network Security Testing
-   Kali Linux
-   VirtualBox
-   SMB Monitoring

