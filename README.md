# SC200-KQL-Threat-Detection-Portfolio
Custom KQL threat detection queries built for SC-200 Microsoft Security Operations Analyst exam preparation. Demonstrates Sentinel Analytics Rule logic using Azure Log Analytics.

## Overview
Custom KQL queries built as part of SC-200 exam preparation, demonstrating threat detection logic applicable to Microsoft Sentinal Analytics Rules.

## Environment
- Platform: Azure Log Analytics Demo Workspace
- Language: Kusto Query Language (KQL)
- Certification targeet: SC-200 Microsoft Security Operations Analyst exam preparation.

## MITRE ATT&CK Coverage
| Query | Threat Concept | MITRE Tactic |
|---|---|---|
| Query 1 | Brute Force Detection | Credential Access (TA0006) |
| Query 2 | Suspicious App Activity | Execution (TA0002) |
| Query 3 | Lateral Movement | Lateral Movement (TA0008) |
| Query 4 | Performance Anomaly | Privilege Escalation (TA0004) |
| Query 5 | Data Exfiltration | Exfiltration (TA0010) |

## Query 1: High Error Rate Detection
**SC-200 Concept:** Threshold-based Analytics Rule detection  
**Production table:** SecurityEvent (EventID 4625)  
**Demo table:** AppExceptions

### KQL Code
```kql
AppExceptions
| where TimeGenerated > ago(7d)
| summarize ErrorCount = count() by AppRoleName, ExceptionType
| where ErrorCount > 100
| sort by ErrorCount desc
```

### What it detects
Unusual spike in errors from specific application roles. 
In production, this same logic detects repeated failed login 
attempts indicating a brute force attack against user accounts.

### SC-200 KQL Concepts Demonstrated
- Time filtering with `ago()`
- Aggregation with `summarize` and `count()`
- Entity grouping with `by`
- Threshold filtering with `where`
- Result sorting with `sort by`

## Query 2: Suspicious Application Activity
**SC-200 Concept:** Execution Detection - identifying suspcious repeated application errors indicative of beaconing or misconfigured outbound connections
**MITRE ATT&CK:** Execution (TA0002) / Command and Control (TA0011)
**Production table:** SecurityEvent (EventID 4688 - Process Creation)
**Demo table:** AppTraces

### KQL Code
AppTraces
| where TimeGenerated > ago7d)
| where SeverityLevel == 3
| summarize SuspiciousCount = count() by AppRoleName, Message
| where SuspiciousCount > 50
| sort by SuspiciousCount desc

## What it detects 
Unusual spike in error-level application traces from specific application roles.
In production, this same logic detects suspicious process execution activity such as PowerShell with obfuscation flags or repeated outbound connection attempts indicating beaconing or command and control behavior.

### SC-200 KQL Concepts Demonstrated
- Severity level filtering with 'where SeverityLevel'
- Aggregate with 'summarize' and 'count()'
- Threshold filtering with 'where'
- Result sort with 'sort by'

## Query 3: Lateral Movement Detection

**SC-200 Concept:** Lateral movement detection — identifying applications or users accessing an unusually high number of unique targets  
**MITRE ATT&CK:** Lateral Movement (TA0008)  
**Production table:** SecurityEvent / NetworkCommunicationEvents  
**Demo table:** AppDependencies

### KQL Code
```kql
AppDependencies
| summarize TargetCount = dcount(Target) by AppRoleName
| where TargetCount > 5
| sort by TargetCount desc
```

### What it detects
Application accessing an unusually high number of unique external
targets. In production, this same logic detects lateral movement
where a compromised account or device accesses multiple servers
across the environment in a short period of time.

### SC-200 KQL Concepts Demonstrated
- `dcount()` — counting distinct/unique values (not total occurrences)
- `summarize` with grouping by entity
- Threshold filtering with `where`
- `sort by desc` — prioritizing highest risk first

## Query 4: Performance Anomaly Detection

**SC-200 Concept:** Privilege escalation and malware detection 
through abnormal resource consumption patterns  
**MITRE ATT&CK:** Privilege Escalation (TA0004)  
**Production table:** Perf / SecurityEvent  
**Demo table:** AppPerformanceCounters

### KQL Code
```kql
AppPerformanceCounters
| where TimeGenerated > ago(7d)
| summarize AvgValue = avg(Value) by Name, AppRoleName
| where AvgValue > 1000000
| sort by AvgValue desc
```

### What it detects
Applications with sustained abnormally high resource consumption
(memory, CPU, network). In production, this same logic detects
ransomware, cryptomining malware, or privilege escalation tools
consuming unusually high system resources over time.

### SC-200 KQL Concepts Demonstrated
- `avg()` — calculating average values instead of counting
- `summarize` with grouping by multiple columns
- High threshold filtering with `where`
- `sort by desc` — surfacing highest risk first
