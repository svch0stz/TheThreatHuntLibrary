# TH-0006-Autoruns Analysis

***Creation Date:*** 2020/06/28

***Author:*** svch0st

***Target Platform:*** Windows

***Analytics:***

- Autorunsc.exe - Custom Output

## Hypothesis

Adversaries may try to gain persistence by using the autorun or ASEP locations in Windows

## Description

The Sysinternals tool Autoruns checks the registry and file system for known identify persistence mechanisms. It will output any tools identified, including built-in or added-on Microsoft functionality and third party software. Many of these locations are known by adversaries and used to obtain Persistence.

## ATT&CK Detection

|Technique|Subtechnique(s)|Tactic(s)|
|---|---|---|
|[Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|[Windows Service](https://attack.mitre.org/techniques/T1543/003/)|[Persistence](https://attack.mitre.org/tactics/TA0003/), [Execution](https://attack.mitre.org/tactics/TA0002/)|
|[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)|[At (Windows)](https://attack.mitre.org/techniques/T1053/002/), [Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)|[Execution](https://attack.mitre.org/tactics/TA0002/), [Persistence](https://attack.mitre.org/tactics/TA0003/), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)|
|[Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)|[Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003/), [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012/), [PowerShell Profile](https://attack.mitre.org/techniques/T1546/013/)|[Persistence](https://attack.mitre.org/tactics/TA0003/), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)|
|[Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037/)|[Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/), [Startup Items](https://attack.mitre.org/techniques/T1037/005/)|[Persistence](https://attack.mitre.org/tactics/TA0003/), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)|
|[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|[Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)|[Persistence](https://attack.mitre.org/tactics/TA0003/), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)|

## Analytics

### Autorunsc.exe

***Data Source:*** Custom Output

***Description:*** wsdadas

***Logic:***
```

```

## Atomic Tests


[T1543.003 - Windows Service](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md/)

1. [Modify Fax service to run PowerShell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md/#atomic-test-1---modify-fax-service-to-run-powershell)

2. [Service Installation CMD](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md/#atomic-test-2---service-installation-cmd)

3. [Service Installation PowerShell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md/#atomic-test-3---service-installation-powershell)

[T1053.002 - At (Windows)](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.002/T1053.002.md/)

1. [At.exe Scheduled task](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.002/T1053.002.md/#atomic-test-1---at.exe-scheduled-task)

[T1053.005 - Scheduled Task](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md/)

1. [Scheduled Task Startup Script](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md/#atomic-test-1---scheduled-task-startup-script)

2. [Scheduled task Local](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md/#atomic-test-2---scheduled-task-local)

3. [Scheduled task Remote](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md/#atomic-test-3---scheduled-task-remote)

4. [Powershell Cmdlet Scheduled Task](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md/#atomic-test-4---powershell-cmdlet-scheduled-task)

[T1546.003 - Windows Management Instrumentation Event Subscription](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md/)

1. [Persistence via WMI Event Subscription](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md/#atomic-test-1---persistence-via-wmi-event-subscription)

[T1546.012 - Image File Execution Options Injection](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.012/T1546.012.md/)

1. [IFEO Add Debugger](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.012/T1546.012.md/#atomic-test-1---ifeo-add-debugger)

2. [IFEO Global Flags](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.012/T1546.012.md/#atomic-test-2---ifeo-global-flags)

[T1546.013 - PowerShell Profile](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.013/T1546.013.md/)

1. [Append malicious start-process cmdlet](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.013/T1546.013.md/#atomic-test-1---append-malicious-start-process-cmdlet)

[T1037.001 - Logon Script (Windows)](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.001/T1037.001.md/)

1. [Logon Scripts](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.001/T1037.001.md/#atomic-test-1---logon-scripts)

[T1037.005 - Startup Items](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.005/T1037.005.md/)

1. [Add file to Local Library StartupItems](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.005/T1037.005.md/#atomic-test-1---add-file-to-local-library-startupitems)

[T1547.001 - Registry Run Keys / Startup Folder](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md/)

1. [Reg Key Run](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md/#atomic-test-1---reg-key-run)

2. [Reg Key RunOnce](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md/#atomic-test-2---reg-key-runonce)

3. [PowerShell Registry RunOnce](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md/#atomic-test-3---powershell-registry-runonce)

4. [Suspicious vbs file run from startup Folder](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md/#atomic-test-4---suspicious-vbs-file-run-from-startup-folder)

5. [Suspicious jse file run from startup Folder](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md/#atomic-test-5---suspicious-jse-file-run-from-startup-folder)

6. [Suspicious bat file run from startup Folder](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md/#atomic-test-6---suspicious-bat-file-run-from-startup-folder)

## Hunter Notes



## Hunt Outputs



## References

- https://car.mitre.org/analytics/CAR-2013-01-002/