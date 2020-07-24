# TH-0005-Web Shells

***Creation Date:*** 2020/06/28

***Author:*** svch0st

***Target Platform:*** Network

***Analytics:***

- Suspicious commands spawned from common web server processes - Sysmon, Security

## Hypothesis

Adversaries may have planted web shells on internet facing web servers.

## Description

A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. 

## ATT&CK Detection

|Technique|Subtechnique(s)|Tactic(s)|
|---|---|---|
|[Server Software Component](https://attack.mitre.org/beta/techniques/T1505/)|[Web Shell](https://attack.mitre.org/beta/techniques/T1505/003/)|[Persistence](https://attack.mitre.org/beta/tactics/TA0003/)|

## Analytics

### Suspicious commands spawned from common web server processes

***Data Source:*** Sysmon, Security

***Description:*** Isolate the log entries that contain domains hosted on dynamic DNS provider

***Logic:***
```
title: Webshell Detection With Command Line Keywords
id: bed2a484-9348-4143-8a8a-b801c979301c
description: Detects certain command line parameters often used during reconnaissance activity via web shells
author: Florian Roth
reference:
    - https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html
date: 2017/01/01
modified: 2019/10/26
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1100
    - attack.t1505.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\apache*'
            - '*\tomcat*'
            - '*\w3wp.exe'
            - '*\php-cgi.exe'
            - '*\nginx.exe'
            - '*\httpd.exe'
        CommandLine:
            - '*whoami*'
            - '*net user *'
            - '*ping -n *'
            - '*systeminfo'
            - '*&cd&echo*'
            - '*cd /d*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high
```

## Atomic Tests


[T1505.003 - Web Shell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md/)

1. [Web Shell Written to Disk](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md/#atomic-test-1---web-shell-written-to-disk)

## Hunter Notes



## Hunt Outputs



## References

- https://www.cyber.gov.au/sites/default/files/2019-03/ACSC_Web_Shells.pdf
- https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF