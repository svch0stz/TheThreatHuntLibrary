# TH-0001-LSASS Access from Non System Account

***Creation Date:*** 2020/06/28

***Author:*** Roberto Rodriguez @Cyb3rWard0g, svch0st

***Target Platform:*** Windows

***Analytics:***

- Non-system accounts getting a handle and access lsass - Security

- Unknown calltrace - potential fileless DLLs - Microsoft-Windows-Sysmon/Operational

- Known Suspicious DLLs observed - Microsoft-Windows-Sysmon/Operational

## Hypothesis

Adversaries might be using a non system account to access LSASS and extract credentials from memory.

## Description

After a user logs on, a variety of credentials are generated and stored in the Local Security Authority Subsystem Service (LSASS) process in memory.
This is meant to facilitate single sign-on (SSO) ensuring a user isn't prompted each time resource access is requested.
The credential data may include Kerberos tickets, NTLM password hashes, LM password hashes (if the password is <15 characters, depending on Windows OS version and patch level), and even clear-text passwords (to support WDigest and SSP authentication among others.
Adversaries look to get access to the credential data and do it so by finding a way to access the contents of memory of the LSASS process.
For example, tools like Mimikatz get credential data by listing all available provider credentials with its SEKURLSA::LogonPasswords module.
The module uses a Kernel32 function called OpenProcess to get a handle to lsass to then access LSASS and dump password data for currently logged on (or recently logged on) accounts as well as services running under the context of user credentials.
Even though most adversaries might inject into a System process to blend in with most applications accessing LSASS, there are ocassions where adversaries do not elevate to System and use the available administrator rights from the user since that is the minimum requirement to access LSASS.

## ATT&CK Detection

|Technique|Subtechnique(s)|Tactic(s)|
|---|---|---|
|[OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|[LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)|[Credential Access](https://attack.mitre.org/tactics/TA0006/)|

## Analytics

### Non-system accounts getting a handle and access lsass

***Data Source:*** Security

***Description:*** Look for non-system accounts getting a handle and access lsass

***Logic:***
```
SELECT *
FROM events
WHERE 'Log Channel' = "Security" AND 'Log Source Type' = "Microsoft Windows Event Log"
    AND (event_id = 4663 OR event_id = 4656)
    AND ImageName LIKE "%lsass.exe"
    AND NOT SubjectUserName LIKE "%$"
```
### Unknown calltrace - potential fileless DLLs

***Data Source:*** Microsoft-Windows-Sysmon/Operational

***Description:*** Processes opening handles and accessing Lsass with potential dlls in memory (i.e UNKNOWN in CallTrace)

***Logic:***
```
SELECT *
FROM events
WHERE 'Log Channel' = "Microsoft-Windows-Sysmon" AND 'Log Source Type' = "Microsoft Windows Event Log"
    AND event_id = 10
    AND TargetImage LIKE "%lsass.exe"
    AND CallTrace LIKE "%UNKNOWN%"
```
### Known Suspicious DLLs observed

***Data Source:*** Microsoft-Windows-Sysmon/Operational

***Description:*** Look for non-system accounts getting a handle and access lsass

***Logic:***
```
SELECT *
FROM events
WHERE 'Log Channel' = "Microsoft-Windows-Sysmon" AND 'Log Source Type' = "Microsoft Windows Event Log"
    AND event_id = 7
    AND ( 
        ImageLoaded LIKE "%samlib.dll"
        OR ImageLoaded LIKE "%vaultcli.dll"
        OR ImageLoaded LIKE "%hid.dll"
        OR ImageLoaded LIKE "%winscard.dll"
        OR ImageLoaded LIKE "%cryptdll.dll"
    )
```

## Atomic Tests

[T1003 - OS Credential Dumping](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md/)

1. [Powershell Mimikatz](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md/#atomic-test-1---powershell-mimikatz)
2. [Gsecdump](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md/#atomic-test-2---gsecdump)
3. [Credential Dumping with NPPSpy](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md/#atomic-test-3---credential-dumping-with-nppspy)

[T1003.001 - LSASS Memory](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md/)

1. [Windows Credential Editor](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md/#atomic-test-1---windows-credential-editor)

2. [Dump LSASS.exe Memory using ProcDump](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md/#atomic-test-2---dump-lsass.exe-memory-using-procdump)

3. [Dump LSASS.exe Memory using comsvcs.dll](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md/#atomic-test-3---dump-lsass.exe-memory-using-comsvcs.dll)

4. [Dump LSASS.exe Memory using direct system calls and API unhooking](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md/#atomic-test-4---dump-lsass.exe-memory-using-direct-system-calls-and-api-unhooking)

5. [Dump LSASS.exe Memory using Windows Task Manager](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md/#atomic-test-5---dump-lsass.exe-memory-using-windows-task-manager)

6. [Offline Credential Theft With Mimikatz](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md/#atomic-test-6---offline-credential-theft-with-mimikatz)

7. [LSASS read with pypykatz](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md/#atomic-test-7---lsass-read-with-pypykatz)

## Hunter Notes

* Looking for processes accessing LSASS with the 0x10(VmRead) rights from a non-system account is very suspicious and not as common as you might think.
* GrantedAccess code 0x1010 is the new permission Mimikatz v.20170327 uses for command "sekurlsa::logonpasswords". You can specifically look for that from processes like PowerShell to create a basic signature.
  * 0x00000010 = VMRead
  * 0x00001000 = QueryLimitedInfo
* GrantedAccess code 0x1010 is less common than 0x1410 in large environment.
* Out of all the Modules that Mimikatz needs to function, there are 5 modules that when loaded all together by the same process is very suspicious.
  * samlib.dll, vaultcli.dll, hid.dll, winscard.dll, cryptdll.dll
* For signatures purposes, look for processes accessing Lsass.exe with a potential CallTrace Pattern> /C:\Windows\SYSTEM32\ntdll.dll+[a-zA-Z0-9]{1,}|C:\Windows\System32\KERNELBASE.dll+[a-zA-Z0-9]{1,}|UNKNOWN.*/
* You could use a stack counting technique to stack all the values of the permissions invoked by processes accessing Lsass.exe. You will have to do some filtering to reduce the number of false positives. You could then group the results with other events such as modules being loaded (EID 7). A time window of 1-2 seconds could help to get to a reasonable number of events for analysis.

## Hunt Outputs

None

## References

* https://tyranidslair.blogspot.com/2017/10/bypassing-sacl-auditing-on-lsass.htmls
* https://adsecurity.org/?page_id=1821#SEKURLSALogonPasswords
* https://github.com/PowerShellMafia/PowerSploit/tree/dev
* http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/