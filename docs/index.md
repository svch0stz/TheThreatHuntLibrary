
# The Threat Hunt Library

## Hunt List

|Hunt|ATT&CK Techniques|Platform(s)|Creation Date|
|---|---|---|---|
|<a href="hunts/TH-0001-LSASS Access from Non System Account.md">TH-0001-LSASS Access from Non System Account</a>|<ul style='margin-bottom: 0;'><li><a href="https://attack.mitre.org/techniques/T1003/">T1003-OS Credential Dumping</a></li></ul>|Windows|2020/06/28|
|<a href="hunts/TH-0002-C2 Beaconing via Standard Protocols.md">TH-0002-C2 Beaconing via Standard Protocols</a>|<ul style='margin-bottom: 0;'><li><a href="https://attack.mitre.org/techniques/T1071/">T1071-Application Layer Protocol</a></li></ul>|Network|2020/06/28|
|<a href="hunts/TH-0003-Compromise via external media and devices.md">TH-0003-Compromise via external media and devices</a>|<ul style='margin-bottom: 0;'><li><a href="https://attack.mitre.org/techniques/T1091/">T1091-Replication Through Removable Media</a></li><li><a href="https://attack.mitre.org/techniques/T1052/">T1052-Exfiltration Over Physical Medium</a></li></ul>|Windows|2020/06/28|
|<a href="hunts/TH-0004-Suspicious network traffic over DNS.md">TH-0004-Suspicious network traffic over DNS</a>|<ul style='margin-bottom: 0;'><li><a href="https://attack.mitre.org/techniques/T1568/">T1568-Dynamic Resolution</a></li><li><a href="https://attack.mitre.org/techniques/T1071/">T1071-Application Layer Protocol</a></li><li><a href="https://attack.mitre.org/techniques/T1048/">T1048-Exfiltration Over Alternative Protocol</a></li></ul>|Network|2020/06/28|
|<a href="hunts/TH-0005-Web Shells.md">TH-0005-Web Shells</a>|<ul style='margin-bottom: 0;'><li><a href="https://attack.mitre.org/techniques/T1505/">T1505-Server Software Component</a></li></ul>|Network|2020/06/28|
|<a href="hunts/TH-0006-Autoruns Analysis.md">TH-0006-Autoruns Analysis</a>|<ul style='margin-bottom: 0;'><li><a href="https://attack.mitre.org/techniques/T1543/">T1543-Create or Modify System Process</a></li><li><a href="https://attack.mitre.org/techniques/T1053/">T1053-Scheduled Task/Job</a></li><li><a href="https://attack.mitre.org/techniques/T1546/">T1546-Event Triggered Execution</a></li><li><a href="https://attack.mitre.org/techniques/T1037/">T1037-Boot or Logon Initialization Scripts</a></li><li><a href="https://attack.mitre.org/techniques/T1547/">T1547-Boot or Logon Autostart Execution</a></li></ul>|Windows|2020/06/28|
|<a href="hunts/TH-0007-File Share Discovery.md">TH-0007-File Share Discovery</a>|<ul style='margin-bottom: 0;'><li><a href="https://attack.mitre.org/techniques/T1039/">T1039-Data from Network Shared Drive</a></li></ul>|Network|2020/07/04|

---
## Hunt List (by technique/sub-technique coverage)

|ATT&CK Technique|ATT&CK Sub-technique(s)|Hunt|
|---|---|---|
|[T1003-OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|[T1003.001-LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0001-LSASS Access from Non System Account.md">TH-0001-LSASS Access from Non System Account</a></li></ul>|
|[T1071-Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|(N/A - see below)|(N/A - see below)|
|...|[T1071.001-Web Protocols](https://attack.mitre.org/techniques/T1071/001/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0002-C2 Beaconing via Standard Protocols.md">TH-0002-C2 Beaconing via Standard Protocols</a></li></ul>|
|...|[T1071.002-File Transfer Protocols](https://attack.mitre.org/techniques/T1071/002/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0002-C2 Beaconing via Standard Protocols.md">TH-0002-C2 Beaconing via Standard Protocols</a></li></ul>|
|...|[T1071.003-Mail Protocols](https://attack.mitre.org/techniques/T1071/003/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0002-C2 Beaconing via Standard Protocols.md">TH-0002-C2 Beaconing via Standard Protocols</a></li></ul>|
|...|[T1071.004-DNS](https://attack.mitre.org/techniques/T1071/004/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0002-C2 Beaconing via Standard Protocols.md">TH-0002-C2 Beaconing via Standard Protocols</a></li><li><a href="hunts/TH-0004-Suspicious network traffic over DNS.md">TH-0004-Suspicious network traffic over DNS</a></li></ul>|
|[T1052-Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052/)|[T1052.001-Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0003-Compromise via external media and devices.md">TH-0003-Compromise via external media and devices</a></li></ul>|
|[T1568-Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)|[T1568.002-Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0004-Suspicious network traffic over DNS.md">TH-0004-Suspicious network traffic over DNS</a></li></ul>|
|[T1048-Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|[T1048.003-Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0004-Suspicious network traffic over DNS.md">TH-0004-Suspicious network traffic over DNS</a></li></ul>|
|[T1505-Server Software Component](https://attack.mitre.org/techniques/T1505/)|[T1505.003-Web Shell](https://attack.mitre.org/techniques/T1505/003/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0005-Web Shells.md">TH-0005-Web Shells</a></li></ul>|
|[T1543-Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|[T1543.003-Windows Service](https://attack.mitre.org/techniques/T1543/003/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0006-Autoruns Analysis.md">TH-0006-Autoruns Analysis</a></li></ul>|
|[T1053-Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)|(N/A - see below)|(N/A - see below)|
|...|[T1053.002-At (Windows)](https://attack.mitre.org/techniques/T1053/002/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0006-Autoruns Analysis.md">TH-0006-Autoruns Analysis</a></li></ul>|
|...|[T1053.005-Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0006-Autoruns Analysis.md">TH-0006-Autoruns Analysis</a></li></ul>|
|[T1546-Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)|(N/A - see below)|(N/A - see below)|
|...|[T1546.003-Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0006-Autoruns Analysis.md">TH-0006-Autoruns Analysis</a></li></ul>|
|...|[T1546.012-Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0006-Autoruns Analysis.md">TH-0006-Autoruns Analysis</a></li></ul>|
|...|[T1546.013-PowerShell Profile](https://attack.mitre.org/techniques/T1546/013/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0006-Autoruns Analysis.md">TH-0006-Autoruns Analysis</a></li></ul>|
|[T1037-Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037/)|(N/A - see below)|(N/A - see below)|
|...|[T1037.001-Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0006-Autoruns Analysis.md">TH-0006-Autoruns Analysis</a></li></ul>|
|...|[T1037.005-Startup Items](https://attack.mitre.org/techniques/T1037/005/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0006-Autoruns Analysis.md">TH-0006-Autoruns Analysis</a></li></ul>|
|[T1547-Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|[T1547.001-Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)|<ul style='margin-bottom: 0;'><li><a href="hunts/TH-0006-Autoruns Analysis.md">TH-0006-Autoruns Analysis</a></li></ul>|
