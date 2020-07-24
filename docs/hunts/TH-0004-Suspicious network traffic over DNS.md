# TH-0004-Suspicious network traffic over DNS

***Creation Date:*** 2020/06/28

***Author:*** svch0st

***Target Platform:*** Network

***Analytics:***

- Dynamic DNS - Network Flow Data, DNS logs

- Long Domains - Network Flow Data, DNS Logs

- DGA-like detection - Network Flow Data, DNS Logs

- Requests to thousands of hosts or subdomains in one domain - Network Metadata

## Hypothesis

Adversaries may use DNS to hide C2 traffic or data exfiltration

## Description

DNS Tunneling is a method of cyber attack that encodes the data of other programs or protocols in DNS queries and responses. This can be used for the exfiltration of data or as a command channel.

## ATT&CK Detection

|Technique|Subtechnique(s)|Tactic(s)|
|---|---|---|
|[Dynamic Resolution](https://attack.mitre.org/beta/techniques/T1568/)|[Domain Generation Algorithms](https://attack.mitre.org/beta/techniques/T1568/002/)|[Command and Control](https://attack.mitre.org/beta/tactics/TA0011/)|
|[Application Layer Protocol](https://attack.mitre.org/beta/techniques/T1071/)|[DNS](https://attack.mitre.org/beta/techniques/T1071/004/)|[Command and Control](https://attack.mitre.org/beta/tactics/TA0011/)|
|[Exfiltration Over Alternative Protocol](https://attack.mitre.org/beta/techniques/T1048/)|[Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](https://attack.mitre.org/beta/techniques/T1048/003/)|[Exfiltration](https://attack.mitre.org/beta/tactics/TA0010/)|

## Analytics

### Dynamic DNS

***Data Source:*** Network Flow Data, DNS logs

***Description:*** Isolate the log entries that contain domains hosted on dynamic DNS provider.

***Logic:***
```
Use a lookup list of Dynamic DNS providers to query against. (hopto.org,dyndns.org,no-ip.org,us.to etc)
select * from events where domain in <lookup list>
```
### Long Domains

***Data Source:*** Network Flow Data, DNS Logs

***Description:*** A domain name is limited to 253 characters long and each subdomain is limited to 63 characters. Looking for queries that are close to these values can indicate malicious use of DNS.

***Logic:***
```
cat dns.log | zeek-cut query | sort | uniq | awk '{ print length, $0 }' | sort -n -s
```
### DGA-like detection

***Data Source:*** Network Flow Data, DNS Logs

***Description:*** Detecting randomness using Mark Baggett's `freq.py` tool (see references)

***Logic:***
```
freq.exe --measure <domain name> <frequency table>
```
### Requests to thousands of hosts or subdomains in one domain

***Data Source:*** Network Metadata

***Description:*** Count how many unique subdomain queries were made per domain.

***Logic:***
```
cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head
```

## Atomic Tests


[T1071.004 - DNS](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md/)

1. [DNS Large Query Volume](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md/#atomic-test-1---dns-large-query-volume)

2. [DNS Regular Beaconing](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md/#atomic-test-2---dns-regular-beaconing)

3. [DNS Long Domain Query](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md/#atomic-test-3---dns-long-domain-query)

4. [DNS C2](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md/#atomic-test-4---dns-c2)
[T1048 - Exfiltration Over Alternative Protocol](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048/T1048.md/)

1. [Exfiltration Over Alternative Protocol - SSH](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048/T1048.md/#atomic-test-1---exfiltration-over-alternative-protocol---ssh)
2. [Exfiltration Over Alternative Protocol - SSH](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048/T1048.md/#atomic-test-2---exfiltration-over-alternative-protocol---ssh)

[T1048.003 - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md/)

1. [Exfiltration Over Alternative Protocol - HTTP](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md/#atomic-test-1---exfiltration-over-alternative-protocol---http)

2. [Exfiltration Over Alternative Protocol - ICMP](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md/#atomic-test-2---exfiltration-over-alternative-protocol---icmp)

3. [Exfiltration Over Alternative Protocol - DNS](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md/#atomic-test-3---exfiltration-over-alternative-protocol---dns)

## Hunter Notes



## Hunt Outputs



## References

- https://github.com/sans-blue-team/freq.py
- https://isc.sans.edu/diary/Detecting+Random+-+Finding+Algorithmically+chosen+DNS+names+%28DGA%29/19893
- https://www.ericconrad.com/2020/03/threat-hunting-via-dns.html
- https://activecm.github.io/threat-hunting-labs/dns/
- https://blog.redteam.pl/2019/08/threat-hunting-dns-firewall.html