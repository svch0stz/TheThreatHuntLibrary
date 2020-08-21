# TH-0002-C2 Beaconing and Exfiltration via Standard Protocols

***Creation Date:*** 2020/06/28

***Author:*** svch0st

***Target Platform:*** Network

***Analytics:***

- HTTP/S User Agents (Least Frequency of Occurence) - Proxy, Network Flow Data

- Beaconing and Session Timing using RITA - Network Flow Data

- Data uploaded per Source/Destination pair - Network Flow Data, Proxy

- High counts of HTTP Errors by status code - Proxy

## Hypothesis

Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic

## Description

Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.
Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, or DNS. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP.

## ATT&CK Detection

|Technique|Subtechnique(s)|Tactic(s)|
|---|---|---|
|[Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|[Web Protocols](https://attack.mitre.org/techniques/T1071/001/), [File Transfer Protocols](https://attack.mitre.org/techniques/T1071/002/), [Mail Protocols](https://attack.mitre.org/techniques/T1071/003/), [DNS](https://attack.mitre.org/techniques/T1071/004/)|[Command and Control](https://attack.mitre.org/tactics/TA0011/)|

## Analytics

### HTTP/S User Agents (Least Frequency of Occurence)

***Data Source:*** Proxy, Network Flow Data

***Description:*** Unusual or rare user agents - Get a list of rare user agents and start looking at some that stand out. Baseline what you expect from within your organisation.

***Logic:***
```
Psuedo-search on Proxy Logs
      select useragent,count(*) from events
      where useragent is NOT NULL
      group by useragent

Zeek Data
      cat http.log | zeek-cut user_agent | sort | uniq -c | sort -n
```
### Beaconing and Session Timing using RITA

***Data Source:*** Network Flow Data

***Description:*** Many RATs communicate with a fixed heartbeat and others keep a session open for long periods of time.

***Logic:***
```
RITA (see references)
      rita show-beacons <dataset name>
```
### Data uploaded per Source/Destination pair

***Data Source:*** Network Flow Data, Proxy

***Description:*** Calculate bytes out or bytes transferred per Source IP and Destination IP pairs in a given period

***Logic:***
```
cat conn.*log | bro-cut id.orig_h id.resp_h orig_bytes | sort | grep -v -e '^$' | grep -v '-' | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10
```
### High counts of HTTP Errors by status code

***Data Source:*** Proxy

***Description:*** List the URLs that only have HTTP errors

***Logic:***
```
TODO
```

## Atomic Tests


[T1071.001 - Web Protocols](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md/)

1. [Malicious User Agents - Powershell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md/#atomic-test-1---malicious-user-agents---powershell)

2. [Malicious User Agents - CMD](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md/#atomic-test-2---malicious-user-agents---cmd)

3. [Malicious User Agents - Nix](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md/#atomic-test-3---malicious-user-agents---nix)

[T1071.004 - DNS](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md/)

1. [DNS Large Query Volume](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md/#atomic-test-1---dns-large-query-volume)

2. [DNS Regular Beaconing](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md/#atomic-test-2---dns-regular-beaconing)

3. [DNS Long Domain Query](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md/#atomic-test-3---dns-long-domain-query)

4. [DNS C2](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md/#atomic-test-4---dns-c2)

## Hunter Notes

* TODO 

## Hunt Outputs

['Potential baseline of user agents. Possibility if a SIEM rule to alert on only newly observed useragents']

## References

- https://activecm.github.io/threat-hunting-labs/beacons/
- https://activecm.github.io/threat-hunting-labs/outliers/
- RITA - https://github.com/activecm/rita