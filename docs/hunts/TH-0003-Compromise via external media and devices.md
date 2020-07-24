# TH-0003-Compromise via external media and devices

***Creation Date:*** 2020/06/28

***Author:*** svch0st

***Target Platform:*** Windows

***Analytics:***

- Unique USB storage devices in EDR (Least Frequency of Occurence) - Microsoft Defender ATP

- Unique USB storage devices (Least Frequency of Occurence) - sigma, Security

## Hypothesis

Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes

## Description

When a piece of malware gets onto a USB flash drive, it may infect the devices into which that drive is subsequently plugged. 
The Windows autorun.inf file contains information on programs meant to run automatically when removable media (often USB flash drives and similar devices) are accessed by a Windows PC user.

## ATT&CK Detection

|Technique|Subtechnique(s)|Tactic(s)|
|---|---|---|
|[Replication Through Removable Media](https://attack.mitre.org/beta/techniques/T1091/)|N/A|[Initial Access](https://attack.mitre.org/beta/tactics/TA0001/), [Lateral Movement](https://attack.mitre.org/beta/tactics/TA0008/)|
|[Exfiltration Over Physical Medium](https://attack.mitre.org/beta/techniques/T1052/)|[Exfiltration over USB](https://attack.mitre.org/beta/techniques/T1052/001/)|[Exfiltration](https://attack.mitre.org/beta/tactics/TA0010/)|

## Analytics

### Unique USB storage devices in EDR (Least Frequency of Occurence)

***Data Source:*** Microsoft Defender ATP

***Description:*** Find USB storage devices that are unique to the organisation. Analyse the Vendor IDs and users to see if they are authorised to use such devices.

***Logic:***
```
let devices =
DeviceEvents
| where ActionType == "PnpDeviceConnected"
| extend parsed=parse_json(AdditionalFields)
| project 
    DeviceDescription=tostring(parsed.DeviceDescription),
    ClassName=tostring(parsed.ClassName),
    DeviceId=tostring(parsed.VendorIds),
    VendorIds=tostring(parsed.VendorIds),
    DeviceName, Timestamp ;
devices
| summarize TimesConnected=count(), FirstTime=min(Timestamp), LastTime=max(Timestamp) by DeviceId, DeviceDescription, ClassName, VendorIds, DeviceName
| join kind=leftanti 
  (devices | summarize Machines=dcount(DeviceName) by DeviceId, DeviceDescription, VendorIds | where Machines > 1)
  on DeviceId, DeviceDescription, VendorIds
| where ClassName in ("DiskDrive", "CDROM")
    or ClassName contains "nas"
    or ClassName contains "SCSI"
    or ClassName == "USB"
```
### Unique USB storage devices (Least Frequency of Occurence)

***Data Source:*** sigma, Security

***Description:*** Find USB devices that are unique to the organisation. Analyse the Vendor IDs and users to see if they are authorised to use such devices.

***Logic:***
```
https://raw.githubusercontent.com/Neo23x0/sigma/master/rules/windows/builtin/win_usb_device_plugged.yml

title: USB Device Plugged
id: 1a4bd6e3-4c6e-405d-a9a3-53a116e341d4
description: Detects plugged USB devices
references:
    - https://df-stream.com/2014/01/the-windows-7-event-log-and-usb-device/
    - https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/
status: experimental
author: Florian Roth
date: 2017/11/09
tags:
    - attack.initial_access
    - attack.t1200
logsource:
    product: windows
    service: driver-framework
detection:
    selection:
        EventID:
            - 2003  # Loading drivers
            - 2100  # Pnp or power management
            - 2102  # Pnp or power management
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: low
```

## Atomic Tests


## Hunter Notes

- Use https://the-sz.com/products/usbid/ to look up the VID and PID of the USB device to get additional information.

## Hunt Outputs

- A baseline of devices connected to the enterprise
- USB VID/PID safelist to deploy to endpoints

## References

- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=6416
- https://www.andreafortuna.org/2018/02/09/usb-devices-in-windows-forensic-analysis/
- https://the-sz.com/products/usbid/