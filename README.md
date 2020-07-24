# The Threat Hunt Library

A collection of organised hunts based of yaml files to create markdown pages for analyst use.

## Link to the [Threat Hunt Library](docs/index.md)

### Methodology

An important part of Threat Hunting sustainably is to create clear and concise documentation, in case someone needs to repeat your work, or take over from where you left off.

#### Hypothesis

A hunt should be drive by a tangible question or catalyst:

- Intelligence-driven
- Situational awareness
- Domain expertise

[Link to addition infomation](https://www.sans.org/reading-room/whitepapers/analyst/generating-hypotheses-successful-threat-hunting-37172)

From the these categories, you can generate a hypothesis that can start your hunt.

#### Analytics

Based off the term coined by MITRE, an analytic describes observed behavior for a tactic, technique or procedure (TTP). Each analytic has a `logic` field which can be used to generate your own searching or queries given your organisations tools.

Note: A TTP can have multiple analytics.

#### Testing

During your hunts, you may want to generate events or traffic based off the TTPs you are investigation to:

- Assess the data sets you are hunting with are providing the visibility you require
- Assessing existing controls and detections to provide feedback loop during hunting.

Each hunt will automatically map to the relevant Atomic Red Team test for the given techniques/subtechniques.

#### Hunt Output

The output of each hunt can vary immensely. It may include one or more of the examples below:

- New detection rule in SIEM based off analytics created in hunts
- Update to Group policy to harden identified gap
- Identified gaps in visibility that affected the hunt during
- Incident Response - identified legitimate incident
- Lessons learnt - Revisiting initial hypothesis

## Credit

Heavily based of scripts and resources from:

- [MITRE Cyber Analytics Repository](https://github.com/mitre-attack/car/) by MITRE

- [ThreatHunter-Playbook](https://github.com/hunters-forge/ThreatHunter-Playbook) by Cyb3rWard0g

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) by Red Canary

Each one of these projects are awesome in their own right!

## Details

The yaml files are located in `/hunts/*`

The script `generate-md.py` will create markdown pages in `/docs/hunts/` for each yaml file.

To add your own hunts:

1. Create a new .yaml file in `/hunts/*`
2. Run `generate-md.py` to generate the documentation

Note: Running `generate-md.py` will re-create all documentation including updating any MITRE ATT&CK techniques/subtechniques or new Atomic Red Team tests. It will also re-create `/docs/index.md` containing a list of all hunts.
