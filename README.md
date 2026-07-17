# Splunk SIEM Home Lab — SSH Brute-Force Detection

A self-built SIEM lab demonstrating log pipeline architecture, endpoint telemetry
collection, and detection engineering in Splunk. Built to develop hands-on
blue-team / detection engineering skills relevant to SOC analyst, security
analyst, and IAM analyst roles.

## Overview

This project simulates a realistic SSH brute-force attack against a Windows
endpoint, captures the resulting telemetry through a full log pipeline, and
detects it using custom SPL correlation searches mapped to MITRE ATT&CK.

**What this demonstrates:**
- Standing up a Splunk Enterprise indexer on Linux
- Deploying and configuring Splunk Universal Forwarders on Windows
- Endpoint telemetry hardening with Sysmon (SwiftOnSecurity config)
- Writing detection logic in SPL, including handling real-world data quirks
  (case-sensitivity, sourcetype changes after TA installation)
- Mapping detections to MITRE ATT&CK
- Documenting findings in an analyst-style incident report

## Architecture

```
┌─────────────────────┐         ┌──────────────────────┐
│   Kali Linux         │         │  Windows 11 Victim    │
│   (Attacker)          │────────▶│  - Sysmon              │
│   Hydra brute-force   │  SSH    │  - OpenSSH Server       │
│                        │  :22    │  - Universal Forwarder  │
└─────────────────────┘         └───────────┬──────────┘
                                              │ TCP 9997
                                              ▼
                                  ┌──────────────────────┐
                                  │  Ubuntu Server         │
                                  │  Splunk Enterprise      │
                                  │  (Indexer + Search Head)│
                                  └──────────────────────┘
```

All VMs run on a VirtualBox host-only network, isolated from the host machine's
network.

**Stack:**
| Component | Details |
|---|---|
| Indexer | Splunk Enterprise 10.4.1 on Ubuntu Server 24.04 |
| Victim endpoint | Windows 11 (Home), Sysmon, OpenSSH Server |
| Forwarder | Splunk Universal Forwarder |
| Attacker | Kali Linux, Hydra v9.7 |
| Add-ons | Splunk Add-on for Microsoft Windows (CIM field extraction) |

## Repo Structure

```
├── README.md
├── detections/          → SPL detection queries
├── docs/                → Incident report, build notes
├── screenshots/         → Evidence from Splunk searches
└── configs/             → Sanitized inputs.conf / sysmonconfig used in the lab
```

## Detections

| Detection | Technique | File |
|---|---|---|
| Failed logon spike (volumetric) | T1110 | [`detections/failed_logon_spike.spl`](detections/failed_logon_spike.spl) |
| Brute-force → successful compromise | T1110.001 | [`detections/bruteforce_success.spl`](detections/bruteforce_success.spl) |

See [`docs/incident_report.md`](docs/incident_report.md) for the full write-up,
including attack timeline, false-positive analysis, and remediation
recommendations. A formatted Word version is also included.

## Key Technical Notes

A couple of real debugging findings worth calling out (documented in full in
the incident report):

- **Case-sensitivity bug**: Windows logs the same account with inconsistent
  casing across event types (`WindowsVic` on success events vs. `windowsvic`
  on failures). Since SPL field comparisons are case-sensitive, this silently
  split correlation results until normalized with `lower()`.
- **Sourcetype shift after TA install**: installing the Splunk Add-on for
  Microsoft Windows changed how incoming events were classified
  (`WinEventLog:Security` → `WinEventLog`), which broke existing searches
  until identified via `| stats count by sourcetype`.
- **Windows Event Log ACL permissions**: the Universal Forwarder's virtual
  service account (`NT SERVICE\SplunkForwarder`) initially lacked permission
  to subscribe to the Sysmon Operational log channel (`errorCode=5`),
  resolved by adding it to the local `Event Log Readers` group.

## Next Steps / Roadmap

- [ ] Add LSASS access detection (Sysmon Event ID 10) for credential dumping (T1003.001)
- [ ] Add PowerShell script block logging detection (Event ID 4104)
- [ ] Add source-IP correlation to reduce false positives on the brute-force detection
- [ ] Build a Splunk dashboard for failed logons / alert volume

## Author

Brandon White — [LinkedIn](https://www.linkedin.com/in/brandon-white-b62701177)
