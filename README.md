# Splunk SSH Brute-Force Detection Lab

I built this lab to practise collecting Linux authentication logs in Splunk and investigating repeated SSH login failures. I used VMware virtual machines, Ubuntu for the target and Splunk server, and Kali Linux to generate test activity against my own lab machine.

## Project documentation

- **[Step-by-step lab guide](step-by-step-lab-guide.md)** — setup, log forwarding, detection query, results, alert configuration, investigation and screenshot placeholders.
- [Investigation report](investigation-report.md)
- [Lab architecture](architecture.md)
- [Screenshot guide](SCREENSHOT-GUIDE.md)
- [Detection query](detections/ssh-brute-force-5min.spl)

## Lab setup

| Component | Details shown in my screenshots |
|---|---|
| Virtualisation | VMware Workstation |
| SIEM | Splunk Enterprise 10.6.0.5 |
| Splunk VM | Ubuntu-Splunk — `192.168.128.129` |
| Target VM | Ubuntu-Target — `192.168.128.128` |
| Test source | Kali Linux — `192.168.128.130` |
| Index / sourcetype | `linux` / `linux_secure` |
| Log source | `/var/log/auth.log` |
| Ports | 8000 (Splunk Web), 9997 (forwarding) |

These are the values visible in my screenshots and may change if I rebuild the lab.

## What I did

1. Set up Ubuntu virtual machines and checked network connectivity.
2. Installed Splunk Enterprise and opened Splunk Web.
3. Forwarded Linux authentication events into Splunk.
4. Used Kali to run repeated SSH login attempts against my Ubuntu target.
5. Searched for failed authentication events and extracted the source IP.
6. Grouped failures into fixed five-minute buckets and filtered for buckets with at least five matching events.
7. Opened the Splunk alert configuration for the detection.

## Detection search

```spl
index=linux sourcetype="linux_secure"
("Failed password" OR "Invalid user")
| rex field=_raw "from (?<attacker_ip>\\d{1,3}(?:\\.\\d{1,3}){3})"
| bin _time span=5m
| stats count AS failures by _time attacker_ip
| where failures >= 5
| sort - failures
```

This search extracts the IPv4 source address, groups events into fixed five-minute buckets and returns buckets with at least five matches. Fixed buckets are not the same as a rolling five-minute window.

## Results captured

The screenshot showed four qualifying buckets for `192.168.128.130` on 15 October 2026:

| Time bucket | Matching events |
|---|---:|
| 23:20 | 50 |
| 23:25 | 38 |
| 12:50 | 30 |
| 23:15 | 6 |
| **Total across these buckets** | **124** |

Splunk showed 148 events before aggregation in that view. These four rows total 124, so I still need to reconcile the difference against the raw events before treating the counts as a complete total.

I also found an `Accepted password` event for `michael` from the same source IP. I need to correlate its timestamp with the test run before deciding whether it was an expected login or related to the simulation.

## Alert status

I configured a scheduled alert named `Brute Force attempt -SSH`, with a five-minute search range and schedule. The screenshot confirms the configuration screen, but I have not captured proof that the alert actually triggered. I won't call it validated until I test it and capture the result.

## MITRE ATT&CK

The simulated repeated authentication failures are broadly relevant to [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/). This maps the behaviour tested in the lab; it does not claim a real attacker compromised a system.

## References

- [PacketHammer — Part 1: Ubuntu VM installs, Build a Real Threat Detection Lab with Splunk](https://www.youtube.com/watch?v=MUNeQDOdCIQ)
- [Ug111 — SSH Brute-Force Detection Lab](https://github.com/Ug111/ssh-brute-force-detection-splunk)
- [Gawade Rahul — SSH Brute-Force Detection Lab](https://github.com/gawaderahul21/ssh-bruteforce-detection-lab)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)

## Still to verify

- Check for duplicate events and reconcile the counts.
- Investigate the successful SSH login.
- Test the saved alert and capture a confirmed trigger.
- Upload the screenshots and remove any credentials or personal information before publishing.
