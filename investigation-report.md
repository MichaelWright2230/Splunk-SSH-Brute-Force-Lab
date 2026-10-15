# SSH Brute-Force Investigation Report

## Summary

I used a small virtual lab to practise finding repeated SSH login failures in Splunk. The activity came from Kali Linux and was aimed at my own Ubuntu target. Linux authentication events were collected in Splunk, then I wrote a search to find repeated failures.

The screenshots show repeated failures from `192.168.128.130`. A successful SSH authentication event also appeared and needs checking before I can say what caused it.

## Environment

| Component | Configuration shown |
|---|---|
| Virtualisation | VMware Workstation |
| SIEM | Splunk Enterprise 10.6.0.5 on Ubuntu-Splunk |
| Splunk address | 192.168.128.129 |
| Target | Ubuntu-Target, 192.168.128.128 |
| Test source | Kali Linux, 192.168.128.130 |
| Index / sourcetype | `linux` / `linux_secure` |
| Log file | `/var/log/auth.log` |
| Ports | 8000 for Splunk Web; 9997 for forwarding |

## Method

I set up the VMs, checked that Splunk Web was available, and confirmed Linux authentication events appeared in the `linux` index. I then used Hydra from Kali to generate repeated SSH login attempts against the Ubuntu target in my lab.

Initial validation search:

```spl
index=linux sourcetype="linux_secure"
```

Search for failed authentication:

```spl
index=linux sourcetype="linux_secure" ("Failed password" OR "Invalid user")
```

Threshold detection:

```spl
index=linux sourcetype="linux_secure"
("Failed password" OR "Invalid user")
| rex field=_raw "from (?<attacker_ip>\\d{1,3}(?:\\.\\d{1,3}){3})"
| bin _time span=5m
| stats count AS failures by _time attacker_ip
| where failures >= 5
| sort - failures
```

The search selects failed-password and invalid-user messages, extracts the IPv4 source address, groups events into fixed five-minute buckets, and returns buckets with five or more matches. This is not a rolling five-minute window.

## Observed results

The screenshot showed four qualifying buckets for `192.168.128.130` on 15 October 2026:

| Time bucket shown | Events |
|---|---:|
| 23:20 | 50 |
| 23:25 | 38 |
| 12:50 | 30 |
| 23:15 | 6 |
| Total of displayed rows | 124 |

The base search showed 148 events before aggregation. The four qualifying rows total 124, but the difference has not been fully reconciled. I would inspect the raw events and check whether some events did not have an extracted IP or fell outside the qualifying buckets.

## Alert configuration

I configured a scheduled alert named `Brute Force attempt -SSH`. The screenshot shows a five-minute search range and a five-minute schedule. It does not prove the alert triggered or that a notification was delivered. To validate it, I need to ensure the saved search includes the threshold logic, generate fresh test activity, and capture the alert firing.

## Successful-login event

A separate search returned an `Accepted password` event for account `michael` from `192.168.128.130`. I need to compare the timestamp with the test run and review `/var/log/auth.log` on the target. It may have been an expected login during setup or testing. The screenshot alone does not prove unauthorised access.

## Initial assessment

The evidence supports that repeated SSH authentication failures were present in the lab and that the SPL search found multiple five-minute buckets above the threshold. In a real SOC, I would check the source host, target account, surrounding events and any successful logins before deciding on severity or response.

## Suggested response steps

1. Confirm source, target, username, timestamps and failure count.
2. Look for successful logins around the same time.
3. Check whether the source is an expected admin or automation machine.
4. If the activity is unauthorised, follow the incident response process and preserve the logs.
5. Record what was checked and why the alert was classified as a true or false positive.

These are suggested triage steps, not actions taken against a production system.

## Limitations and next steps

- Reconcile the 148 base-search events with the 124 events in qualifying buckets.
- Check whether duplicate ingestion affected the counts.
- Investigate the successful login and document its context.
- Test the alert against fresh activity and capture proof it triggered.
- Consider a rolling-window search and IPv6 support as improvements.

## MITRE ATT&CK

The behaviour simulated in the lab is broadly relevant to [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/). This is a technique mapping only, not attribution to a real threat actor.

## References

- [ShamellJordan — SSH Brute Force Splunk](https://github.com/ShamellJordan/ssh-brute-force-splunk)
- [Ug111 — SSH Brute-Force Detection Lab](https://github.com/Ug111/ssh-bruteforce-detection-splunk)
- [Guscyrus-cyber — Splunk SSH Brute Force Detection Lab](https://github.com/Guscyrus-cyber/splunk-ssh-bruteforce-detection-lab)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
