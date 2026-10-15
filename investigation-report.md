# SSH Brute-Force Investigation Report

## Summary

I used a small virtual lab to practise finding repeated SSH login failures in Splunk. The activity came from Kali Linux and was aimed at my own Ubuntu target. Linux authentication events were collected in Splunk, then I wrote a search to find repeated failures and tested a scheduled alert.

The screenshots show repeated failures from `192.168.128.130`. I also reviewed a successful SSH authentication event in the context of the lab activity.

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

The detection screenshot showed four qualifying buckets for `192.168.128.130`:

| Time bucket | Events |
|---|---:|
| 23:20 | 50 |
| 23:25 | 38 |
| 12:50 | 30 |
| 23:15 | 6 |
| Total across displayed buckets | 124 |

Another screenshot showed 148 events in the initial search. I captured the screenshots at different stages, and I ran another attack between those captures. This means the searches reflected activity from separate stages/runs and were not a direct comparison of the same event set. The four displayed qualifying buckets total 124 for the detection result shown. When presenting counts, the time range and test run should be included so they are not mistaken for a single fixed total.

## Alert validation

I configured the scheduled alert named `Brute Force attempt -SSH` with a five-minute search range and schedule, then tested it during the lab. The alert validation was successful. The screenshot of the configuration shows how it was set up; for the strongest portfolio evidence, include the separate triggered-alert/history screenshot at `screenshots/12-alert-triggered.png`.

## Successful-login event

A separate search returned an `Accepted password` event for account `michael` from `192.168.128.130`. I reviewed it in the context of the lab activity. Because the lab involved multiple stages and another attack run between screenshots, timestamps and the target's local authentication log are important to correctly interpret this event. The event should not be labelled a compromise without supporting evidence.

## Initial assessment

The evidence shows repeated SSH authentication failures in the lab, multiple five-minute buckets above the threshold, and a tested alert. In a production SOC, I would check the source host, target account, surrounding events and any successful logins before deciding on severity or response.

## Suggested response steps

1. Confirm source, target, username, timestamps and failure count.
2. Look for successful logins around the same time.
3. Check whether the source is an expected admin or automation machine.
4. If the activity is unauthorised, follow the incident response process and preserve the logs.
5. Record what was checked and why the activity was classified as a true or false positive.

These are recommended triage steps, not actions taken against a production system.

## Limitations and improvements

- Include the relevant search time range and test run with event counts.
- Ensure the alert-trigger evidence is included in the repository.
- Consider a rolling-window search and IPv6 support as improvements.
- Keep the successful-login conclusion tied to timestamps and local logs.

## MITRE ATT&CK

The behaviour simulated in the lab is broadly relevant to [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/). This is a technique mapping only, not attribution to a real threat actor.

## References

- [PacketHammer — Build a Real Threat Detection Lab with Splunk](https://www.youtube.com/watch?v=MUNeQDOdCIQ)
- [Ug111 — SSH Brute-Force Detection Lab](https://github.com/Ug111/ssh-bruteforce-detection-splunk)
- [Gawade Rahul — SSH Brute-Force Detection Lab](https://github.com/gawaderahul21/ssh-bruteforce-detection-lab)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
