# Step-by-Step Splunk SSH Detection Lab

This guide documents the lab setup, log collection, detection search and investigation workflow using the configuration and results recorded from my lab.

## References

- PacketHammer, [Part 1 — Ubuntu VM installs: Build a Real Threat Detection Lab with Splunk](https://www.youtube.com/watch?v=MUNeQDOdCIQ)
- [Ug111 — SSH Brute-Force Detection Lab](https://github.com/Ug111/ssh-brute-force-detection-splunk)
- [Gawade Rahul — SSH Brute-Force Detection Lab](https://github.com/gawaderahul21/ssh-bruteforce-detection-lab)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)

The references helped me understand the general workflow. The configuration and results below are based on my own lab.

## 1. Lab design and virtual machines

I used VMware Workstation to run three virtual machines. Keeping the test source, target and SIEM separate made it easier to follow where activity came from and where it was logged.

| Role | Hostname | IP shown in evidence | Purpose |
|---|---|---|---|
| Test source | Kali Linux | `192.168.128.130` | Generate test SSH attempts |
| Target | Ubuntu-Target | `192.168.128.128` | Run SSH and record authentication events |
| SIEM | Ubuntu-Splunk | `192.168.128.129` | Receive and search logs in Splunk |

The captured setup shows Splunk Web on TCP 8000 and forwarding on TCP 9997.

<img width="1909" height="987" alt="01-vm-setup png" src="https://github.com/user-attachments/assets/a07aec1d-bb83-4300-a98f-1dd18c6a22c5" />

<img width="1722" height="978" alt="02-network-configuration png" src="https://github.com/user-attachments/assets/f301f162-1dbb-441c-a3ba-09a18c59ad82" />

## 2. Splunk installation and access

The Splunk VM acts as the central place to search authentication activity. The captured configuration identifies Splunk Enterprise 10.6.0.5 on Ubuntu-Splunk. I accessed Splunk Web on port 8000.

**Screenshot placeholder:** `screenshots/03-splunk-web.png` — Splunk Web open and readable. Hide credentials or tokens.

## 3. Forward Linux authentication logs

SSH authentication messages are recorded in `/var/log/auth.log` on Ubuntu-Target. The searches use index `linux` and sourcetype `linux_secure`.

Validation search:

```spl
index=linux sourcetype="linux_secure"
```

**Screenshot placeholders:** `screenshots/04-forwarder-config.png` — forwarding configuration. `screenshots/05-linux-events.png` — authentication events in Splunk.

## 4. Generate controlled SSH failures

Kali Linux was the test source and Ubuntu-Target was the target. Hydra was used to generate repeated SSH login attempts in the lab. Only run this test against systems you own or have explicit permission to test.

**Screenshot placeholder:** `screenshots/06-hydra-test.png` — test output against your own lab target. Hide passwords and private information.

## 5. Search for failed authentication

```spl
index=linux sourcetype="linux_secure" ("Failed password" OR "Invalid user")
```

These events indicate unsuccessful authentication, not automatic proof of malicious activity.

**Screenshot placeholder:** `screenshots/07-failed-ssh-events.png` — failed SSH events with timestamps and source details visible.

## 6. Detection search

The saved search is in `detections/ssh-brute-force-5min.spl`:

```spl
index=linux sourcetype="linux_secure"
("Failed password" OR "Invalid user")
| rex field=_raw "from (?<attacker_ip>\\d{1,3}(?:\\.\\d{1,3}){3})"
| bin _time span=5m
| stats count AS failures by _time attacker_ip
| where failures >= 5
| sort - failures
```

- The first line limits the data to the Linux authentication index and sourcetype.
- The message filter selects failed-password and invalid-user events.
- `rex` extracts an IPv4 source address from the raw message.
- `bin` groups timestamps into fixed five-minute buckets.
- `stats` counts matching events per bucket and source IP.
- `where` keeps buckets with at least five events.
- `sort` puts the largest counts first.

This uses fixed five-minute buckets, not a rolling five-minute window. The extraction expression also supports IPv4 only.

**Screenshot placeholder:** `screenshots/11-five-minute-detection.png` — full query and results table.

## 7. Interpret the counts in context

The detection screenshot showed four qualifying buckets for `192.168.128.130`:

| Time bucket | Events |
|---|---:|
| 23:20 | 50 |
| 23:25 | 38 |
| 12:50 | 30 |
| 23:15 | 6 |
| Total of displayed rows | 124 |

Another screenshot showed 148 events in the initial search. There was a gap between capturing the screenshots, and I ran another attack during that gap. The screenshots therefore show different stages/runs of the test activity, rather than two counts from the same unchanged event set. The four qualifying rows total 124 for the detection result shown.

**Screenshot placeholder:** `screenshots/08-failure-counts.png` — count search and time range, if separate from the final detection screenshot.

## 8. Configure and validate the alert

I configured the scheduled alert named `Brute Force attempt -SSH` with a five-minute search range and schedule, then tested it during the lab. The alert validation was successful.

**Screenshot placeholders:** `screenshots/10-alert-settings.png` — alert configuration. `screenshots/12-alert-triggered.png` — triggered alert/history evidence.

## 9. Review the successful login

A separate search showed an `Accepted password` event for account `michael` from `192.168.128.130`. I considered it in the context of the lab's multiple stages. Compare the timestamp with the attack run and use the target's local authentication log to explain the event accurately; the event alone does not prove compromise.

**Screenshot placeholders:** `screenshots/09-successful-login-review.png` — event details. `screenshots/13-login-investigation.png` — final explanation supported by the timestamps/logs.

## 10. SOC assessment and MITRE ATT&CK

The lab demonstrated repeated SSH authentication failures, threshold-based detection and alert validation. In a production SOC, I would confirm the source and target, review surrounding events, correlate successful logins, and decide whether the activity was authorised.

The simulated behaviour broadly maps to [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/). This is a technique mapping, not attribution to a real threat actor.

## Evidence files

Place genuine screenshots in the `screenshots/` directory using the filenames above. Hide passwords, private keys, tokens and personal information before publishing.
