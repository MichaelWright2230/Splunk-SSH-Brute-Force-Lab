# Step-by-Step Splunk SSH Detection Lab

This guide documents the lab setup, log collection, detection search and investigation workflow. It uses the configuration and results recorded in my screenshots. Anything not verified is marked as a follow-up rather than assumed to be complete.

## References

- PacketHammer, [Part 1 — Ubuntu VM installs: Build a Real Threat Detection Lab with Splunk](https://www.youtube.com/watch?v=MUNeQDOdCIQ). This covers creating an Ubuntu Splunk VM and an Ubuntu target VM.
- [Ug111 — SSH Brute-Force Detection Lab](https://github.com/Ug111/ssh-brute-force-detection-splunk)
- [Gawade Rahul — SSH Brute-Force Detection Lab](https://github.com/gawaderahul21/ssh-bruteforce-detection-lab)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)

The references helped me understand the general workflow and how to document a similar project. The IP addresses and result counts below are from my own lab evidence.

## 1. Lab design and virtual machines

I used VMware Workstation to run three virtual machines. Keeping the test source, target and SIEM separate made it easier to follow where activity came from and where it was logged.

| Role | Hostname | IP shown in evidence | Purpose |
|---|---|---|---|
| Test source | Kali Linux | `192.168.128.130` | Generate test SSH attempts |
| Target | Ubuntu-Target | `192.168.128.128` | Run SSH and record authentication events |
| SIEM | Ubuntu-Splunk | `192.168.128.129` | Receive and search logs in Splunk |

The captured setup shows Splunk Web on TCP 8000 and forwarding on TCP 9997. These are the values shown in my lab and may change if rebuilt.

**Screenshot placeholders:** `screenshots/01-vm-setup.png` should show the VM list. `screenshots/02-network-configuration.png` should show the VM network/IP details.

## 2. Splunk installation and access

The Splunk VM acts as the central place to search authentication activity. The captured configuration identifies Splunk Enterprise 10.6.0.5 on Ubuntu-Splunk. I accessed Splunk Web on port 8000.

**Screenshot placeholder:** `screenshots/03-splunk-web.png` — Splunk Web open and readable. Hide credentials or tokens.

## 3. Forward Linux authentication logs

SSH authentication messages are recorded in `/var/log/auth.log` on Ubuntu-Target. These can include failed passwords, invalid usernames, source addresses and successful authentication events. The searches in this project use index `linux` and sourcetype `linux_secure`.

Validation search:

```spl
index=linux sourcetype="linux_secure"
```

The purpose is to confirm that data is arriving before building a detection. If events are missing, check the forwarder, receiver, TCP 9997 connectivity, file monitor and index/sourcetype.

**Screenshot placeholders:** `screenshots/04-forwarder-config.png` — forwarding configuration. `screenshots/05-linux-events.png` — authentication events in Splunk.

## 4. Generate controlled SSH failures

Kali Linux was the test source and Ubuntu-Target was the target. Hydra can automate repeated login attempts and generate authentication telemetry. Only run this test against systems you own or have explicit permission to test.

The source IP visible in the Splunk results was `192.168.128.130`; the target was `192.168.128.128`.

**Screenshot placeholder:** `screenshots/06-hydra-test.png` — the test output against your own lab target. Do not include real passwords or private information.

## 5. Search for failed authentication

I searched the collected events for failed-password and invalid-user messages:

```spl
index=linux sourcetype="linux_secure" ("Failed password" OR "Invalid user")
```

These are indicators of unsuccessful authentication, not automatic proof of malicious activity. Mistyped passwords and service misconfiguration can also create failures.

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

This uses fixed five-minute buckets, not a rolling five-minute window. The extraction expression also supports IPv4 only; both are limitations worth improving later.

**Screenshot placeholder:** `screenshots/11-five-minute-detection.png` — full query and results table, readable in one image if possible.

## 7. Review the counts

The captured search showed four qualifying buckets for `192.168.128.130` on 15 October 2026:

| Time bucket | Events |
|---|---:|
| 23:20 | 50 |
| 23:25 | 38 |
| 12:50 | 30 |
| 23:15 | 6 |
| Total of displayed rows | 124 |

The base search showed 148 events before aggregation. The displayed qualifying rows sum to 124, and I have not fully reconciled the difference. I would inspect raw events, the time range, possible duplicate ingestion and events where IP extraction failed before treating the count as complete.

**Screenshot placeholder:** `screenshots/08-failure-counts.png` — count search and time range, if separate from the final detection screenshot.

## 8. Configure and validate the alert

The captured configuration is named `Brute Force attempt -SSH` and shows a five-minute search range and schedule. This proves the configuration screen was set up, but it does not prove the alert fired or that a notification was delivered.

To validate it, check the saved search includes the threshold logic, generate fresh test events in the isolated lab, and review Splunk's triggered-alert view or history.

**Screenshot placeholders:** `screenshots/10-alert-settings.png` — configuration. `screenshots/12-alert-triggered.png` — add only after a real trigger is observed.

## 9. Investigate the successful login

A separate search showed an `Accepted password` event for account `michael` from `192.168.128.130`. It needs to be correlated with the test timing and checked against `/var/log/auth.log` on the target. It may have been expected during setup or testing; the event alone does not prove a compromise.

Questions to answer: Was the time during the test? Was the username expected? Do the local logs confirm it? Were there any related events afterward?

**Screenshot placeholders:** `screenshots/09-successful-login-review.png` — event details. `screenshots/13-login-investigation.png` — add after reviewing timestamps and local logs and writing a grounded conclusion.

## 10. Initial SOC assessment

The evidence supports repeated SSH authentication failures in the lab and multiple fixed five-minute buckets above the threshold. In a production SOC, I would validate the alert, identify source and target assets, check usernames, correlate successful logins, confirm whether the source is authorised, and document whether the activity is a true positive or benign.

These are recommended triage steps, not actions taken against a production system. The simulated behaviour maps broadly to [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/); this is not attribution to a real threat actor.

## Evidence file list

Place genuine screenshots in the `screenshots/` directory using the filenames above. Hide passwords, private keys, tokens and personal information. Do not create placeholder images or mark untested outcomes as verified.

## Conclusion and remaining validation

This lab provided practice with VM setup, Linux authentication logs, Splunk ingestion, SPL filtering, threshold-based detection and basic investigation. The key remaining checks are to reconcile 148 base-search events against the 124 displayed qualifying events, investigate the successful login, and capture evidence that the alert actually fires.
