# Build and Investigation Walkthrough

This page records the workflow used for my Splunk SSH authentication lab. I used the PacketHammer video series as a guide for the general lab structure, then documented the settings and search results visible in my own screenshots. The video is a reference, not proof that every setting below matches its exact sequence.

Video reference: [Part 1 — Ubuntu VM installs — Build a Real Threat Detection Lab with Splunk](https://www.youtube.com/watch?v=MUNeQDOdCIQ).

## 1. Objective

The aim was to build a small lab where Linux authentication activity could be collected centrally, searched in Splunk, and used to identify repeated SSH login failures. The exercise follows a basic SOC workflow:

1. Generate activity in a controlled environment.
2. Record it in the target system's authentication logs.
3. Forward the events to Splunk.
4. Search and aggregate the events.
5. Review the detection results and alert configuration.
6. Investigate any successful authentication events instead of assuming what they mean.

## 2. Lab requirements

### Software and components

- VMware Workstation for virtual machines.
- Ubuntu VM to run Splunk Enterprise.
- Ubuntu VM as the SSH target.
- Kali Linux VM as the test source.
- Splunk Enterprise 10.6.0.5.
- Linux authentication logging at `/var/log/auth.log`.
- Splunk log forwarding, with TCP 9997 shown in the configuration.
- Splunk Web, accessed on TCP 8000.
- Hydra for generating repeated SSH login attempts inside the lab.

Use an isolated virtual network and only run test activity against systems you own or are authorised to test. Keep the target's test credentials separate from any real account.

### Observed VM details

| VM | Hostname | Address observed |
|---|---|---|
| Splunk server | Ubuntu-Splunk | `192.168.128.129` |
| SSH target | Ubuntu-Target | `192.168.128.128` |
| Test source | Kali Linux | `192.168.128.130` |

These values are recorded from the screenshots supplied for this project. IP addresses can change after a VM network is rebuilt, so confirm them on the running machines before using them.

<img width="1909" height="987" alt="01-vm-setup png" src="https://github.com/user-attachments/assets/1967a45f-2bb0-4869-8d34-ab3622a7d06c" />

## 3. Prepare the Ubuntu machines

I used separate Ubuntu machines for the target and Splunk server so that authentication events could be collected from one machine and searched on another.

The target needed an SSH service so it could receive test logins and write authentication events. The Splunk VM needed network access to receive the forwarded log data and a browser-accessible Splunk Web interface.

Checks to record during a rebuild:
- Both VMs start without errors.
- Each VM has the expected IP address.
- The target can be reached from the test VM on the lab network.
- The Splunk interface is reachable from the host or lab browser.
- The target's authentication log is being updated during test logins.

Don't publish passwords, private keys or other credentials in screenshots or configuration files.

<img width="1722" height="978" alt="02-network-configuration png" src="https://github.com/user-attachments/assets/462fe7b4-e324-42d0-8aac-6fb69f20332a" />

## 4. Install and open Splunk Enterprise

Splunk Enterprise was installed on Ubuntu-Splunk. The interface shown in the screenshots is Splunk Enterprise 10.6.0.5, accessed over TCP 8000.

After installation, the useful validation was to open Splunk Web and check that the instance was running before configuring ingestion. A running interface alone does not prove that source logs are arriving; ingestion must be checked separately.

<img width="1723" height="978" alt="03-splunk-installed png" src="https://github.com/user-attachments/assets/8c61cb3e-ad86-4b3a-92c8-100544c38329" />

## 5. Configure log forwarding

The target's Linux authentication logs were sent to Splunk so that searches could be performed centrally. The screenshots show a forwarding receiver on TCP 9997 and the `linux` index with sourcetype `linux_secure`.

The source log used for this exercise was:

```text
/var/log/auth.log
```

The key validation is that new authentication events appear in Splunk after a login attempt is made on the target. If events do not arrive, check the forwarding destination, receiver status, network reachability and the index/sourcetype selected for the data.

<img width="713" height="346" alt="05-forwarder-config" src="https://github.com/user-attachments/assets/a7245977-b250-4ce6-ba69-410c0e20680a" />

## 6. Generate test authentication activity

Kali Linux was used as the test source, with address `192.168.128.130`. Repeated SSH login attempts were sent to the Ubuntu target at `192.168.128.128`. The purpose was to create failed-authentication telemetry for analysis.

Only generate this activity against your own isolated lab target. Use a small test account and controlled test inputs rather than attempting logins against public or third-party systems.

The expected defensive evidence is repeated failure messages in the target's authentication log and corresponding events in Splunk. The event text commonly includes the attempted account and source address, but the exact fields depend on the log message and Splunk parsing.

**Screenshot placeholder —** Add `screenshots/06-hydra-test.png` showing the test command/output with any passwords or sensitive values hidden. Add `screenshots/07-failed-ssh-events.png` showing matching failed SSH events in Splunk.

## 7. Validate event collection before detection

Before writing the threshold search, I checked the `linux` index and `linux_secure` sourcetype for authentication events. A basic search is:

```spl
index=linux sourcetype="linux_secure"
```

To focus on the failed attempts:

```spl
index=linux sourcetype="linux_secure" ("Failed password" OR "Invalid user")
```

The first search checks whether data exists in the expected index and sourcetype. The second narrows the events to common failed-authentication messages. Review a few raw events to make sure the search is matching the intended test, not unrelated authentication activity.

<img width="1713" height="967" alt="08-failure-counts png" src="https://github.com/user-attachments/assets/ea2ce573-0bd4-4a89-b4a9-4c3145121350" />

## 8. Build the detection search

The saved detection is in [detections/ssh-brute-force-5min.spl](detections/ssh-brute-force-5min.spl).

```spl
index=linux sourcetype="linux_secure"
("Failed password" OR "Invalid user")
| rex field=_raw "from (?<attacker_ip>\\d{1,3}(?:\\.\\d{1,3}){3})"
| bin _time span=5m
| stats count AS failures by _time attacker_ip
| where failures >= 5
| sort - failures
```

What each part does:

1. `index=linux sourcetype="linux_secure"` limits the search to the configured Linux authentication data.
2. `("Failed password" OR "Invalid user")` selects common failure messages.
3. `rex` extracts an IPv4 address from raw text after the word `from`.
4. `bin _time span=5m` groups events into fixed five-minute time buckets.
5. `stats count AS failures by _time attacker_ip` counts matching events per bucket and source.
6. `where failures >= 5` keeps only buckets meeting the threshold.
7. `sort - failures` places the largest counts first.

This query has limitations: it uses fixed five-minute buckets rather than a rolling window, and its regular expression handles IPv4 addresses only. Events that do not match the source-IP expression may not appear in the grouped output. For a stronger production detection, I would test field extraction against the raw events, consider grouping by both source and target account, and tune the threshold against normal login noise.

<img width="1231" height="75" alt="11-event-details" src="https://github.com/user-attachments/assets/886bdd48-200d-4704-bf95-34e0875c8fd8" />

## 9. Interpret the observed results

The supplied screenshot showed four qualifying buckets for `192.168.128.130` on 15 October 2026:

| Time bucket | Matching events |
|---|---:|
| 23:20 | 50 |
| 23:25 | 38 |
| 12:50 | 30 |
| 23:15 | 6 |
| Total of displayed rows | 124 |

The search view also showed 148 events before aggregation. The four listed rows sum to 124, which means there is a difference of 24 events that I have not fully explained. I have not treated 124 as the total number of all failed events. A proper follow-up is to inspect raw events, confirm the search time range and timezone, and check whether some events had no extracted IPv4 address or did not meet the bucket threshold.

## 10. Review the successful authentication event

A separate search showed an `Accepted password` event for account `michael` from `192.168.128.130`. A successful login appearing near failed attempts is worth reviewing, but it does not automatically prove a compromise.

To investigate, compare the timestamp against the test run, inspect the corresponding entry in `/var/log/auth.log` on Ubuntu-Target, and check whether the account and source match the expected lab activity. Record what the evidence supports and avoid drawing a conclusion from the event text alone.

<img width="1723" height="957" alt="09-successful-login-review png" src="https://github.com/user-attachments/assets/8869611b-7fbc-4f38-883c-d1ffa7f3e9ab" />

## 11. Configure and validate the alert

The screenshots show a scheduled alert named `Brute Force attempt -SSH` configured with a five-minute search range and schedule. That is evidence of configuration, but it is not evidence that the alert successfully fired or that a notification was delivered.

Before treating the alert as complete:
1. Open the saved search and confirm it contains the threshold detection logic.
2. Confirm the schedule and search time range are appropriate for the intended detection.
3. Generate fresh, controlled failed-login activity in the lab.
4. Check the alert history or triggered-alert view for the new event.
5. If email actions are configured, verify delivery separately.
6. Record any tuning needed to avoid repeated or noisy alerts.

<img width="652" height="729" alt="saved alert part 1" src="https://github.com/user-attachments/assets/87e72c64-e291-4ff8-acc0-7c0a7e51ea1e" />

<img width="636" height="721" alt="saved alert 2" src="https://github.com/user-attachments/assets/08f53ce4-0bdd-4945-b8c3-6d75ec47aa84" />

## 12. MITRE ATT&CK mapping

The simulated repeated authentication failures broadly relate to [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/). This is a mapping of the behaviour exercised in the lab, not a claim that a real threat actor was involved.

## 13. What I learned

This exercise helped me connect endpoint log generation with SIEM ingestion and detection. The main lesson was that finding a high count is only one part of the investigation. I also need to validate the event fields, check the search time range, understand why totals differ, and correlate successful logins before deciding whether the activity is suspicious.

## 14. References

- PacketHammer, [Part 1 — Ubuntu VM installs — Build a Real Threat Detection Lab with Splunk](https://www.youtube.com/watch?v=MUNeQDOdCIQ). Used as a reference for the overall lab-building approach.
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [ShamellJordan — SSH Brute Force Splunk](https://github.com/ShamellJordan/ssh-brute-force-splunk)
- [Ug111 — SSH Brute-Force Detection Lab](https://github.com/Ug111/ssh-brute-force-detection-splunk)

The linked community repositories are examples of how similar projects document detection logic and evidence. Their results are not used as my own results.
