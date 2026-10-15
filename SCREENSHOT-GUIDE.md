# Screenshot and Evidence Guide

This file tracks the evidence a reviewer should be able to find for the Splunk SSH brute-force detection lab.

Some screenshots are already embedded in [step-by-step-lab-guide.md](step-by-step-lab-guide.md) as GitHub attachment links.

## Evidence checklist

| Evidence | What it should show | Status from the repository review |
|---|---|---|
| VM setup and network | VMware VMs and private lab IP addresses | Embedded in the step-by-step guide |
| Splunk Web | Splunk Enterprise interface accessible | Embedded in the step-by-step guide |
| Forwarder configuration | Forwarder destination and port 9997 | Embedded in the step-by-step guide |
| Events arriving in Splunk | Events in index `linux` / sourcetype `linux_secure` | Embedded in the step-by-step guide |
| Test activity | Kali test output aimed at Ubuntu-Target | The guide currently has a placeholder for `screenshots/06-hydra-test.png`; no local screenshot file was listed at the repository root |
| Failed SSH events | Failed-password or invalid-user messages | Embedded in the step-by-step guide |
| Detection results | SPL query and five-minute bucket counts | Embedded in the step-by-step guide |
| Alert settings | Alert name, schedule and trigger conditions | Embedded in the step-by-step guide |
| Alert triggered/history | A result or history entry showing the alert actually fired | Not clearly shown by the alert-settings screenshots; add direct trigger/history evidence if available |
| Successful login review | The `Accepted password` event and timestamp | Embedded in the step-by-step guide |
