# Lab Architecture

The lab uses three virtual machines:

- **Kali Linux** (`192.168.128.130`) generated the SSH test activity.
- **Ubuntu-Target** (`192.168.128.128`) received the attempts and records authentication events in `/var/log/auth.log`.
- **Ubuntu-Splunk** (`192.168.128.129`) runs Splunk Enterprise and searches the forwarded logs.

The screenshots show Splunk Web on TCP 8000 and a configured forwarding receiver on TCP 9997.

```text
Kali Linux — 192.168.128.130
       | SSH test attempts
       v
Ubuntu-Target — 192.168.128.128
       | /var/log/auth.log
       v
Log forwarding — TCP 9997
       v
Ubuntu-Splunk — 192.168.128.129
       | Splunk search and alert
       v
Detection results and investigation
```

The addresses are the ones shown in my lab evidence and may change if I rebuild the virtual network. This diagram describes the intended log flow; it is not a packet capture proving every connection.
