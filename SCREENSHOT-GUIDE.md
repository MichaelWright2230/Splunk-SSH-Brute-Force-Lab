# Screenshot Guide

Save your own screenshots in the `screenshots/` directory. Keep the images readable and hide passwords, tokens, private keys and personal contact details before publishing.

| Filename | What it should show |
|---|---|
| `01-vm-setup.png` | VMware list showing the lab VMs |
| `02-network-configuration.png` | VM IP addresses or network settings |
| `03-splunk-web.png` | Splunk Web opened successfully |
| `04-forwarder-config.png` | Forwarder destination and receiver port |
| `05-linux-events.png` | Linux authentication events in the `linux` index |
| `06-hydra-test.png` | Hydra test output against your own lab target |
| `07-failed-ssh-events.png` | Failed SSH events in Splunk |
| `08-failure-counts.png` | Search results grouped by source or user |
| `09-successful-login-review.png` | Accepted-password event that needs investigation |
| `10-alert-settings.png` | Scheduled alert configuration |
| `11-five-minute-detection.png` | Final SPL query and qualifying result table |
| `12-alert-triggered.png` | Fresh test showing the alert actually fired |
| `13-login-investigation.png` | Evidence explaining whether the successful login was expected |

## Adding the images

1. Open the `screenshots` folder in your local copy of this repository.
2. Copy the screenshots into that folder using the filenames above.
3. Commit and push them, or upload through GitHub's **Add file → Upload files** option.
4. Check the README links after uploading.

Only add a screenshot once you have captured it. The alert-triggered and login-investigation screenshots need additional testing; don't create example images or label untested results as verified.
