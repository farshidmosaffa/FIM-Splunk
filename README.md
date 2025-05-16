# FIM-Splunk

File Integrity Monitoring (FIM) scripts for both **Windows** and **Linux**, designed to be lightweight, auditable, and compatible with SIEM tools like **Splunk**.

## Platforms

### [Windows Version](windows/README.md)
- Batch script (`Fim_integrated_to_splunk-windows.bat`)
- Works with Splunk Universal Forwarder
- Uses SHA256 hashing

### [Linux Version](linux/README.md)
- Shell script (`Fim_integrated_to_splunk-linux.sh`)
- Monitors sensitive paths like `/etc`, `/var`, `/usr/bin`
- Uses `sha256sum` and logs changes

---

### This project is licensed under the MIT License.
