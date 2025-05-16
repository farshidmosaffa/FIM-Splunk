# FIM-Splunk

This repository contains a lightweight **File Integrity Monitoring (FIM)** script for Windows and Linux, written in `(.bat)` and `(.sh)` format, designed to work with **Splunk Universal Forwarder**.

##  Features

- SHA256 hashing of critical system files and folders
- Detects file changes, deletions, and restorations
- Logs output in a format compatible with Splunk ingestion

##  Use Case

This script is intended for environments where:
- Agents like Wazuh or OSSEC are too heavy
- You want a simple and auditable FIM setup
- Integration with Splunk is required

##  How to Use

Windows:
1. Copy the script to:  
   `C:\Program Files\SplunkUniversalForwarder\etc\apps\FIM\bin\Fim_integrated_to_splunk-windows.bat`

2. Schedule it using:
   - Windows Task Scheduler **or**
   - Configure `inputs.conf` in Splunk to run every X minutes (recommand)


Linux:
1. Copy the script to:  
   `\opt\spllunkforwarder\bin\scripts\Fim_integrated_to_splunk-linux.sh`

2. Schedule it using:
   - Cronjob **or**
   - Configure `inputs.conf` in Splunk to run every X minutes (recommand)

3. Logs will be saved locally or sent to Splunk depending on setup.
   
##  Important Paths Monitored
###customise this by organization needed

 - `%SystemRoot%\System32\drivers\etc\hosts`
 - `%SystemRoot%\System32\GroupPolicy`
 - C:\Windows\debug
 - "/etc/passwd"
 - "/etc/shadow"
 - "/etc/group"
 - "/etc/ssh/sshd_config"
 - "/etc/sudoers"
 - "/etc/hosts"
 - "/etc/services"
 - "/etc/resolv.conf"
 - "/etc/apt/sources.list"
 - "/etc/apt/sources.list.d"
 - "/etc/apt/trusted.gpg.d"
 - "/etc/systemd"
 - "/etc/network"
 - "/var/lib/systemd"
 - "/boot"
 - "/etc/crontab"
 - "/etc/cron.d"
 - "/etc/cron.daily"
 - "/etc/cron.hourly"
 - "/etc/cron.weekly"
 - "/etc/audit/audit.rules"
 - "/etc/selinux/config"
 - "/etc/profile"
 - "/root/.bash_history"
 - "/etc/nginx"
 - Custom paths can be configured in the script.

##  configure splunk inputs.conf

[script://.\bin\Fim_integrated_to_splunk-windows.bat]
disabled = 0
index = windows
interval = 60

[monitor://C:\Program Files\SplunkUniversalForwarder\etc\apps\FIM\fim_output.log]
disabled = false
index = windows
sourcetype = fim
interval = 120

[script:///opt/splunkforwarder/bin/scripts/Fim_integrated_to_splunk-linux.sh]
disabled = false
index = linux
interval = 60

[monitor:///opt/splunkforwarder/fim/fim_output.log]
disabled = false
index = linux
sourcetype = fim
interval = 120

##  License

This project is licensed under the MIT License.
