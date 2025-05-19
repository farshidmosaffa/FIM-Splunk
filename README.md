
# File Integrity Monitoring (FIM) integrated with Splunk

This repository contains a lightweight **File Integrity Monitoring (FIM)** system for **Windows** and **Linux**, written in `.bat`, `.ps1`, and `.sh` formats, designed to work with **Splunk Universal Forwarder**.

---

##  Windows Versions

I provide **two separate implementations** for Windows:

### 1. Batch Version
- File: `Fim_integrated_to_splunk-windows.bat`
- Detects file changes, deletions, and restorations
- SHA256 hashing of critical system files and folders
- Basic integration with Splunk using inputs.conf
- Lightweight and easy to deploy

### 2. PowerShell Version(Recommended)
- Main script: `FIM.ps1`
- Setup script: `setup_task.ps1`
- CMD runners: `run_fim.cmd`, `setup_task.cmd`
- **Multithreaded execution**
- Reports include: file path, new hash, **deleted files**, **modified files**, **created files**, changed size, last modified time, and **user who made the change**
- High performance and detailed logs
- Execution is fully automated

### 🔧 Components of the PowerShell System:
- `FIM.ps1`: Main integrity scanner 
- `setup_task.ps1`: Schedules regular scanning
- `run_fim.cmd`: Calls `FIM.ps1` from scheduled task
- `setup_task.cmd`: Calls `setup_task.ps1` via Splunk

---

##  Linux Version

- Script: `Fim_integrated_to_splunk-linux.sh`
- Uses `sha256sum`
- Monitors key system files and folders
- Suitable for crontab-based scheduling or Configure inputs.conf in Splunk to run every X minutes (recommanded)

1. Copy the script to:  
   `\opt\splunkforwarder\bin\scripts\Fim_integrated_to_splunk-linux.sh`

2. Schedule it using:
   - Cronjob **or**
   - Configure `inputs.conf` in Splunk to run every X minutes (recommanded)

3. Logs will be saved locally or sent to Splunk depending on setup.
```
[script:///opt/splunkforwarder/bin/scripts/create_initial_hash-linux.sh]
interval = 3600
disabled = false
index = linux

[monitor:///opt/splunkforwarder/fim/fim_output.log]
disabled = false
index = rbc_linux
sourcetype = fim
```


##  Use Case

This script is ideal when:

- Agents like Wazuh or OSSEC are too heavy
- You want a simple, auditable FIM setup
- Integration with **Splunk** is required

---

##  Splunk Integration & Execution Guide for windows(powershell)

You can package all 4 PowerShell-related files into a **Splunk App** such as `TA_FIM`, with this structure:

```
TA_FIM/
├── bin/
│   ├── FIM.ps1
│   ├── setup_task.ps1
│   ├── run_fim.cmd
│   └── setup_task.cmd
└── local/
    └── inputs.conf
```

### `inputs.conf` example:
```
# Run setup task at Splunk startup and daily
[script://.\bin\setup_task.cmd]
disabled = 0
interval = 86400
sourcetype = fim_setup
index = windows

# Monitor FIM logs
[monitor://C:\FIM\fim_log.json]
disabled = 0
sourcetype = fim_log_json
index = windows
followTail = 0
crcSalt = 

# Monitor FIM logs
[monitor://C:\FIM\fim_report.txt]
disabled = 0
interval = 60
sourcetype = fim_report
index = windows
followTail = 0
crcSalt = <SOURCE>

```

- Baseline file: `baseline.json`
- Report log: `fim_report.txt`

### `props.conf` (Deploy on HF or Indexer):
```
[fim_report]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)===== FIM_CHANGE_START =====
TRUNCATE = 20000
NO_BINARY_CHECK = true
TIME_FORMAT = %Y-%m-%d %H:%M:%S
MAX_EVENTS = 1000

```

> All files are dropped under default folder `FIM`.

---

##  Important Monitored Paths

### Windows ###Change this, if needed.
```
"C:\Windows\System32\drivers",
    "C:\Windows\System32\config",
    "C:\Windows\System32\spool",
    "C:\Windows\System32\winevt\Logs",
    "C:\Windows\System32\Tasks",
    "C:\Windows\SysWOW64",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Windows\System32\GroupPolicy",
    "C:\Windows\System32\inetsrv",
    "C:\Windows\System32\wbem",
    "C:\Windows\System32\WindowsPowerShell"
```

### Linux ###Change this, if needed.
```
/etc/passwd
/etc/shadow
/etc/group
/etc/ssh/sshd_config
/etc/sudoers
/etc/hosts
/etc/services
/etc/resolv.conf
/etc/apt/sources.list
/etc/apt/sources.list.d
/etc/apt/trusted.gpg.d
/etc/systemd
/etc/network
/var/lib/systemd
/boot
/etc/crontab
/etc/cron.d
/etc/cron.daily
/etc/cron.hourly
/etc/cron.weekly
/etc/audit/audit.rules
/etc/selinux/config
/etc/profile
/root/.bash_history
/etc/nginx
```

---
### Splunk query for monitoring
```
index=windows sourcetype=fim_report
| rex "Change Type:\s+(?<change_type>[^\r\n]+)"
| rex "File Path:\s+(?<file_path>[^\r\n]+)"
| rex "User:\s+(?<user>[^\r\n]+)"
| rex "Last Write Time:\s+(?<last_write_time>[^\r\n]+)"
| rex "Last Known Owner:\s+(?<owner>[^\r\n]+)"
| table _time, host, change_type, file_path, user, owner, last_write_time

```
##  License

This project is licensed under the MIT License.
