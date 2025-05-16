#!/bin/bash

basePath="/opt/splunkforwarder/fim"
hashFile="$basePath/hash_store.txt"
deletedLog="$basePath/deleted_files.txt"
restoredLog="$basePath/restored_files.txt"
logFile="$basePath/fim_output.log"
tempFile="$basePath/temp_hashes.txt"

mkdir -p "$basePath"
touch "$hashFile" "$deletedLog" "$restoredLog" "$logFile"

firstRun=0
[[ ! -s "$hashFile" ]] && firstRun=1

paths=(
  # فایل‌های پایه سیستم
  "/etc/passwd"
#  "/bin/"
  "/etc/shadow"
  "/etc/group"
  "/etc/ssh/sshd_config"
  "/etc/sudoers"
  "/etc/hosts"
  "/etc/services"
  "/etc/resolv.conf"
  "/etc/apt/sources.list"
  "/etc/apt/sources.list.d"
  "/etc/apt/trusted.gpg.d"
  "/etc/systemd"
  "/etc/network"
  "/var/lib/systemd"
  # فولدرهای سیستمی مهم
#  "/var/log"
#  "/var/log/ntp.log"
  "/boot"

  # مسیرهای مربوط به امنیت و اجرای زمان‌بندی
  "/etc/crontab"
  "/etc/cron.d"
  "/etc/cron.daily"
  "/etc/cron.hourly"
  "/etc/cron.weekly"
  "/etc/audit/audit.rules"
  "/etc/selinux/config"
  "/etc/profile"
  "/root/.bash_history"
  "/etc/nginx"
)

get_hash() {
  sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

check_file() {
  local path="$1"
  local datetime
  datetime=$(date '+%F %T')

  if [[ ! -e "$path" ]]; then
    grep -q "^$path," "$hashFile" || return

    if ! grep -qx "$path" "$deletedLog"; then
      if [[ "$firstRun" -eq 0 ]]; then
        echo "===================================" >> "$logFile"
        echo "📅 Date: $datetime" >> "$logFile"
        echo "🗂️ Path: $path" >> "$logFile"
        echo "❌ File or folder deleted!" >> "$logFile"
        echo "===================================" >> "$logFile"
        echo "$path" >> "$deletedLog"
      fi
    fi
    return
  fi

  # Check for restoration
  if grep -qx "$path" "$deletedLog"; then
    if [[ "$firstRun" -eq 0 ]]; then
      echo "===================================" >> "$logFile"
      echo "📅 Date: $datetime" >> "$logFile"
      echo "🗂️ Path: $path" >> "$logFile"
      echo "✅ File restored!" >> "$logFile"
      echo "===================================" >> "$logFile"
    fi
    grep -vx "$path" "$deletedLog" > "$tempFile" && mv "$tempFile" "$deletedLog"
    echo "$path" >> "$restoredLog"
  fi

  if [[ -f "$path" ]]; then
    hash=$(get_hash "$path")
  elif [[ -d "$path" ]]; then
    hash=$(find "$path" -type f -exec sha256sum {} \; 2>/dev/null | sort | sha256sum | awk '{print $1}')
  else
    return
  fi

  lastHash=$(grep "^$path," "$hashFile" | cut -d',' -f2)

  [[ "$hash" == "$lastHash" ]] && return

  if [[ "$firstRun" -eq 0 ]]; then
    echo "===================================" >> "$logFile"
    echo "📅 Date: $datetime" >> "$logFile"
    echo "🗂️ Path: $path" >> "$logFile"
    echo "🔄 Change detected!" >> "$logFile"
    echo "🔑 New Hash: $hash" >> "$logFile"
    echo "===================================" >> "$logFile"
  fi

  grep -v "^$path," "$hashFile" > "$tempFile"
  echo "$path,$hash" >> "$tempFile"
  mv "$tempFile" "$hashFile"
}

for path in "${paths[@]}"; do
  check_file "$path"
done

