# Enhanced File Integrity Monitoring Script for Windows Servers
# Version 3 - With improved Splunk logging for fim_report.txt

# Configuration
$baselinePath = "C:\FIM\baseline.json"
$logPath = "C:\FIM\fim_log.json"
$reportPath = "C:\FIM\fim_report.txt"
$scanInterval = 60  # in seconds (for testing)

# Create directory if it doesn't exist
if (-not (Test-Path "C:\FIM")) {
    try {
        New-Item -Path "C:\FIM" -ItemType Directory -Force | Out-Null
        Write-Output "Created C:\FIM directory"
    } catch {
        Write-Output "Error creating C:\FIM directory: $_"
        exit 1
    }
}

# Critical paths to monitor
$criticalPaths = @(
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
)

# Function to try to get the last user who modified a file from Event Logs
function Get-LastModifiedUser {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        # This is a best-effort approach - it won't work for all files
        $fileName = Split-Path -Path $FilePath -Leaf
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4663  # File access event
        } -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -like "*$fileName*" -and $_.Message -like "*WriteData*"
        }
        
        if ($events -and $events.Count -gt 0) {
            $event = $events[0]
            # Extract username from event message
            if ($event.Message -match "Account Name:\s+(.+?)[\r\n]") {
                return $matches[1].Trim()
            }
        }
    }
    catch {
        # Silently fail - this is just a best-effort approach
    }
    
    return "Unknown"
}

# Function to calculate file hash and metadata
function Get-FileMetadata {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        $file = Get-Item -Path $FilePath -ErrorAction Stop
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        $acl = Get-Acl -Path $FilePath -ErrorAction SilentlyContinue
        
        return @{
            Path = $FilePath
            Hash = $hash.Hash
            LastWriteTime = $file.LastWriteTime
            CreationTime = $file.CreationTime
            Size = $file.Length
            Owner = if ($acl) { $acl.Owner } else { "Unknown" }
            LastAccessTime = $file.LastAccessTime
        }
    }
    catch {
        return $null
    }
}

# Function to create baseline
function Create-Baseline {
    $baseline = @{}
    $totalFiles = 0
    $processedFiles = 0
    
    # Count total files for progress reporting
    foreach ($path in $criticalPaths) {
        if (Test-Path $path) {
            $totalFiles += (Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue).Count
        }
    }
    
    Write-Output "Starting baseline creation for $totalFiles files..."
    
    foreach ($path in $criticalPaths) {
        if (-not (Test-Path $path)) {
            Write-Output "Warning: Path $path does not exist, skipping."
            continue
        }
        
        Write-Output "Processing $path..."
        
        Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $processedFiles++
            if ($processedFiles % 1000 -eq 0) {
                Write-Output "Processed $processedFiles of $totalFiles files..."
            }
            
            $metadata = Get-FileMetadata -FilePath $_.FullName
            if ($metadata) {
                $baseline[$_.FullName] = $metadata
            }
        }
    }
    
    # Save baseline to file
    try {
        $baseline | ConvertTo-Json -Depth 10 | Set-Content -Path $baselinePath -Force
        Write-Output "Baseline created successfully with $($baseline.Count) files at $baselinePath"
        
        # Log baseline creation
        $baselineLog = @{
            Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Event = "Baseline_Created"
            FileCount = $baseline.Count
        }
        
        $baselineLog | ConvertTo-Json | Add-Content -Path $logPath -Force
    }
    catch {
        Write-Output "Error saving baseline: $_"
    }
    
    return $baseline
}

# Function to compare with baseline
function Compare-WithBaseline {
    if (-not (Test-Path $baselinePath)) {
        Write-Output "Baseline not found. Creating new baseline..."
        $baseline = Create-Baseline
        return
    }
    
    try {
        # Load baseline as PSObject instead of HashTable for PowerShell 5.1 compatibility
        $baselineJson = Get-Content -Path $baselinePath -Raw
        $baselinePSObject = ConvertFrom-Json -InputObject $baselineJson
        
        # Convert PSObject to hashtable for easier comparison
        $baseline = @{}
        $baselinePSObject.PSObject.Properties | ForEach-Object {
            $baseline[$_.Name] = $_.Value
        }
    }
    catch {
        Write-Output "Error reading baseline: $_. Creating new baseline..."
        $baseline = Create-Baseline
        return
    }
    
    $changes = @()
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $processedFiles = 0
    
    Write-Output "Starting file integrity check at $timestamp..."
    
    foreach ($path in $criticalPaths) {
        if (-not (Test-Path $path)) {
            Write-Output "Warning: Path $path does not exist, skipping."
            continue
        }
        
        Write-Output "Scanning $path for changes..."
        
        Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $processedFiles++
            if ($processedFiles % 1000 -eq 0) {
                Write-Output "Processed $processedFiles files..."
            }
            
            $filePath = $_.FullName
            $currentMetadata = Get-FileMetadata -FilePath $filePath
            
            if ($currentMetadata) {
                # Check if file is new
                if (-not $baseline.ContainsKey($filePath)) {
                    # Try to get the user who created the file
                    $lastUser = Get-LastModifiedUser -FilePath $filePath
                    
                    $change = @{
                        Path = $filePath
                        Type = "Created"
                        Timestamp = $timestamp
                        User = if ($lastUser -ne "Unknown") { $lastUser } else { $currentMetadata.Owner }
                        Details = "New file detected"
                        Size = $currentMetadata.Size
                        Hash = $currentMetadata.Hash
                    }
                    
                    $changes += $change
                }
                # Check if file was modified
                elseif ($baseline[$filePath].Hash -ne $currentMetadata.Hash) {
                    # Try to get the user who modified the file
                    $lastUser = Get-LastModifiedUser -FilePath $filePath
                    
                    $change = @{
                        Path = $filePath
                        Type = "Modified"
                        Timestamp = $timestamp
                        User = if ($lastUser -ne "Unknown") { $lastUser } else { $currentMetadata.Owner }
                        PreviousHash = $baseline[$filePath].Hash
                        CurrentHash = $currentMetadata.Hash
                        LastWriteTime = $currentMetadata.LastWriteTime
                        PreviousSize = $baseline[$filePath].Size
                        CurrentSize = $currentMetadata.Size
                        SizeChange = $currentMetadata.Size - $baseline[$filePath].Size
                    }
                    
                    $changes += $change
                }
            }
        }
    }
    
    # Check for deleted files
    foreach ($filePath in $baseline.Keys) {
        if (-not (Test-Path $filePath)) {
            $deletion = @{
                Path = $filePath
                Type = "Deleted"
                Timestamp = $timestamp
                PreviousHash = $baseline[$filePath].Hash
                PreviousSize = $baseline[$filePath].Size
                LastKnownOwner = $baseline[$filePath].Owner
                LastWriteTime = $baseline[$filePath].LastWriteTime
                CreationTime = $baseline[$filePath].CreationTime
            }
            
            $changes += $deletion
        }
    }
    
    # Log changes
    if ($changes.Count -gt 0) {
        $logEntry = @{
            Timestamp = $timestamp
            Changes = $changes
            ChangesCount = $changes.Count
        }
        
        try {
            $logEntry | ConvertTo-Json -Depth 10 | Add-Content -Path $logPath -Force
        }
        catch {
            Write-Output "Error writing to log: $_"
        }
        
        # Create human-readable report with event separators
        $report = ""
        foreach ($change in $changes) {
            $report += "===== FIM_CHANGE_START =====`r`n"
            $report += "Change Type: $($change.Type)`r`n"
            $report += "File Path: $($change.Path)`r`n"
            $report += "Timestamp: $($change.Timestamp)`r`n"
            
            if ($change.User) {
                $report += "User: $($change.User)`r`n"
            }
            
            if ($change.Type -eq "Modified") {
                $report += "Previous Hash: $($change.PreviousHash)`r`n"
                $report += "Current Hash: $($change.CurrentHash)`r`n"
                $report += "Last Write Time: $($change.LastWriteTime)`r`n"
                $report += "Previous Size: $($change.PreviousSize) bytes`r`n"
                $report += "Current Size: $($change.CurrentSize) bytes`r`n"
                $report += "Size Change: $($change.SizeChange) bytes`r`n"
            }
            elseif ($change.Type -eq "Deleted") {
                $report += "Previous Hash: $($change.PreviousHash)`r`n"
                $report += "Last Known Owner: $($change.LastKnownOwner)`r`n"
                $report += "Previous Size: $($change.PreviousSize) bytes`r`n"
            }
            elseif ($change.Type -eq "Created") {
                $report += "Hash: $($change.Hash)`r`n"
                $report += "Size: $($change.Size) bytes`r`n"
                if ($change.Details) {
                    $report += "Details: $($change.Details)`r`n"
                }
            }
            
            $report += "===== FIM_CHANGE_END =====`r`n`r`n"
        }
        
        try {
            Add-Content -Path $reportPath -Value $report -Force
            Write-Output "Changes detected and logged to $logPath and $reportPath"
        }
        catch {
            Write-Output "Error writing report: $_"
        }
        
        # Update baseline with new state
        Write-Output "Updating baseline with new state..."
        $baseline = Create-Baseline
    } else {
        Write-Output "No changes detected"
    }
}

# Main execution - single run for scheduled task
try {
    $startTime = Get-Date
    Write-Output "FIM scan started at $startTime"
    
    if (-not (Test-Path $baselinePath)) {
        Write-Output "Initial baseline not found. Creating baseline..."
        Create-Baseline
    } else {
        Compare-WithBaseline
    }
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    Write-Output "FIM scan completed in $duration seconds"
}
catch {
    Write-Output "Error in FIM execution: $_"
    exit 1
}