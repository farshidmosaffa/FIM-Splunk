@echo off
REM --------------------------------------------------------
REM Script: File Integrity Monitor (FIM)
REM Author: Farshid Mosaffa
REM Date: 2025-05-14
REM Description: Monitors changes to files and directories, integrated to splunk.
REM --------------------------------------------------------
setlocal enabledelayedexpansion
cls

REM Setting the first parameter for the first-run modest-run
if "%~1"=="--first-run" (
    set "firstRun=1"
) else (
    set "firstRun=0"
)

REM Path to save FIM files
set "basePath=C:\Program Files\SplunkUniversalForwarder\etc\apps\FIM"
if not exist "!basePath!" mkdir "!basePath!" >nul 2>&1

set "hashFile=!basePath!\hash_store.txt"
set "deletedFileLog=!basePath!\deleted_files.txt"
set "restoredFileLog=!basePath!\restored_files.txt"
set "tempHashFile=!basePath!\temp_hashes.txt"
set "logFile=!basePath!\fim_output.log"

REM Create empty files if they do not already exist
if not exist "!hashFile!" type nul > "!hashFile!"
if not exist "!deletedFileLog!" type nul > "!deletedFileLog!"
if not exist "!restoredFileLog!" type nul > "!restoredFileLog!"

REM Paths to be monitored
set "filePaths=C:\Windows\System32\services.exe C:\Temp C:\Windows\debug C:\Windows\System32\svchost.exe C:\Windows\System32\lsass.exe C:\Windows\System32\winlogon.exe C:\Windows\System32\explorer.exe C:\Windows\System32\smss.exe C:\Windows\System32\wininit.exe C:\Windows\System32\config\SAM C:\Windows\System32\config\SYSTEM C:\Windows\System32\config\SECURITY C:\Windows\System32\GroupPolicy C:\Windows\System32\GroupPolicyUsers C:\Windows\System32\SecEdit.sdb C:\Windows\System32\drivers\etc\hosts C:\Windows\System32\drivers\etc\services"

for %%F in (!filePaths!) do (
    call :CheckFileOrFolder "%%F"
)

exit /b

:CheckFileOrFolder
set "filePath=%~1"
for /f "tokens=1-3 delims= " %%i in ("%date% %time%") do set "datetime=%%i %%j %%k"

if not exist "!filePath!" (
    findstr /c:"!filePath!," "!hashFile!" >nul
    if !errorlevel! == 0 (
        findstr /x /c:"!filePath!" "!deletedFileLog!" >nul
        if errorlevel 1 (
            if "!firstRun!"=="0" (
                >>"!logFile!" echo ===================================
                >>"!logFile!" echo 🗓️ Date: !datetime!
                >>"!logFile!" echo 📂 Path: "!filePath!"
                >>"!logFile!" echo ❌ File or folder deleted!
                >>"!logFile!" echo ===================================
                echo !filePath!>>"!deletedFileLog!"
            )
        )
    )
    exit /b
) else (
    findstr /x /c:"!filePath!" "!deletedFileLog!" >nul
    if !errorlevel! == 0 (
        >>"!logFile!" echo ===================================
        >>"!logFile!" echo 🗓️ Date: !datetime!
        >>"!logFile!" echo 📂 Path: "!filePath!"
        >>"!logFile!" echo ✅ File restored!
        >>"!logFile!" echo ===================================
        findstr /v /x /c:"!filePath!" "!deletedFileLog!" > "!tempHashFile!"
        move /y "!tempHashFile!" "!deletedFileLog!" >nul
    )
)

if exist "!filePath!\*" (
    call :CheckFolderHash "!filePath!"
) else (
    call :CheckFileHash "!filePath!"
)

exit /b

:CheckFileHash
set "filePath=%~1"
for /f "tokens=*" %%a in ('certutil -hashfile "!filePath!" SHA256 ^| findstr /v "SHA256" ^| findstr /v "CertUtil"') do (
    set "hash=%%a"
    goto :hashDone
)
:hashDone
set "hash=!hash: =!"

set "lastHash="
for /f "tokens=1,2 delims=," %%a in ('type "!hashFile!" ^| findstr /b /c:"!filePath!,"') do (
    set "lastHash=%%b"
)

if "!lastHash!"=="!hash!" exit /b

if "!firstRun!"=="0" (
    >>"!logFile!" echo ===================================
    >>"!logFile!" echo 🗓️ Date: !datetime!
    >>"!logFile!" echo 📂 File: "!filePath!"
    >>"!logFile!" echo 🔄 Change detected!
    >>"!logFile!" echo 🔑 New Hash: !hash!
    >>"!logFile!" echo ===================================
)

findstr /v /b /c:"!filePath!," "!hashFile!" > "!tempHashFile!"
echo !filePath!,!hash!>>"!tempHashFile!"
move /y "!tempHashFile!" "!hashFile!" >nul
exit /b

:CheckFolderHash
set "folderPath=%~1"
set "folderHash="

REM 1. Compute hash of files directly located in the folder
for /f "tokens=*" %%F in ('dir /b /a:-d "!folderPath!\*" 2^>nul') do (
    for /f "tokens=*" %%a in ('certutil -hashfile "!folderPath!\%%F" SHA256 ^| findstr /v "SHA256" ^| findstr /v "CertUtil"') do (
        set "fileHash=%%a"
        set "fileHash=!fileHash: =!"
        set "folderHash=!folderHash!!fileHash!"
    )
)

REM 2. Compute hash of the name of subdirectories
for /f "tokens=*" %%D in ('dir /b /ad "!folderPath!\*" 2^>nul') do (
    set "subfolderName=%%D"
    set "folderHash=!folderHash!!subfolderName!"
)

set "lastFolderHash="
for /f "tokens=1,2 delims=," %%a in ('type "!hashFile!" ^| findstr /b /c:"!folderPath!,"') do (
    set "lastFolderHash=%%b"
)

if "!lastFolderHash!"=="!folderHash!" exit /b

if "!firstRun!"=="0" (
    >>"!logFile!" echo ===================================
    >>"!logFile!" echo 🗓️ Date: !datetime!
    >>"!logFile!" echo 📂 Folder: "!folderPath!"
    >>"!logFile!" echo 🔄 Change detected!
    >>"!logFile!" echo 🔑 New Hash: !folderHash!
    >>"!logFile!" echo ===================================
)

findstr /v /b /c:"!folderPath!," "!hashFile!" > "!tempHashFile!"
echo !folderPath!,!folderHash!>>"!tempHashFile!"
move /y "!tempHashFile!" "!hashFile!" >nul
exit /b
