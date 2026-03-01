# Get Desktop path
$desktopPath = [Environment]::GetFolderPath("Desktop")

# Batch file path
$batchFilePath = Join-Path $desktopPath "CreateSysFile.bat"

# Content of the batch file
$batchContent = @"
@echo off
set filename=system_report_%RANDOM%.txt
echo System Name: %COMPUTERNAME% > C:\Windows\System32\%filename%
echo Timestamp: %DATE% %TIME% >> C:\Windows\System32\%filename%
echo File created in System32.
pause
"@

# Create the batch file
Set-Content -Path $batchFilePath -Value $batchContent

Write-Host "Batch file created at: $batchFilePath"