# Script 2: Monitor if CreateSysFile.bat is running

$batchName = "CreateSysFile.bat"

# Get all cmd.exe processes and their command lines
$cmdProcesses = Get-CimInstance Win32_Process | Where-Object { $_.Name -eq "cmd.exe" }

$suspiciousProcess = $cmdProcesses | Where-Object { $_.CommandLine -like "*$batchName*" }

if ($suspiciousProcess) {
    Write-Host "Suspicious process detected!"
    foreach ($proc in $suspiciousProcess) {
        Write-Host "Process ID: $($proc.ProcessId)"
        Write-Host "Command Line: $($proc.CommandLine)"
    }
} else {
    Write-Host "No suspicious batch process running."
}