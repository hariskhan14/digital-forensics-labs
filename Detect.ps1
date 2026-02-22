$system32Path = "C:\Windows\System32"

# Time threshold (last 1 hour)
$oneHourAgo = (Get-Date).AddHours(-1)

Write-Host "Scanning System32 for suspicious .txt files created in last 1 hour..."
Write-Host "--------------------------------------------------------------"

Get-ChildItem $system32Path -File -Recurse -ErrorAction SilentlyContinue |
Where-Object {
    $_.Extension -eq ".txt" -and $_.CreationTime -ge $oneHourAgo
} |
ForEach-Object {
    Write-Host "🚩 RED FLAG: Suspicious TXT File Detected!" -ForegroundColor Red
    Write-Host "File Name: $($_.Name)"
    Write-Host "Full Path: $($_.FullName)"
    Write-Host "Created: $($_.CreationTime)"
    Write-Host "--------------------------------------------------"
}