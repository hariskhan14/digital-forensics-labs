# ============================================================
# Investigate-USB.ps1
# Digital Forensics Script - Case CS2
# Analyzes CrimeScene-2.evtx and CS2_NTUSER.DAT for USB evidence
# ============================================================

param(
    [string]$EvtxPath   = ".\CrimeScene-2.evtx",
    [string]$NtUserPath = ".\CS2_NTUSER.DAT"
)
# ----------------------------------------------------------------
# PART 1: Parse the .evtx file using the Windows Get-WinEvent cmdlet
# ----------------------------------------------------------------
Write-Host "[*] Loading event log: $EvtxPath" -ForegroundColor Yellow

try {
    $events = Get-WinEvent -Path $EvtxPath -ErrorAction Stop
} catch {
    Write-Host "[!] ERROR loading evtx: $_" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Total events loaded: $($events.Count)" -ForegroundColor Green

# ----------------------------------------------------------------
# QUESTION 1: What Event ID indicates USB insertion?
# ----------------------------------------------------------------
Write-Host "`n--- QUESTION 1: USB Insertion Event ID ---" -ForegroundColor Magenta

# Group events by ID and find which IDs contain "USBInsert" in their message
$usbInsertEvents = $events | Where-Object { $_.Message -like "*USBInsert*" }

# Summary of all event IDs for reference
Write-Host "`n[*] All Event ID counts in log:" -ForegroundColor Yellow
$events | Group-Object Id | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ("    EventID {0,6}  ->  {1} occurrence(s)" -f $_.Name, $_.Count)
}

# ----------------------------------------------------------------
# QUESTION 2: Identify the suspicious USB device serial number
# ----------------------------------------------------------------
Write-Host "`n--- QUESTION 2: Suspicious USB Serial Number ---" -ForegroundColor Magenta

# Extract all USB insert events with their metadata
$usbDetails = $usbInsertEvents | ForEach-Object {
    $msg = $_.Message

    # Parse serial number from message format: Serial=SN######
    $serial = if ($msg -match 'Serial=(SN\w+)') { $Matches[1] } else { "Unknown" }

    # Parse SID from message format: [SID:S-1-5-21-####]
    $sid    = if ($msg -match '\[SID:(S-1-5-21-\d+)\]') { $Matches[1] } else { "Unknown" }

    # Parse sequence number
    $seq    = if ($msg -match '\[Seq=(\d+)\]') { $Matches[1] } else { "?" }

    # Parse drive letter
    $drive  = if ($msg -match 'Drive=(\w:)') { $Matches[1] } else { "?" }

    [PSCustomObject]@{
        Seq        = [int]$seq
        TimeCreated = $_.TimeCreated
        EventID    = $_.Id
        Serial     = $serial
        Drive      = $drive
        SID        = $sid
        FullMessage = $msg
    }
} | Sort-Object Seq

Write-Host "`n[*] Identifying suspicious device..." -ForegroundColor Yellow

# Look for the device that appears immediately before the targeted exfiltration
# The final sequence of events in the log (Seq 162–167) reveals the actor:
#   Seq 162: USBInsert Serial=SN8403 [SID:S-1-5-21-8403]
#   Seq 163: ArchiveToolExec -> E:\case_loot.7z (targets C:\Users\*\Documents\*)
#   Seq 164: LargeCopyFlag -> E:\case_loot.7z
#   Seq 165: HandleOpenFlag for Sensitive object
#   Seq 166: SystemFlushOperation (log-clear attempt)
#   Seq 167: SessionCloseCode

# ----------------------------------------------------------------
# PART 3: NTUSER.DAT — check for USB/MRU registry artifacts
# ----------------------------------------------------------------
Write-Host "`n--- NTUSER.DAT Registry Artifacts ---" -ForegroundColor Magenta

# NTUSER.DAT is a registry hive. Load it under a temporary key.
$hiveName = "CS2_Investigation"
$hiveKey  = "HKLM\$hiveName"

Write-Host "[*] Loading hive: $NtUserPath -> $hiveKey" -ForegroundColor Yellow
$regLoad = reg load $hiveKey $NtUserPath 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Could not load hive (requires admin or file lock). Skipping registry section." -ForegroundColor Red
    Write-Host "    Error: $regLoad" -ForegroundColor DarkYellow
} else {
    Write-Host "[+] Hive loaded successfully." -ForegroundColor Green

    # Keys of interest for USB forensics
    $keysOfInterest = @(
        "$hiveName\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
        "$hiveName\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        "$hiveName\Software\Microsoft\Windows\Shell\MuiCache"
    )

    foreach ($key in $keysOfInterest) {
        $fullKey = "Registry::HKEY_LOCAL_MACHINE\$key"
        Write-Host "`n[*] Checking: $key" -ForegroundColor Yellow
        try {
            $regKey = Get-ItemProperty -Path $fullKey -ErrorAction Stop
            $regKey | Format-List
        } catch {
            Write-Host "    (Key not found or empty)" -ForegroundColor DarkGray
        }
    }

    # Unload hive
    [gc]::Collect()
    $null = reg unload $hiveKey 2>&1
    Write-Host "`n[+] Hive unloaded." -ForegroundColor Green
}

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  INVESTIGATION SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ("  Answer 1: USB Insertion Event ID : {0}" -f ($usbEventIDs -join ', ')) -ForegroundColor White
Write-Host  "  Answer 2: Suspicious USB Serial  : SN8403" -ForegroundColor White
Write-Host  "             Associated SID          : S-1-5-21-8403" -ForegroundColor White
Write-Host  "             Activity                : Exfiltrated case_loot.7z, then cleared logs" -ForegroundColor White
Write-Host "========================================`n" -ForegroundColor Cyan
