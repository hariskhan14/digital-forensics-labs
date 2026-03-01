# ============================================================
# Investigate-CS2.ps1  |  Digital Forensics  |  Case CS2
# Evidence: CrimeScene-2.evtx  +  CS2_NTUSER.DAT
# Answers all 10 assignment questions with timeline correlation
# and forensic conclusion.
# ============================================================

param(
    [string]$EvtxPath   = ".\CrimeScene-2.evtx",
    [string]$NtUserPath = ".\CS2_NTUSER.DAT"
)

function Write-Header($text) {
    Write-Host "`n$('=' * 65)" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "$('=' * 65)" -ForegroundColor Cyan
}

function Write-Q($n, $text) {
    Write-Host ("`n  [Q{0}] {1}" -f $n, $text) -ForegroundColor Yellow
    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray
}

# ----------------------------------------------------------------
# Load & parse events
# ----------------------------------------------------------------
Write-Host "[*] Loading: $EvtxPath" -ForegroundColor Green
try {
    $rawEvents = Get-WinEvent -Path $EvtxPath -ErrorAction Stop
} catch {
    Write-Host "[!] Failed to load evtx: $_" -ForegroundColor Red; exit 1
}
Write-Host "[+] $($rawEvents.Count) events loaded." -ForegroundColor Green

# Parse into structured objects (provider not installed so Message=null; use raw XML)
$events = $rawEvents | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = [string]$xml.Event.EventData.Data
    [PSCustomObject]@{
        Seq     = if ($data -match '\[Seq=(\d+)\]')         { [int]$Matches[1] }    else { 9999 }
        EventID = $_.Id
        Time    = $_.TimeCreated
        SID     = if ($data -match '\[SID:(S-1-5-21-\d+)\]') { $Matches[1] }        else { 'N/A' }
        Data    = $data
    }
} | Sort-Object Seq

# Convenience subsets
$usbEvents      = $events | Where-Object { $_.Data -like 'USBInsert*' }
$archiveEvents  = $events | Where-Object { $_.Data -like 'ArchiveToolExec*' }
$copyEvents     = $events | Where-Object { $_.Data -like 'LargeCopyFlag*' }
$tamperEvents   = $events | Where-Object { $_.Data -like 'EvidenceTamperHint*' }
$handleEvents   = $events | Where-Object { $_.Data -like 'HandleOpenFlag*' }
$flushEvents    = $events | Where-Object { $_.Data -like 'SystemFlushOperation*' }

# ================================================================
# Q1  -- USB Insertion Event ID
# ================================================================
Write-Header "QUESTION 1: Event ID for USB Insertion"
Write-Q 1 "Identify the Event ID that indicates USB insertion."

$usbEventIDs = $usbEvents | Select-Object -ExpandProperty EventID -Unique
Write-Host ("  Answer : EventID  {0}" -f ($usbEventIDs -join ', ')) -ForegroundColor White
Write-Host "  Reason : All USBInsert keyword events share this ID." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Event ID breakdown (all types):" -ForegroundColor Yellow
$events | Group-Object EventID | Sort-Object Name | ForEach-Object {
    $sample = ($_.Group | Select-Object -First 1).Data -replace '\[.*','(truncated)'
    Write-Host ("    EID {0,3}  x{1,-4}  {2}" -f $_.Name, $_.Count, $sample.Substring(0,[Math]::Min(60,$sample.Length)))
}

# ================================================================
# Q2  -- Suspicious USB Serial Number
# ================================================================
Write-Header "QUESTION 2: Suspicious USB Serial Number"
Write-Q 2 "What was the serial number of the suspicious USB device?"

Write-Host "  All USB insertions in the log:" -ForegroundColor Yellow
$usbEvents | ForEach-Object {
    $serial = if ($_.Data -match 'Serial=(\S+)')  { $Matches[1] } else { '?' }
    $drive  = if ($_.Data -match 'Drive=(\S+)')   { $Matches[1] } else { '?' }
    $flag   = if ($serial -eq 'SN8403') { '  <-- SUSPICIOUS' } else { '' }
    Write-Host ("    Seq={0,3}  Serial={1,-12}  Drive={2}  SID={3}{4}" -f
        $_.Seq, $serial, $drive, $_.SID, $flag) -ForegroundColor $(if ($flag) {'Red'} else {'White'})
}

Write-Host ""
Write-Host "  Answer : Serial = SN8403  (inserted at Seq=162 by SID S-1-5-21-8403)" -ForegroundColor White
Write-Host "  Reason : Serial 'SN8403' numerically mirrors the actor's SID suffix (8403)."  -ForegroundColor DarkGray
Write-Host "           No other USB serial correlates with its inserting user's SID." -ForegroundColor DarkGray
Write-Host "           SN8403 is IMMEDIATELY followed by targeted archive + log clear." -ForegroundColor DarkGray

# ================================================================
# Q3  -- SID that inserted the suspicious USB
# ================================================================
Write-Header "QUESTION 3: SID that Inserted the Suspicious USB"
Write-Q 3 "Which SID inserted the suspicious USB?"

$suspInsert = $usbEvents | Where-Object { $_.Data -match 'Serial=SN8403' }
Write-Host ("  Answer : {0}" -f $suspInsert.SID) -ForegroundColor White
Write-Host ("  Event  : Seq={0}  EventID={1}  Time={2}" -f $suspInsert.Seq, $suspInsert.EventID, $suspInsert.Time) -ForegroundColor DarkGray
Write-Host ("  Data   : {0}" -f $suspInsert.Data) -ForegroundColor DarkGray

# ================================================================
# Q4  -- Archive Tool
# ================================================================
Write-Header "QUESTION 4: Archive Tool & Command Pattern"
Write-Q 4 "Was an archive tool used? Identify the tool and command pattern."

Write-Host "  Answer : YES  -  7z.exe  (7-Zip command-line)" -ForegroundColor White
Write-Host ""
Write-Host "  Unique command patterns observed:" -ForegroundColor Yellow
$archiveEvents | Select-Object -ExpandProperty Data -Unique | ForEach-Object {
    $cmd = ($_ -replace '\[.*','').Trim()
    Write-Host "    $cmd" -ForegroundColor White
}
Write-Host ""
Write-Host "  Flag meanings:" -ForegroundColor Yellow
Write-Host "    a            = add / create archive"
Write-Host "    E:\loot.7z   = generic output path on USB (E:)"
Write-Host "    E:\case_loot.7z = TARGETED output - exclusive to SID-8403 (Seq=163)"
Write-Host "    C:\Users\Public\*           = broad staging grab (all SIDs)"
Write-Host "    C:\Users\*\Documents\*      = targeted documents grab (SID-8403 only)"
Write-Host "    -mx=9        = maximum compression (minimise transfer size)"

# ================================================================
# Q5  -- Amount of data copied
# ================================================================
Write-Header "QUESTION 5: Amount of Data Copied to Removable Media"
Write-Q 5 "Estimate the amount of data copied to removable media."

Write-Host "  LargeCopyFlag totals per SID:" -ForegroundColor Yellow
$copyEvents | Group-Object SID | Sort-Object Name | ForEach-Object {
    $total  = ($_.Group | ForEach-Object {
        if ($_.Data -match 'Bytes=(\d+)') { [long]$Matches[1] } else { 0 }
    } | Measure-Object -Sum).Sum
    $flag = if ($_.Name -like '*8403*') { '  <-- SUSPECT' } else { '' }
    Write-Host ("    SID={0,-18} Events={1,-4} Total={2,15} bytes  ({3:N2} GB){4}" -f
        $_.Name, $_.Count, $total, ($total/1GB), $flag) `
        -ForegroundColor $(if ($flag) {'Red'} else {'White'})
}

$suspBytes = ($copyEvents | Where-Object { $_.SID -like '*8403*' } | ForEach-Object {
    if ($_.Data -match 'Bytes=(\d+)') { [long]$Matches[1] } else { 0 }
} | Measure-Object -Sum).Sum

$targetedBytes = ($copyEvents | Where-Object { $_.Data -match 'case_loot\.7z' } | ForEach-Object {
    if ($_.Data -match 'Bytes=(\d+)') { [long]$Matches[1] } else { 0 }
} | Measure-Object -Sum).Sum

Write-Host ""
Write-Host ("  Answer (SID-8403 total) : {0:N0} bytes  =  {1:N2} GB" -f $suspBytes, ($suspBytes/1GB)) -ForegroundColor White
Write-Host ("  Answer (targeted E:\case_loot.7z only) : {0:N0} bytes  =  {1:N2} GB" -f $targetedBytes, ($targetedBytes/1GB)) -ForegroundColor White
Write-Host "  Note   : The targeted archive (case_loot.7z) represents the actual exfil payload." -ForegroundColor DarkGray

# ================================================================
# Q6  -- Evidence Tampering
# ================================================================
Write-Header "QUESTION 6: Event Suggesting Evidence Tampering"
Write-Q 6 "Identify any event suggesting evidence tampering."

Write-Host "  Answer : EventID 204  --  EvidenceTamperHint RecentItemsClearFlag 0xE2" -ForegroundColor White
Write-Host ""
Write-Host "  Meaning: Windows Recent Items / MRU lists were cleared (flag 0xE2)," -ForegroundColor DarkGray
Write-Host "           removing traces of which files the actor accessed or opened." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  All tampering events by SID:" -ForegroundColor Yellow
$tamperEvents | Group-Object SID | Sort-Object Name | ForEach-Object {
    $flag = if ($_.Name -like '*8403*') { '  <-- SUSPECT' } else { '' }
    Write-Host ("    SID={0,-18}  Count={1}{2}" -f $_.Name, $_.Count, $flag) `
        -ForegroundColor $(if ($flag) {'Red'} else {'White'})
}
Write-Host ""
Write-Host "  SID-8403 tampering events (Seq):" -ForegroundColor Yellow
$tamperEvents | Where-Object { $_.SID -like '*8403*' } | ForEach-Object {
    Write-Host ("    Seq={0,3}  {1}" -f $_.Seq, $_.Data) -ForegroundColor Red
}

# ================================================================
# Q7  -- Log Clearing Attempt
# ================================================================
Write-Header "QUESTION 7: Log Clearing Attempt"
Write-Q 7 "Did the attacker attempt log clearing?"

Write-Host "  Answer : YES  --  EventID 206  --  SystemFlushOperation 0xC1" -ForegroundColor White
Write-Host ""
$flushEvents | ForEach-Object {
    Write-Host ("  Seq={0}  Time={1}" -f $_.Seq, $_.Time) -ForegroundColor Red
    Write-Host ("  {0}" -f $_.Data) -ForegroundColor Red
}
Write-Host ""
Write-Host "  Meaning: SystemFlushOperation code 0xC1 is flagged in this log as a" -ForegroundColor DarkGray
Write-Host "           'log clear indicator' -- the actor triggered a system-level" -ForegroundColor DarkGray
Write-Host "           flush to wipe or rotate event log buffers before closing." -ForegroundColor DarkGray

# ================================================================
# Q8  -- Sensitive Object
# ================================================================
Write-Header "QUESTION 8: Sensitive Object"
Write-Q 8 "Which object was marked as sensitive?"

Write-Host "  Answer : OBJ-1C4B  (tagged 'Sensitive' in the event log)" -ForegroundColor White
Write-Host ""
$handleEvents | ForEach-Object {
    Write-Host ("  Seq={0}  EventID={1}  Time={2}" -f $_.Seq, $_.EventID, $_.Time) -ForegroundColor Red
    Write-Host ("  {0}" -f $_.Data) -ForegroundColor Red
}
Write-Host ""
Write-Host "  Handle flags 0x9E include: read, write, delete access." -ForegroundColor DarkGray
Write-Host "  This occurred AFTER the targeted archive, just before log clearing." -ForegroundColor DarkGray

# ================================================================
# Q9  -- USB Insertion correlated with Archive Activity
# ================================================================
Write-Header "QUESTION 9: USB Insertion vs Archive Activity Correlation"
Write-Q 9 "Correlate the USB insertion with file archive activity."

Write-Host "  The 6-event terminal sequence for SID-8403 (all within 0.5 seconds):" -ForegroundColor Yellow
Write-Host ""
$events | Where-Object { $_.Seq -ge 162 -and $_.Seq -le 167 } | ForEach-Object {
    $type = switch ($_.EventID) {
        201 { "USB INSERTION   " }
        202 { "ARCHIVE EXEC    " }
        203 { "LARGE COPY      " }
        205 { "SENSITIVE HANDLE" }
        206 { "LOG CLEAR       " }
        207 { "SESSION CLOSE   " }
        default { "EVENT           " }
    }
    Write-Host ("  Seq={0}  EID={1}  [{2}]  {3}" -f $_.Seq, $_.EventID, $type, $_.Data.Substring(0,[Math]::Min(70,$_.Data.Length))) `
        -ForegroundColor $(if ($_.Seq -in 162,163,164) {'Red'} else {'DarkYellow'})
}
Write-Host ""
Write-Host "  Correlation: USB inserted at Seq=162; archive executed at Seq=163 (< 0.1s later);" -ForegroundColor White
Write-Host "               1.84 GB written to USB at Seq=164. Direct cause-effect chain." -ForegroundColor White

# ================================================================
# Q10 -- Insider Data Theft Assessment
# ================================================================
Write-Header "QUESTION 10: Insider Data Theft Validation"
Write-Q 10 "Validate whether this scene indicates insider data theft."

Write-Host "  Answer : YES -- strong indicators of DELIBERATE INSIDER DATA THEFT." -ForegroundColor Red
Write-Host ""
Write-Host "  TIMELINE CORRELATION:" -ForegroundColor Yellow
Write-Host "  ---------------------------------------------------------------"
Write-Host "  09:03:30 - 09:03:36  SID-8403 active alongside other users"
Write-Host "                        (blends in with general USB/copy/archive activity)"
Write-Host "  09:03:37.532  [Seq=162] USB INSERTED  -- Serial SN8403 (own device)"
Write-Host "  09:03:37.625  [Seq=163] ARCHIVE EXEC  -- 7z.exe E:\case_loot.7z C:\Users\*\Documents\* -mx=9"
Write-Host "  09:03:37.700  [Seq=164] LARGE COPY    -- 1,842,209,920 bytes -> E:\case_loot.7z"
Write-Host "  09:03:37.783  [Seq=165] SENSITIVE OBJ -- HandleOpenFlag OBJ-1C4B (0x9E)"
Write-Host "  09:03:37.859  [Seq=166] LOG CLEAR     -- SystemFlushOperation 0xC1"
Write-Host "  09:03:37.936  [Seq=167] SESSION CLOSE -- Code 0x01B"
Write-Host "  ---------------------------------------------------------------"
Write-Host ""
Write-Host "  FORENSIC INDICATORS:" -ForegroundColor Yellow
Write-Host "  [1] Personal USB: Serial SN8403 matches SID suffix 8403 -- user brought own device."
Write-Host "  [2] Targeted scope: Only SID-8403 used 'case_loot.7z' + 'C:\Users\*\Documents\*'."
Write-Host "      All other SIDs used generic 'loot.7z' + 'C:\Users\Public\*'."
Write-Host "  [3] Data volume: 1.84 GB of case documents exfiltrated in a single operation."
Write-Host "  [4] Anti-forensics: RecentItemsClearFlag (0xE2) triggered 4x during session"
Write-Host "      to erase file-access traces from Windows MRU lists."
Write-Host "  [5] Sensitive access: OBJ-1C4B accessed with read/write/delete handle (0x9E)"
Write-Host "      immediately after exfiltration."
Write-Host "  [6] Log suppression: SystemFlushOperation 0xC1 fired before session close."
Write-Host "  [7] Rapid exit: Entire exfil + cover-up sequence completed in under 0.5 seconds"
Write-Host "      (typical of scripted/automated insider tool)."
Write-Host ""
Write-Host "  FORENSIC CONCLUSION:" -ForegroundColor Cyan
Write-Host "  ---------------------------------------------------------------"
Write-Host "  SID S-1-5-21-8403 is the insider threat actor. On 2026-02-26 at"
Write-Host "  approximately 09:03:37 UTC, the actor inserted a pre-labelled USB"
Write-Host "  device (SN8403), executed a targeted 7-Zip archive of all case"
Write-Host "  documents (C:\Users\*\Documents\*) with maximum compression, and"
Write-Host "  transferred 1.84 GB to the USB drive as 'case_loot.7z'. The actor"
Write-Host "  then accessed the sensitive object OBJ-1C4B, cleared Windows Recent"
Write-Host "  Items four times to erase file-access history, triggered a log"
Write-Host "  flush to suppress event evidence, and terminated the session."
Write-Host "  The matching SID-to-serial pattern (SN8403 / S-1-5-21-8403) and"
Write-Host "  the exclusive use of targeted paths confirm intentional, premeditated"
Write-Host "  insider data exfiltration against Case CS2."
Write-Host "  ---------------------------------------------------------------"

# ================================================================
# NTUSER.DAT  -- MountPoints2 / USB registry artifacts
# ================================================================
Write-Header "BONUS: NTUSER.DAT Registry (MountPoints2 / USB History)"

$hiveName = "CS2_Investigation"
$hiveKey  = "HKLM\$hiveName"
Write-Host "[*] Loading hive: $NtUserPath" -ForegroundColor Yellow
$regLoad = reg load $hiveKey $NtUserPath 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Hive load requires admin rights. Skipping registry section." -ForegroundColor DarkYellow
    Write-Host "    Run as Administrator to inspect MountPoints2." -ForegroundColor DarkGray
} else {
    Write-Host "[+] Hive loaded." -ForegroundColor Green
    $mp2 = "Registry::HKEY_LOCAL_MACHINE\$hiveName\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    Write-Host "`n[*] MountPoints2 USB entries:" -ForegroundColor Yellow
    try {
        Get-ChildItem -Path $mp2 -ErrorAction Stop |
            Select-Object -ExpandProperty PSChildName |
            ForEach-Object { Write-Host "    $_" }
    } catch {
        Write-Host "    (Key absent -- may have been wiped)" -ForegroundColor DarkYellow
    }
    [gc]::Collect()
    $null = reg unload $hiveKey 2>&1
    Write-Host "[+] Hive unloaded." -ForegroundColor Green
}

Write-Host "`n[DONE]" -ForegroundColor Green
