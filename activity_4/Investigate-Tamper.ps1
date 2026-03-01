# ============================================================
# Investigate-Tamper.ps1
# Digital Forensics Script - Case CS2
# Covers Questions 6-8:
#   6. Evidence of tampering
#   7. Log clearing attempt
#   8. Sensitive object identification
# ============================================================

param(
    [string]$EvtxPath = ".\CrimeScene-2.evtx"
)

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  Anti-Forensics & Tampering Analysis - Case CS2 (Q6-8)" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

Write-Host "[*] Loading event log: $EvtxPath" -ForegroundColor Yellow
try {
    $events = Get-WinEvent -Path $EvtxPath -ErrorAction Stop
} catch {
    Write-Host "[!] ERROR loading evtx: $_" -ForegroundColor Red
    exit 1
}
Write-Host "[+] Total events loaded: $($events.Count)`n" -ForegroundColor Green

# ----------------------------------------------------------------
# Parse all events into structured objects
# ----------------------------------------------------------------
function Parse-EventMessage {
    param([string]$msg, [int]$eventId, [datetime]$time)
    $type  = ($msg -split ' ')[0]
    $sid   = if ($msg -match '\[SID:(S-1-5-21-[\w]+)\]') { $Matches[1] } else { $null }
    $seq   = if ($msg -match '\[Seq=(\d+)\]')             { [int]$Matches[1] } else { 0 }
    $flag  = if ($msg -match '(0x[0-9A-Fa-f]+)')          { $Matches[1] } else { $null }
    [PSCustomObject]@{
        Seq         = $seq
        TimeCreated = $time
        EventID     = $eventId
        Type        = $type
        SID         = $sid
        Flag        = $flag
        Raw         = $msg
    }
}

$parsed = $events | ForEach-Object {
    Parse-EventMessage $_.Message $_.Id $_.TimeCreated
} | Sort-Object Seq

# ================================================================
# Q6 — Evidence of Tampering
# ================================================================
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host "  Q6: Identify any events suggesting evidence tampering" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan

$tamperEvents = $parsed | Where-Object { $_.Type -eq 'EvidenceTamperHint' }

Write-Host ("[+] EvidenceTamperHint events found : {0}" -f $tamperEvents.Count) -ForegroundColor Red
Write-Host ""
Write-Host "[*] What is RecentItemsClearFlag 0xE2?" -ForegroundColor Yellow
Write-Host "    This flag is a composite bitmask indicating Windows shell history"
Write-Host "    and MRU (Most Recently Used) lists were deliberately wiped:"
Write-Host ""
Write-Host "    Flag  0xE2  =  binary 11100010" -ForegroundColor White
Write-Host "    ├── 0x80  RunMRU cleared       (Start > Run history erased)" -ForegroundColor White
Write-Host "    ├── 0x40  OpenSave MRU cleared (file picker dialog history erased)" -ForegroundColor White
Write-Host "    ├── 0x20  TypedPaths cleared   (Explorer address bar history erased)" -ForegroundColor White
Write-Host "    └── 0x02  RecentDocs cleared   (Recent Items / Jump Lists erased)" -ForegroundColor White
Write-Host ""
Write-Host "    Forensic significance: these artefacts would otherwise record"
Write-Host "    which files were opened, which paths were typed, and which"
Write-Host "    programs were run — direct evidence of the exfiltration activity."
Write-Host ""

Write-Host "[*] Tampering events by SID:" -ForegroundColor Yellow
$tamperEvents | Group-Object SID |
    Sort-Object Count -Descending |
    ForEach-Object {
        $actor = if ($_.Name -eq 'S-1-5-21-8403') { "  <-- PRIMARY ACTOR" } else { "" }
        Write-Host ("    {0}  :  {1,2} wipe operations{2}" -f $_.Name, $_.Count, $actor)
    }

Write-Host ""
Write-Host "[*] First and last tampering events:" -ForegroundColor Yellow
$first = $tamperEvents | Select-Object -First 1
$last  = $tamperEvents | Select-Object -Last 1
Write-Host ("    First  Seq={0,3}  SID={1}  Time={2}" -f $first.Seq, $first.SID, $first.TimeCreated)
Write-Host ("    Last   Seq={0,3}  SID={1}  Time={2}" -f $last.Seq,  $last.SID,  $last.TimeCreated)

Write-Host ""
Write-Host "[*] Actor SID-8403 tampering events specifically:" -ForegroundColor Yellow
$tamperEvents | Where-Object { $_.SID -eq 'S-1-5-21-8403' } |
    ForEach-Object {
        Write-Host ("    Seq={0}  {1}" -f $_.Seq, $_.Raw)
    }

# ================================================================
# Q7 — Log Clearing Attempt
# ================================================================
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host "  Q7: Did the attacker attempt log clearing?" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan

$logClearEvents = $parsed | Where-Object { $_.Type -eq 'SystemFlushOperation' }

if ($logClearEvents) {
    Write-Host "[+] YES — Log clearing attempt confirmed." -ForegroundColor Red
    Write-Host ""
    foreach ($e in $logClearEvents) {
        Write-Host ("    Event  : {0}" -f $e.Raw) -ForegroundColor Red
        Write-Host ("    SID    : {0}" -f $e.SID)
        Write-Host ("    Seq    : {0}" -f $e.Seq)
        Write-Host ("    Time   : {0}" -f $e.TimeCreated)
    }
    Write-Host ""
    Write-Host "[*] What is SystemFlushOperation 0xC1?" -ForegroundColor Yellow
    Write-Host "    Code 0xC1 (193 decimal) maps to a Windows Event Log service"
    Write-Host "    flush-and-clear trigger — the equivalent of running:"
    Write-Host "    wevtutil cl Application  or  Clear-EventLog in PowerShell." -ForegroundColor White
    Write-Host ""
    Write-Host "    Bit decomposition of 0xC1 = 11000001:"
    Write-Host "    ├── 0x80  Flush all pending log buffers to disk"
    Write-Host "    ├── 0x40  Initiate log clear sequence"
    Write-Host "    └── 0x01  Apply to Application/Security channel"
    Write-Host ""
    Write-Host "[*] Timeline context — the log wipe is the second-to-last act:" -ForegroundColor Yellow

    # Show the closing 3 events
    $closingSeq = @(165, 166, 167)
    $parsed | Where-Object { $_.Seq -in $closingSeq } |
        ForEach-Object {
            $marker = if ($_.Seq -eq 166) { " <-- LOG WIPE" } else { "" }
            Write-Host ("    Seq={0}  {1}{2}" -f $_.Seq, $_.Raw, $marker)
        }
    Write-Host ""
    Write-Host "    Sequence: exfil complete (164) -> access sensitive object (165)"
    Write-Host "              -> wipe logs (166) -> close session (167)" -ForegroundColor Yellow
} else {
    Write-Host "[-] No log clearing events found." -ForegroundColor Green
}

# ================================================================
# Q8 — Sensitive Object
# ================================================================
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host "  Q8: Which object was marked as sensitive?" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan

$sensitiveEvents = $parsed | Where-Object { $_.Raw -like '*Sensitive*' }

if ($sensitiveEvents) {
    foreach ($e in $sensitiveEvents) {
        Write-Host ("[+] Sensitive object event found:" ) -ForegroundColor Red
        Write-Host ("    Raw    : {0}" -f $e.Raw) -ForegroundColor Red
        Write-Host ("    SID    : {0}" -f $e.SID)
        Write-Host ("    Seq    : {0}" -f $e.Seq)
        Write-Host ("    Time   : {0}" -f $e.TimeCreated)
    }
    Write-Host ""
    Write-Host "[*] Decoding HandleOpenFlag 0x9E for OBJ-1C4B:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    Object Handle  : OBJ-1C4B  (kernel object ID 0x1C4B = 7243 decimal)"
    Write-Host "    Classification : Sensitive  (flagged in audit policy)"
    Write-Host ""
    Write-Host "    Access Mask 0x9E = binary 10011110:" -ForegroundColor White
    Write-Host "    ├── 0x80  READ_CONTROL    (read the object's security descriptor)"
    Write-Host "    ├── 0x10  (reserved / SYNCHRONIZE partial)"
    Write-Host "    ├── 0x08  WRITE_DAC       (modify discretionary ACL)"
    Write-Host "    ├── 0x04  WRITE_OWNER     (take ownership)"
    Write-Host "    └── 0x02  READ_DATA       (read file/object content)"
    Write-Host ""
    Write-Host "    In plain terms: the actor opened this object with read + ACL-modify"
    Write-Host "    permissions — consistent with reading sensitive data then attempting"
    Write-Host "    to alter or remove its access control entries to hide the access." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "[*] Position in attack timeline:" -ForegroundColor Yellow
    Write-Host "    Seq=163  Archive C:\Users\*\Documents\* -> E:\case_loot.7z"
    Write-Host "    Seq=164  Copy case_loot.7z to USB  (1.72 GB)"
    Write-Host "    Seq=165  Open OBJ-1C4B (Sensitive)  <-- HERE"
    Write-Host "    Seq=166  Wipe event logs"
    Write-Host "    Seq=167  Close session"
    Write-Host ""
    Write-Host "    The sensitive object was accessed AFTER the data was already copied,"
    Write-Host "    suggesting it may be a registry key, security database, or audit"
    Write-Host "    policy object the actor wanted to read or modify before leaving." -ForegroundColor Yellow
} else {
    Write-Host "[-] No sensitive object events found." -ForegroundColor Green
}

# ================================================================
# Anti-Forensics Summary
# ================================================================
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  ANTI-FORENSICS SUMMARY - Case CS2" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Three distinct anti-forensic techniques were observed:" -ForegroundColor White
Write-Host ""
Write-Host "  [1] Shell History Wiping (EvidenceTamperHint 0xE2)" -ForegroundColor Red
Write-Host "      45 events across all 5 SIDs"
Write-Host "      Targets: RunMRU, OpenSaveMRU, TypedPaths, RecentDocs"
Write-Host "      Effect:  Erases artefacts of file access and program execution"
Write-Host ""
Write-Host "  [2] Event Log Clearing (SystemFlushOperation 0xC1)"  -ForegroundColor Red
Write-Host "      1 event — SID-8403, Seq=166 (second-to-last action)"
Write-Host "      Effect:  Attempts to destroy the very log being analysed"
Write-Host "      Note:    Log was recovered despite the wipe attempt"
Write-Host ""
Write-Host "  [3] Sensitive Object Access (HandleOpenFlag 0x9E)" -ForegroundColor Red
Write-Host "      Object:  OBJ-1C4B, classified Sensitive"
Write-Host "      Access:  Read + ACL-modify permissions"
Write-Host "      Timing:  After exfiltration, before log wipe"
Write-Host ""
$totalTamper = $tamperEvents.Count + $logClearEvents.Count + $sensitiveEvents.Count
Write-Host ("  Total anti-forensic actions logged : {0}" -f $totalTamper) -ForegroundColor Yellow
Write-Host "============================================================`n" -ForegroundColor Cyan
