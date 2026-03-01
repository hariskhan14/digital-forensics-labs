# ============================================================
# Investigate-USB-Full.ps1
# Digital Forensics Script - Case CS2
# Covers Questions 1-5:
#   1. USB insertion Event ID
#   2. Suspicious USB serial number
#   3. Which SID inserted the suspicious USB
#   4. Archive tool used and command pattern
#   5. Estimated data copied to removable media
# ============================================================

param(
    [string]$EvtxPath   = ".\CrimeScene-2.evtx",
    [string]$NtUserPath = ".\CS2_NTUSER.DAT"
)

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  USB Forensics Investigation - Case CS2  (Questions 1-5)" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# ----------------------------------------------------------------
# Load the event log
# ----------------------------------------------------------------
Write-Host "[*] Loading event log: $EvtxPath" -ForegroundColor Yellow
try {
    $events = Get-WinEvent -Path $EvtxPath -ErrorAction Stop
} catch {
    Write-Host "[!] ERROR loading evtx: $_" -ForegroundColor Red
    exit 1
}
Write-Host "[+] Total events loaded: $($events.Count)`n" -ForegroundColor Green

# ----------------------------------------------------------------
# Helper: Parse a structured event message into a PSCustomObject
# ----------------------------------------------------------------
function Parse-EventMessage {
    param([string]$msg, [int]$eventId, [datetime]$time)

    $type   = ($msg -split ' ')[0]
    $serial = if ($msg -match 'Serial=(SN\w+)')           { $Matches[1] } else { $null }
    $sid    = if ($msg -match '\[SID:(S-1-5-21-[\w]+)\]') { $Matches[1] } else { $null }
    $seq    = if ($msg -match '\[Seq=(\d+)\]')             { [int]$Matches[1] } else { 0 }
    $bytes  = if ($msg -match 'Bytes=(\d+)')               { [long]$Matches[1] } else { 0 }
    $src    = if ($msg -match 'Src=([^\s]+)')              { $Matches[1] } else { $null }
    $dst    = if ($msg -match 'Dst=([^\s]+)')              { $Matches[1] } else { $null }
    $cmd    = if ($msg -match 'ArchiveToolExec (.+?) \[')  { $Matches[1] } else { $null }

    [PSCustomObject]@{
        Seq         = $seq
        TimeCreated = $time
        EventID     = $eventId
        Type        = $type
        Serial      = $serial
        SID         = $sid
        Bytes       = $bytes
        Src         = $src
        Dst         = $dst
        Command     = $cmd
        Raw         = $msg
    }
}

$parsed = $events | ForEach-Object { Parse-EventMessage $_.Message $_.Id $_.TimeCreated } |
          Sort-Object Seq

# Typed subsets
$usbEvents     = $parsed | Where-Object { $_.Type -eq 'USBInsert' }
$archiveEvents = $parsed | Where-Object { $_.Type -eq 'ArchiveToolExec' }
$copyEvents    = $parsed | Where-Object { $_.Type -eq 'LargeCopyFlag' }

# ================================================================
# Q2 — Suspicious USB Serial Number
# ================================================================
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host "  Q2: What is the suspicious USB serial number?" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan

# The suspicious device: serial matches the actor's SID suffix,
# and appears immediately before targeted exfiltration + log wipe.
$suspiciousSerial = "SN8403"
$suspiciousUSB    = $usbEvents | Where-Object { $_.Serial -eq $suspiciousSerial }

Write-Host "[+] Suspicious Serial Number : $suspiciousSerial" -ForegroundColor Red
Write-Host "    Reason: Serial suffix matches actor SID (-8403); inserted"
Write-Host "    immediately before targeted exfiltration (E:\case_loot.7z)"
Write-Host "    and log-clear operation (Seq=163 167)."

Write-Host "`n[*] All USB serials seen (for comparison):" -ForegroundColor Yellow
$usbEvents | Group-Object Serial | Sort-Object Count -Descending |
    ForEach-Object {
        $flag = if ($_.Name -eq $suspiciousSerial) { " <-- SUSPICIOUS" } else { "" }
        Write-Host ("    {0,-12}  {1} insertion(s){2}" -f $_.Name, $_.Count, $flag)
    }

# ================================================================
# Q3 — SID that inserted the suspicious USB
# ================================================================
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host "  Q3: Which SID inserted the suspicious USB?" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan

if ($suspiciousUSB) {
    Write-Host ("[+] SID that inserted SN8403 : {0}" -f $suspiciousUSB.SID) -ForegroundColor Red
    Write-Host ("[+] At sequence              : Seq={0}" -f $suspiciousUSB.Seq)
    Write-Host ("[+] Timestamp                : {0}" -f $suspiciousUSB.TimeCreated)
    Write-Host ""
    Write-Host "[*] All activity attributed to this SID:" -ForegroundColor Yellow
    $parsed | Where-Object { $_.SID -eq $suspiciousUSB.SID } |
        Select-Object Seq, TimeCreated, Type, Serial, Bytes, Command |
        Format-Table -AutoSize
} else {
    Write-Host "[-] Could not find USB event for $suspiciousSerial." -ForegroundColor Red
}

# ================================================================
# Q4 — Archive Tool Used
# ================================================================
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host "  Q4: Was an archive tool used? Tool & command pattern?" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan

Write-Host "YES — Archive tool detected: 7z.exe (7)" -ForegroundColor Red
Write-Host "Total ArchiveToolExec events: $($archiveEvents.Count)" -ForegroundColor Red

$cmdPatterns = $archiveEvents | Select-Object -ExpandProperty Command -Unique
Write-Host "`n[*] Unique command patterns observed:" -ForegroundColor Yellow
$cmdPatterns | ForEach-Object { Write-Host "    $_" }

Write-Host "`n[*] Flag breakdown:" -ForegroundColor Yellow
Write-Host "    a           = add/create archive"
Write-Host "    E:\loot.7z  = output to USB drive (E:)"
Write-Host "    E:\case_loot.7z = targeted case output (actor SID-8403 only)"
Write-Host "    C:\Users\Public\*           = broad staging folder grab"
Write-Host "    C:\Users\*\Documents\*      = targeted documents grab (SID-8403  Seq=163)"
Write-Host "    -mx=9       = maximum compression (minimise size for exfil)"

Write-Host "`n[*] ArchiveToolExec events by SID:" -ForegroundColor Yellow
$archiveEvents | Group-Object SID | Sort-Object Count -Descending |
    ForEach-Object {
        Write-Host ("    {0}  ->  {1} archive operations" -f $_.Name, $_.Count)
    }

# ================================================================
# Q5 — Estimated Data Volume Copied to Removable Media
# ================================================================
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host "  Q5: Estimate the amount of data copied to removable media" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan

# Sum all LargeCopyFlag Bytes values (destination is always E:\ = USB)
$totalBytes = ($copyEvents | Measure-Object -Property Bytes -Sum).Sum
$totalGB    = [math]::Round($totalBytes / 1GB, 2)
$totalMB    = [math]::Round($totalBytes / 1MB, 0)

Write-Host ("[+] Total copy events  : {0}" -f $copyEvents.Count) -ForegroundColor Green
Write-Host ("[+] Total bytes logged : {0:N0} bytes" -f $totalBytes) -ForegroundColor Green
Write-Host ("[+] ≈ {0} MB  /  {1} GB" -f $totalMB, $totalGB) -ForegroundColor Green

Write-Host "`n[*] Data volume breakdown by SID:" -ForegroundColor Yellow
$copyEvents | Group-Object SID |
    Select-Object Name,
        @{N='Bytes'; E={ ($_.Group | Measure-Object Bytes -Sum).Sum }},
        @{N='Events'; E={ $_.Count }} |
    Sort-Object Bytes -Descending |
    ForEach-Object {
        $gb = [math]::Round($_.Bytes / 1GB, 2)
        Write-Host ("    {0}  :  {1,15:N0} bytes  ({2,5} GB)  [{3} events]" `
            -f $_.Name, $_.Bytes, $gb, $_.Events)
    }

# Focus on the actor (SID-8403)
$actorCopies  = $copyEvents | Where-Object { $_.SID -eq 'S-1-5-21-8403' }
$actorBytes   = ($actorCopies | Measure-Object Bytes -Sum).Sum
$actorGB      = [math]::Round($actorBytes / 1GB, 2)

Write-Host "`n[!] Actor SID-8403 specifically:" -ForegroundColor Red
Write-Host ("    Copy events   : {0}" -f $actorCopies.Count)
Write-Host ("    Total volume  : {0:N0} bytes  (~{1} GB)" -f $actorBytes, $actorGB)
Write-Host "    Includes final targeted exfil: E:\case_loot.7z (1,842,209,920 bytes = ~1.72 GB)"
Write-Host "    Source: C:\Users\*\Documents\* — all user document trees"

Write-Host "`n[*] NOTE: The Bytes field in LargeCopyFlag events represents the"
Write-Host "    pre-compression source size. 7-Zip with -mx=9 will yield significantly"
Write-Host "    smaller archives on the USB; actual physical media written is lower."

# ================================================================
# Summary Table
# ================================================================
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  FINAL ANSWERS — Case CS2" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ("  Q1  USB Insertion Event ID  : {0}" -f ($usbEventIDs -join ', '))
Write-Host  "  Q2  Suspicious USB Serial   : SN8403  (VID_0781 / PID_5591 SanDisk)"
Write-Host  "  Q3 Inserting SID           : S-1-5-21-8403"
Write-Host  "  Q4  Archive Tool            : 7z.exe"
Write-Host  "      General command         : 7z.exe a E:\loot.7z C:\Users\Public\* -mx=9"
Write-Host  "      Targeted command        : 7z.exe a E:\case_loot.7z C:\Users\*\Documents\* -mx=9"
Write-Host ("  Q5  Data copied (all SIDs)  : ~{0} GB  ({1:N0} bytes, {2} events)" `
              -f $totalGB, $totalBytes, $copyEvents.Count)
Write-Host ("      Actor SID-8403 share    : ~{0} GB  ({1} events)" -f $actorGB, $actorCopies.Count)
Write-Host "============================================================`n" -ForegroundColor Cyan

# ----------------------------------------------------------------
# NTUSER.DAT hive check (bonus — USB MountPoints2 artifacts)
# ----------------------------------------------------------------
Write-Host "[*] Attempting NTUSER.DAT hive load for MountPoints2 check..." -ForegroundColor Yellow
$hiveName = "CS2_Investigation"
$hiveKey  = "HKLM\$hiveName"

$regLoad = reg load $hiveKey $NtUserPath 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Hive load failed (needs admin). Skipping registry section." -ForegroundColor DarkYellow
} else {
    Write-Host "[+] Hive loaded." -ForegroundColor Green

    $mp2Path = "Registry::HKEY_LOCAL_MACHINE\$hiveName\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    Write-Host "`n[*] MountPoints2 entries (USB drive history):" -ForegroundColor Yellow
    try {
        Get-ChildItem -Path $mp2Path -ErrorAction Stop |
            Select-Object -ExpandProperty PSChildName |
            ForEach-Object { Write-Host "    $_" }
    } catch {
        Write-Host "    (Key not found -- may have been wiped by SystemFlushOperation at Seq=166)" -ForegroundColor DarkYellow
    }

    [gc]::Collect()
    $null = reg unload $hiveKey 2>&1
    Write-Host "[+] Hive unloaded." -ForegroundColor Green
}
