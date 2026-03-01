$path = "E:\Haris\Digital Forensics\Activity3\obfuscated-crime.evtx"

$sids = Get-WinEvent -Path $path |
ForEach-Object {
    $_.ToXml()
} |
Select-String -Pattern "S-1-\d+-\d+(-\d+)+" -AllMatches |
ForEach-Object { $_.Matches.Value } |
Sort-Object -Unique

$sids.Count
$sids