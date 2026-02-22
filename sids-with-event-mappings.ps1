$path = "E:\Haris\Digital Forensics\Activity3\obfuscated-crime.evtx"

Get-WinEvent -Path $path | ForEach-Object {

    $eventId = $_.Id
    $time = $_.TimeCreated
    $xml = [xml]$_.ToXml()

    # Extract SID
    $sidMatches = [regex]::Matches($_.ToXml(), "S-1-\d+-\d+(-\d+)+")

    # Extract username if present
    $username = $xml.Event.EventData.Data |
        Where-Object { $_.Name -match "TargetUserName|SubjectUserName" } |
        Select-Object -ExpandProperty '#text' -First 1

    foreach ($match in $sidMatches) {

        [PSCustomObject]@{
            EventID = $eventId
            Username = $username
            SID = $match.Value
            Time = $time
        }
    }

} | Sort-Object EventID -Unique | Format-Table -AutoSize