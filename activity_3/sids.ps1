$path = "E:\Haris\Digital Forensics\Activity3\obfuscated-crime.evtx"

# Dictionary of common Security Event IDs
$eventDescriptions = @{
    4624 = "Successful Logon"
    4625 = "Failed Logon Attempt"
    4634 = "Logoff"
    4648 = "Logon using explicit credentials"
    4672 = "Special privileges assigned to new logon"
    4688 = "New process created"
    4720 = "User account created"
    4726 = "User account deleted"
    4732 = "Member added to security-enabled local group"
    1102 = "Audit log cleared"
    4663 = "Object Access Attempt"
    4673 = "Privileged Service Called"
}

Get-WinEvent -Path $path | ForEach-Object {

    $eventId = $_.Id
    $time = $_.TimeCreated
    $xmlString = $_.ToXml()

    # Extract all SIDs from entire XML
    $sidMatches = [regex]::Matches($xmlString, "S-1-\d+-\d+(-\d+)+")

    foreach ($match in $sidMatches) {

        $description = $eventDescriptions[$eventId]
        if (-not $description) { $description = "Other / Not Mapped" }

        [PSCustomObject]@{
            EventID        = $eventId
            Description    = $description
            SID            = $match.Value
            TimeAttempt    = $time
        }
    }

} | Sort-Object EventID, SID -Unique | Format-Table -AutoSize