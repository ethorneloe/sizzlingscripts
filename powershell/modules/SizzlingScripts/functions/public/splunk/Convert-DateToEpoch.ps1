function Convert-DateToEpoch {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [ValidateScript({
            $_ -is [DateTime]
        })]
        [DateTime]$Time = (Get-Date),  # Default to current date/time if no input is given

        [Parameter(Mandatory=$false)]
        [Switch]$ConvertToUTC
    )

    # Convert the time to UTC if the switch is provided
    if ($ConvertToUTC) {
        $Time = $Time.ToUniversalTime()
    }

    $start = [DateTime]"1970-01-01 00:00:00"
    try {
        $epochTime = [Math]::Floor((New-TimeSpan -Start $start -End $Time).TotalSeconds)
        return $epochTime
    }
    catch {
        Write-Error "Failed to convert date to epoch time. Error: $_"
        return $null
    }
}
