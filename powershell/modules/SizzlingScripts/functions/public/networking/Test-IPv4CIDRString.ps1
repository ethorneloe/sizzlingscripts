function Test-IPv4CIDRString {
    param(
        [string]$cidr
    )

    #Make sure there aren't any spaces
    if ($cidr -match '\s') {
        throw "Spaces are not permitted."
    }

    # Split the string by '/' to separate the IP address from the subnet mask
    $parts = $cidr -split '/'
    if ($parts.Count -ne 2) {
        throw "Invalid CIDR format."
    }

    # Validate the subnet mask is an integer from 0 to 32
    $subnet = $parts[1]
    if (-not ($subnet -as [int] -is [int]) -or $subnet -lt 0 -or $subnet -gt 32) {
        throw "Invalid subnet mask."
    }

    # Split the IP address into its components
    $ipParts = $parts[0] -split '\.'
    if ($ipParts.Count -ne 4) {
        throw "IP address must have exactly three dots."
    }

    foreach ($part in $ipParts) {
        if (-not ($part -as [int] -is [int]) -or $part -lt 0 -or $part -gt 255) {
            throw "Each segment of the IP address must be a number between 0 and 255."
        }
        if ($part -ne '0' -and $part.StartsWith('0')) {
            throw "Leading zeros are not allowed except for 0 itself."
        }
    }

    # If all checks pass, return true
    return $true
}
