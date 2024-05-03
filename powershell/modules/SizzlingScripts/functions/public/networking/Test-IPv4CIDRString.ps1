function Test-IPv4CIDRString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$cidr
    )

    process {
        # Make sure there aren't any spaces
        if ($cidr -match '\s') {
            throw "Spaces are not permitted in the input: $cidr"
        }

        # Split the string by '/' to separate the IP address from the subnet mask
        $parts = $cidr -split '/'
        if ($parts.Count -ne 2) {
            throw "Invalid CIDR format for input: $cidr"
        }

        # Validate the subnet mask is an integer from 0 to 32
        $subnet = $parts[1]
        if (-not ($subnet -as [int] -is [int]) -or $subnet -lt 0 -or $subnet -gt 32) {
            throw "Invalid subnet mask for input: $cidr"
        }

        # Split the IP address into its components
        $ipParts = $parts[0] -split '\.'
        if ($ipParts.Count -ne 4) {
            throw "IP address must have exactly three dots for input: $cidr"
        }

        # Check for leading zeros, spaces, empty string and segment out of range
        foreach ($part in $ipParts) {
            if (-not ($part -as [int] -is [int]) -or [int]$part -lt 0 -or [int]$part -gt 255 -or [string]::IsNullOrEmpty($part)) {
                throw "Each segment of the IP address must be a number between 0 and 255 for input: $cidr"
            }
            if ($part -ne '0' -and $part.StartsWith('0')) {
                throw "Leading zeros are not allowed except for 0 itself in input: $cidr"
            }
        }

        # If all checks pass, return true
        return $true
    }
}