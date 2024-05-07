<#
.SYNOPSIS
    Tests if a given string is a valid IPv4 CIDR notation.

.DESCRIPTION
    This function validates an IPv4 CIDR string to ensure it is in the correct format and range.
    The CIDR input must not contain spaces, must have a valid IPv4 address, and a subnet mask
    that ranges from 0 to 32. The function throws exceptions with specific error messages for
    various types of invalid input.

.EXAMPLE
    Test-IPv4CIDRString -cidr "192.168.1.1/24"
    Returns $true because "192.168.1.1/24" is a valid IPv4 CIDR notation.

.EXAMPLE
    Test-IPv4CIDRString -cidr "192.168.1.1/33"
    Throws an error because the subnet mask 33 is out of the allowed range (0-32).

.PARAMETER cidr
    The IPv4 CIDR string that needs to be validated. The string format should be IP address followed by a slash and a subnet mask.
#>

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