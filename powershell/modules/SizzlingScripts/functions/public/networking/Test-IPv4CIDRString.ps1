function Test-IPv4CIDRString {
    param(
        [string]$cidr
    )

    # Split the string by the '/' character to separate the IP address from the subnet mask
    $parts = $cidr -split '/'
    if ($parts.Count -ne 2) {
        Write-Output "Invalid CIDR format."
        return $false
    }

    # Declare a variable to hold the parsed IP address
    $ip = $null

    # Validate the IP address part using [System.Net.IPAddress]::TryParse
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$ip)) {
        Write-Output "Invalid IP address."
        return $false
    }

    # Ensure the IP address is IPv4
    if ($ip.AddressFamily -ne 'InterNetwork') {
        Write-Output "Not an IPv4 address."
        return $false
    }

    # Validate the subnet mask is within the valid range for IPv4
    $subnet = $parts[1]
    if ($subnet -match '^\d+$' -and $subnet -ge 0 -and $subnet -le 32) {
        Write-Output "Valid IPv4 CIDR notation."
        return $true
    }
    else {
        Write-Output "Invalid subnet mask."
        return $false
    }
}