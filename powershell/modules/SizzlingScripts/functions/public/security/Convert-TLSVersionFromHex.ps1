<#
.SYNOPSIS
Converts hexadecimal TLS version codes to their descriptive string equivalents.

.DESCRIPTION
This function takes a hexadecimal TLS version code as input and returns the corresponding TLS version name. It supports conversion for versions from SSL 3.0 up to TLS 1.3, including a placeholder for reserved codes.

.EXAMPLE
PS> Convert-TLSVersionFromHex -HexCode "0x0303"
TLS 1.2

This example shows how to convert the hexadecimal code "0x0303" to its corresponding TLS version name, TLS 1.2.

.PARAMETERS
-HexCode
The hexadecimal code representing a TLS version.

.NOTES
The function provides a mapping for commonly used TLS versions and reserved codes. If the hexadecimal code does not match any known TLS version, the function simply returns the input hexadecimal code.
#>
function Convert-TLSVersionFromHex {

    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]$HexCode
    )

    begin {
        $TLSVersionMapping = @{
            "0x0300" = "SSL 3.0"
            "0x0301" = "TLS 1.0"
            "0x0302" = "TLS 1.1"
            "0x0303" = "TLS 1.2"
            "0x0304" = "TLS 1.3"
            "0x0A0A" = "Reserved"
            "0x1A1A" = "Reserved"
            "0x2A2A" = "Reserved"
            "0x3A3A" = "Reserved"
            "0x4A4A" = "Reserved"
            "0x5A5A" = "Reserved"
            "0x6A7A" = "Reserved"
            "0x7A7A" = "Reserved"
            "0x8A8A" = "Reserved"
            "0x9A9A" = "Reserved"
            "0xAAAA" = "Reserved"
            "0xBABA" = "Reserved"
            "0xCACA" = "Reserved"
            "0xDADA" = "Reserved"
            "0xEAEA" = "Reserved"
            "0xFAFA" = "Reserved"
        }
    }

    process {
        if ($TLSVersionMapping.ContainsKey($HexCode)) {
            $TLSVersionMapping[$HexCode]
        }
        else {
            $HexCode
        }
    }
}