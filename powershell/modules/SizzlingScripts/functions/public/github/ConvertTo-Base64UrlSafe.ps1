<#
.SYNOPSIS
Converts input to a Base64Url-safe encoded string.

.DESCRIPTION
The ConvertTo-Base64UrlSafe function takes an input object, which can be a string, byte array, or any object that can be converted to JSON, and returns a Base64Url-safe encoded string.
This encoding ensures the output is safe to use in URLs and filenames by replacing certain characters that have special meanings in URLs and filesystems.

.PARAMETER Input
The input object to encode. This parameter can accept strings, byte arrays, or other objects. If the input is not a byte array, the function will convert the input to a JSON string before encoding.

.EXAMPLE
$encodedString = ConvertTo-Base64UrlSafe -Input "Hello, World!"
This example encodes a simple string to a Base64Url-safe format.

.EXAMPLE
$object = @{name="John"; age=30}
$encodedString = ConvertTo-Base64UrlSafe -Input $object
This example converts a hashtable to a JSON string, then encodes it to a Base64Url-safe format.

.INPUTS
String, Byte[], Object
You can input a string directly, provide a byte array, or pass any object that can be serialized to JSON.

.OUTPUTS
String
Outputs a Base64Url-safe encoded string.
#>

function ConvertTo-Base64UrlSafe {
    param(
        [Parameter(Mandatory = $true)]
        [object] $inputObject
    )

    $bytes = $null
    if ($inputObject -is [byte[]]) {
        $bytes = $inputObject
    }
    elseif ($inputObject -is [string]) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($inputObject)
    }
    else {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes(($inputObject | ConvertTo-Json))
    }

    # Modify the Base64 encoding to be URL safe by replacing '+', '/', and removing padding '=' characters.
    return [Convert]::ToBase64String($bytes) -replace '\+', '-' -replace '/', '_' -replace '=+$', ''
}
