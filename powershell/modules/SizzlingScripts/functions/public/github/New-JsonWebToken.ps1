<#
.SYNOPSIS
Generates a JSON Web Token (JWT) using specified header and payload objects and signs it with a private RSA key.

.DESCRIPTION
The New-JsonWebToken function takes a header and payload as hashtables, converts them to a JSON format,
encodes them in Base64Url-safe format, and then signs the resulting token using the RSA-SHA256 algorithm.
The function requires the path to an RSA private key in PEM format for signing.

.PARAMETER Header
A hashtable representing the JWT header. Typically includes the type of token (JWT)
and the signing algorithm (RS256).

.PARAMETER Payload
A hashtable representing the JWT payload. Contains claims such as issuer, subject,
expiration time, etc.

.PARAMETER PrivateKeyPath
The filesystem path to the RSA private key (in PEM format) used for signing the JWT. This parameter cannot be used in conjunction with privateKeyString.

.PARAMETER PrivateKeyString
A string containing the RSA private key (in PEM format) used for signing the JWT. This parameter cannot be used in conjunction with privateKeyPath.

.EXAMPLE
$header = @{ alg = "RS256"; typ = "JWT" }
$payload = @{ sub = "1234567890"; name = "John Doe"; iat = 1516239022 }
$jwt = New-JsonWebToken -Header $header -Payload $payload -PrivateKeyPath "C:\Path\To\privateKey.pem"

This example generates a JWT with the specified header and payload, signed with the RSA private key located at the given path.

.OUTPUTS
String
The function outputs the generated JWT as a string.

#>

function New-JsonWebToken {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $header,

        [Parameter(Mandatory = $true)]
        [hashtable] $payload,

        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [string] $privateKeyPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'String')]
        [string] $privateKeyString
    )

    if ($PSCmdlet.ShouldProcess("New JWT Generation", "Generating a new JSON Web Token")) {
        try {
            # Convert header and payload objects to Base64Url-safe strings
            $headerEncoded = ConvertTo-Base64UrlSafe -InputObject $header
            $payloadEncoded = ConvertTo-Base64UrlSafe -InputObject $payload

            $rsa = [System.Security.Cryptography.RSA]::Create()
            # Load RSA private key for signing
            if ($PSCmdlet.ParameterSetName -eq 'Path') {
                $pemContent = Get-Content -Path $privateKeyPath -Raw
                $rsa.ImportFromPem($pemContent)
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'String') {
                $rsa.ImportFromPem($privateKeyString)
            }

            # Prepare the data to be signed
            $dataToSign = [System.Text.Encoding]::UTF8.GetBytes("$headerEncoded.$payloadEncoded")
            $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256
            $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1

            # Sign the data using the RSA private key and SHA-256 hashing algorithm
            $signature = $rsa.SignData($dataToSign, $hashAlgorithm, $padding)

            # Convert the signature to a Base64Url-safe string
            $signatureEncoded = ConvertTo-Base64UrlSafe -Input $signature

            # Construct the final JWT
            $jwt = "$headerEncoded.$payloadEncoded.$signatureEncoded"
        }
        catch {
            Write-Error "Error generating JWT: $_"
            return $null
        }

        return $jwt
    }
}
