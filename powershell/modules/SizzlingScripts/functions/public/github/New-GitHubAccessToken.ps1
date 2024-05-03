<#
.SYNOPSIS
Retrieves an access token for the GitHub API using a GitHub App.

.DESCRIPTION
The New-GitHubAccessToken function authenticates using a GitHub App's credentials to retrieve an access token. It supports authentication using either the path to the GitHub App's private key file or a base64 encoded private key string.

.PARAMETER installationId
The installation ID for the GitHub App.

.PARAMETER appId
The ID of the GitHub App.

.PARAMETER githubAppKeyPath
Path to the GitHub App's private key file. This parameter cannot be used in conjunction with githubAppKeyString.

.PARAMETER githubAppKeyString
The GitHub App's private key as a base64 encoded string. This parameter cannot be used in conjunction with privateKeyPath.

.EXAMPLE
New-GitHubAccessToken -installationId "123456" -appId "1" -privateKeyPath "path/to/key.pem"
This example shows how to retrieve a GitHub access token using the path to the private key file.

.EXAMPLE
New-GitHubAccessToken -installationId "123456" -appId "1" -githubAppKeyString "base64_encoded_private_key"
This example demonstrates how to retrieve a GitHub access token using a base64 encoded private key string.

.NOTES
The function uses parameter sets to ensure that users provide either a privateKeyPath or a githubAppKeyString, but not both. This approach enhances the security and flexibility of the authentication process.

#>

function New-GitHubAccessToken {
    [CmdletBinding(DefaultParameterSetName = 'Path', SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $installationId,

        [Parameter(Mandatory = $true)]
        [string]
        $appId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [string]
        $githubAppKeyPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'String')]
        [string]
        $githubAppKeyString
    )

    if ($PSCmdlet.ShouldProcess("GitHub Installation ID: $installationId", "Requesting new GitHub access token")) {
        # Define JWT header and payload
        $header = @{
            alg = "RS256"
            typ = "JWT"
        }
        $payload = @{
            iat = [System.DateTimeOffset]::UtcNow.AddSeconds(-10).ToUnixTimeSeconds()
            exp = [System.DateTimeOffset]::UtcNow.AddMinutes(10).ToUnixTimeSeconds()
            iss = $appId
        }

        # Determine which parameter set is being used and call New-JsonWebToken accordingly
        if ($PSBoundParameters.ContainsKey('githubAppKeyPath')) {
            $jwt = New-JsonWebToken -Header $header -Payload $payload -privateKeyPath $githubAppKeyPath
        }
        elseif ($PSBoundParameters.ContainsKey('githubAppKeyString')) {
            $jwt = New-JsonWebToken -Header $header -Payload $payload -privateKeyString $githubAppKeyString
        }

        # Use the JWT to request a new GitHub access token
        $headers = @{
            "Accept"        = "application/vnd.github+json"
            "Authorization" = "Bearer $jwt"
        }

        try {
            $response = Invoke-RestMethod -Uri "https://api.github.com/app/installations/$installationId/access_tokens" -Headers $headers -Method Post
        }
        catch {
            Write-Error "Failed to retrieve access token: $_"
            return $null
        }

        return $response.token
    }
}