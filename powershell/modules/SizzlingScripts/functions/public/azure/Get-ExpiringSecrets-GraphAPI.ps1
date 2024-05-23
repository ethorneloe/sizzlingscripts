<# 
.SYNOPSIS
    Retrieves Azure AD application secrets and certificates, including their owners.

.DESCRIPTION
    This function connects to Microsoft Graph using a user-assigned managed identity and retrieves all Azure AD applications. 
    It extracts the secrets and certificates for each application, along with their owners, and logs the details.

.PARAMETER UserAssignedMI
    The Client ID of the user-assigned managed identity.

.EXAMPLE
    Get-AppCredentialsAndOwners -UserAssignedMI '2510783b-d45a-4dad-bd8e-15dc85d2d4a7'

.NOTES
    Ensure the user-assigned managed identity has the necessary permissions to read application credentials and owners.
#>

function Get-AppCredentialsAndOwners {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserAssignedMI
    )

    # Connect to Microsoft Graph using the managed identity
    Connect-MgGraph -Identity -ClientId $UserAssignedMI -Environment 'Global' > $null

    # Retrieve all applications
    $Applications = Get-MgApplication -All

    # Initialize an array to store logs
    $Logs = @()

    foreach ($App in $Applications) {
        $AppName = $App.DisplayName
        $AppID   = $App.Id
        $ApplID  = $App.AppId

        # Retrieve application credentials
        $AppCreds = Get-MgApplication -ApplicationId $AppID |
            Select-Object PasswordCredentials, KeyCredentials

        $Secrets = $AppCreds.PasswordCredentials
        $Certs   = $AppCreds.KeyCredentials

        foreach ($Secret in $Secrets) {
            $StartDate  = $Secret.StartDateTime
            $EndDate    = $Secret.EndDateTime
            $SecretName = $Secret.DisplayName

            $Owner    = Get-MgApplicationOwner -ApplicationId $App.Id
            $Username = $Owner.AdditionalProperties.userPrincipalName -join ';'
            $OwnerID  = $Owner.Id -join ';'

            if ($null -eq $Owner.AdditionalProperties.userPrincipalName) {
                $Username = @(
                    $Owner.AdditionalProperties.displayName
                    '**<This is an Application>**'
                ) -join ' '
            }
            if ($null -eq $Owner.AdditionalProperties.displayName) {
                $Username = '<<No Owner>>'
            }

            $Logs += [PSCustomObject]@{
                'ApplicationName'        = $AppName
                'ApplicationID'          = $ApplID
                'Secret Name'            = $SecretName
                'Secret Start Date'      = $StartDate
                'Secret End Date'        = $EndDate
                'Certificate Name'       = $Null
                'Certificate Start Date' = $Null
                'Certificate End Date'   = $Null
                'Owner'                  = $Username
                'Owner_ObjectID'         = $OwnerID
            }
        }

        foreach ($Cert in $Certs) {
            $StartDate = $Cert.StartDateTime
            $EndDate   = $Cert.EndDateTime
            $CertName  = $Cert.DisplayName

            $Owner    = Get-MgApplicationOwner -ApplicationId $App.Id
            $Username = $Owner.AdditionalProperties.userPrincipalName -join ';'
            $OwnerID  = $Owner.Id -join ';'

            if ($null -eq $Owner.AdditionalProperties.userPrincipalName) {
                $Username = @(
                    $Owner.AdditionalProperties.displayName
                    '**<This is an Application>**'
                ) -join ' '
            }
            if ($null -eq $Owner.AdditionalProperties.displayName) {
                $Username = '<<No Owner>>'
            }

            $Logs += [PSCustomObject]@{
                'ApplicationName'        = $AppName
                'ApplicationID'          = $ApplID
                'Secret Name'            = $Null
                'Certificate Name'       = $CertName
                'Certificate Start Date' = $StartDate
                'Certificate End Date'   = $EndDate
                'Owner'                  = $Username
                'Owner_ObjectID'         = $OwnerID
            }
        }
    }

    return $Logs
}