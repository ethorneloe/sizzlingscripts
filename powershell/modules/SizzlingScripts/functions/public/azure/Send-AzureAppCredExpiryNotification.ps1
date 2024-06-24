<#
.SYNOPSIS
Sends notification emails for expiring or expired Azure app registration credentials.

.DESCRIPTION
The Send-AzureAppCredExpiryNotification function connects to Azure Graph API to retrieve all application registrations
and checks for expiring or expired secrets and certificates. If any credentials are nearing their expiry date within 
the specified threshold, an email notification is sent to the application's owners.

.PARAMETER DaysUntilExpiryThreshold
Specifies the number of days until expiry to trigger the notification. The default value is 30 days.

.PARAMETER AppDetailsClientId
The Client ID of the application used to connect to the Graph API for retrieving app registration details.

.PARAMETER AppDetailsCertificateThumbprint
The certificate thumbprint used to authenticate the application for retrieving app registration details.

.PARAMETER AppDetailsTenantId
The Tenant ID associated with the application used to connect to the Graph API for retrieving app registration details.

.PARAMETER GraphMailClientId
The Client ID of the application used to send email notifications via the Graph API.

.PARAMETER GraphMailCertificateThumbprint
The certificate thumbprint used to authenticate the application for sending email notifications via the Graph API.

.PARAMETER GraphMailTenantId
The Tenant ID associated with the application used to send email notifications via the Graph API.

.PARAMETER Sender
The email address of the sender for the notification emails.

.PARAMETER TestRecipient
(Optional) The email address of a test recipient to receive the notifications. If specified, all notifications will be sent to this address instead of the actual owners.

.EXAMPLE
Send-AzureAppCredExpiryNotification -AppDetailsClientId "your-client-id" -AppDetailsCertificateThumbprint "your-thumbprint" -AppDetailsTenantId "your-tenant-id" -GraphMailClientId "your-mail-client-id" -GraphMailCertificateThumbprint "your-mail-thumbprint" -GraphMailTenantId "your-mail-tenant-id" -Sender "noreply@yourdomain.com"

This example sends notifications for expiring or expired app registration credentials using the specified details.

.NOTES
This function requires the Microsoft.Graph.Authentication and Microsoft.Graph.Applications modules.
Make sure to have appropriate permissions to access and send emails through the Graph API.
#>

function Send-AzureAppCredExpiryNotification {
    [CmdletBinding()]
    param (
        [int]$DaysUntilExpiryThreshold = 30, # Default is 30 days

        [Parameter(Mandatory = $true)]
        [string] $AppDetailsClientId,

        [Parameter(Mandatory = $true)]
        [string] $AppDetailsCertificateThumbprint,

        [Parameter(Mandatory = $true)]
        [string] $AppDetailsTenantId,

        [Parameter(Mandatory = $true)]
        [string] $GraphMailClientId,

        [Parameter(Mandatory = $true)]
        [string] $GraphMailCertificateThumbprint,

        [Parameter(Mandatory = $true)]
        [string] $GraphMailTenantId,

        [Parameter(Mandatory = $true)]
        [string] $Sender,

        [Parameter(Mandatory = $false)]
        [string] $TestRecipient

    )

    Import-Module Microsoft.Graph.Authentication -Force
    Import-Module Microsoft.Graph.Applications -Force

    #Remove existing session
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Try {
        Connect-MgGraph -TenantId $AppDetailsTenantId -ClientId $AppDetailsClientId -CertificateThumbprint $AppDetailsCertificateThumbprint -NoWelcome
    }
    catch {
        throw ("Unable to connect to Graph API. Error: " + $_.Exception.Message)
    }

    $Applications = Get-MgApplication -All

    # Create a thread-safe concurrent bag to store results
    $results = [System.Collections.Concurrent.ConcurrentBag[pscustomobject]]::new()

    $Applications | ForEach-Object -Parallel {

        $_results = $using:results
        $_DaysUntilExpiryThreshold = $using:DaysUntilExpiryThreshold
        $Today = Get-Date

        $App = $_
        $AppName = $App.DisplayName
        $AppID = $App.Id
        $ApplID = $App.AppId

        $AppCreds = Get-MgApplication -ApplicationId $AppID |
        Select-Object PasswordCredentials, KeyCredentials

        $Secrets = $AppCreds.PasswordCredentials
        $Certs = $AppCreds.KeyCredentials

        foreach ($Secret in $Secrets) {

            $EndDate = $Secret.EndDateTime
            $DaysLeft = ($EndDate - $Today).Days



            if ($DaysLeft -le $_DaysUntilExpiryThreshold) {

                $StartDate = $Secret.StartDateTime
                $SecretName = $Secret.DisplayName

                $Owner = Get-MgApplicationOwner -ApplicationId $App.Id

                if ($null -ne $Owner) {
                    $Username = $Owner.AdditionalProperties.userPrincipalName -join ';'
                    $OwnerID = $Owner.Id -join ';'
                }

                $AppDetails = [PSCustomObject]@{
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

                $_results.add($AppDetails)
            }
        }

        foreach ($Cert in $Certs) {

            $EndDate = $Cert.EndDateTime
            $DaysLeft = ($EndDate - $Today).Days

            if ($DaysLeft -le $_DaysUntilExpiryThreshold) {

                $StartDate = $Cert.StartDateTime
                $CertName = $Cert.DisplayName

                $Owner = Get-MgApplicationOwner -ApplicationId $App.Id

                if ($null -ne $Owner) {
                    $Username = $Owner.AdditionalProperties.userPrincipalName -join ';'
                    $OwnerID = $Owner.Id -join ';'
                }

                $AppDetails = [PSCustomObject]@{
                    'ApplicationName'        = $AppName
                    'ApplicationID'          = $ApplID
                    'Secret Name'            = $Null
                    'Secret Start Date'      = $Null
                    'Secret End Date'        = $Null
                    'Certificate Name'       = $CertName
                    'Certificate Start Date' = $StartDate
                    'Certificate End Date'   = $EndDate
                    'Owner'                  = $Username
                    'Owner_ObjectID'         = $OwnerID
                }

                $_results.add($AppDetails)
            }
        }
    }

    $groupedResults = $results | Group-Object Owner

    #$groupedResults | fl Name

    # Loop through each group and send an email
    foreach ($group in $groupedResults) {

        # Skip the null owner group
        if ([string]::IsNullOrEmpty($group.Name)) { continue }

        # Prepare HTML content
        $EmailBody = '<html><head>'
        $EmailBody += '<style>'
        $EmailBody += 'table { border-collapse: collapse; width: 100%; }'
        $EmailBody += 'th, td { border: 1px solid black; padding: 8px; text-align: left; }'
        $EmailBody += '</style>'
        $EmailBody += '</head><body>'
        $EmailBody += "<h1>The following Azure app registrations have expiring or expired secrets/certificates</h1>"
        $EmailBody += '<table>'
        $EmailBody += '<tr><th>Application Name</th><th>Secret/Certificate Name</th><th>Expiry Date</th></tr>'

        foreach ($item in $group.Group) {
            $name = "N/A"
            if (!([string]::IsNullOrEmpty($item.'Secret Name'))) {
                $name = $item.'Secret Name'
            }
            elseif (!([string]::IsNullOrEmpty($item.'Certificate Name'))) {
                $name = $item.'Certificate Name'
            }
            $expiryDate = if ($item.'Secret End Date') { $item.'Secret End Date' } else { $item.'Certificate End Date' }

            $EmailBody += "<tr><td>$($item.ApplicationName)</td><td>$name</td><td>$expiryDate</td></tr>"
        }

        $EmailBody += '</table>'
        $EmailBody += '</body></html>'

        $Subject = "Expiring or Expired Azure App Registration Credentials"

        $Recipients = $group.Name -split ';'

        if (!([string]::IsNullOrEmpty($TestRecipient))) {
            $Recipients = $TestRecipient
        }

        # Disconnet from the current context so we can switch to the graph mail context.
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

        Send-GraphMail -ClientId $GraphMailClientId -CertificateThumbprint $GraphMailCertificateThumbprint -Tenant $GraphMailTenantId -Subject $Subject -Body $EmailBody -ToRecipients $Recipients -Sender $Sender -SaveToSentItems
    }
}
