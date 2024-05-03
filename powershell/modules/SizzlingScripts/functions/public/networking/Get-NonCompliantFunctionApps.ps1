<#
.SYNOPSIS
    Retrieves a list of non-compliant Azure Function Apps based on network settings.

.DESCRIPTION
    This function checks all Azure Function Apps across all subscriptions for specific compliance criteria related to network access and security settings. It flags apps that do not meet these criteria, such as incorrect IP restrictions or settings.

.PARAMETER allowList
    An array of allowed IP addresses/subnets in CIDR notation that are considered compliant.

.EXAMPLE
    $allowedIPs = @"
    [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "10.0.3.0/24"
    ]
    "@ | ConvertFrom-Json
    $nonCompliantApps = Get-NonCompliantFunctionApps -allowList $allowedIPs
    $nonCompliantApps | Format-Table

.NOTES
    Dependencies:
        1. Test-IPv4CIDRString function in this module.
#>

function Get-NonCompliantFunctionApps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$allowList
    )

    try {
        $allowList | Test-IPv4CIDRString | Out-Null
    }
    catch {
        $exception = "Allow list contains one or more incorrect CIDR strings - " + $_.Exception.Message
        throw $exception
    }

    $subscriptionIds = az account list --all | convertfrom-json | Select-Object -ExpandProperty id

    # Create an empty ArrayList
    $nonCompliantFunctions = New-Object System.Collections.ArrayList

    foreach ($subscriptionId in $subscriptionIds) {
        # Set the active subscription
        az account set --subscription $subscriptionId

        # List all function apps in the current subscription
        $functionApps = az resource list --resource-type 'Microsoft.Web/sites' | ConvertFrom-Json | Where-Object { $_.kind -match "functionapp" }

        foreach ($functionApp in $functionApps) {
            # Retrieve the function app configuration
            $functionAppConfig = az functionapp config show --resource-group $functionApp.resourceGroup --name $functionApp.name | ConvertFrom-Json

            #if the properties are null non-compliant and continue to next
            if ($null -eq $functionAppConfig.publicNetworkAccess `
                    -or $null -eq $functionAppConfig.ipSecurityRestrictionsDefaultAction `
                    -or $null -eq $functionAppConfig.scmIpSecurityRestrictionsDefaultAction `
                    -or $null -eq $functionAppConfig.scmIpSecurityRestrictionsUseMain) {

                $nonCompliantFunctions.Add($functionAppConfig) | Out-Null
                continue
            }

            # Get the configured 'Allow' IP restrictions.  Only getting the main ones as the the 'Use main site rules' option must be ticked for compliance.
            $IPRestrictions = $functionAppConfig.ipSecurityRestrictions | where-object { $_.action -eq 'Allow' } | Select-Object -ExpandProperty ipAddress

            # Check that the allow rules all contain IP ranges that fall within the allowList ranges
            $allAllowed = !($ipRestrictions | Where-Object { $allowList -notcontains $_ })

            # Check for non-compliance based on multiple conditions
            if ($functionAppConfig.publicNetworkAccess -ne 'Disabled' `
                    -and ( $functionAppConfig.ipSecurityRestrictionsDefaultAction -ne 'Deny' `
                        -or $functionAppConfig.scmIpSecurityRestrictionsDefaultAction -ne 'Deny' `
                        -or $functionAppConfig.scmIpSecurityRestrictionsUseMain -ne $true `
                        -or $allAllowed -ne $true) ) {
                # Add non-compliant function apps to the ArrayList
                $nonCompliantFunctions.Add($functionAppConfig) | Out-Null
            }
        }
    }

    # Return the list of non-compliant function apps
    return $nonCompliantFunctions
}