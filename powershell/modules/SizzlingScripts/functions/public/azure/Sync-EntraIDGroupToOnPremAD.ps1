<#
.SYNOPSIS
    Synchronizes members from an Entra ID group to an on-premises Active Directory (AD) group, tracking changes in a JSON object.

.DESCRIPTION
    This script connects to Microsoft Graph using certificate-based authentication to retrieve members of a specified Entra ID group.
    It then retrieves members of a specified on-premises AD group, compares the two lists, updates the on-premises AD group by
    adding members that are present in Entra ID but not in on-premises AD, and removing members that are present in on-premises AD
    but not in Entra ID. Additionally, it tracks the changes by creating a JSON object containing detailed information about
    the synchronization process, including any failures encountered during the add/remove operations.

.PARAMETER TenantId
    The Azure tenant ID.

.PARAMETER ClientId
    The Application (client) ID of the Entra ID app registration.

.PARAMETER CertificateThumbprint
    The thumbprint of the certificate used for authentication.

.PARAMETER AzureGroupId
    The Object ID of the Entra ID group to synchronize from.

.PARAMETER OnPremGroupName
    The name of the on-premises AD group to synchronize to.

.PARAMETER LogFilePath
    (Optional) The file path where the JSON output will be saved. If not specified, the JSON output will be written to the console.

.EXAMPLE
    Sync-EntraIDGroupToOnPremAD `
        -TenantId "your-tenant-id" `
        -ClientId "your-client-id" `
        -CertificateThumbprint "your-cert-thumbprint" `
        -AzureGroupId "azure-group-id" `
        -OnPremGroupName "OnPremGroupName" `
        -LogFilePath "C:\Logs\GroupSyncLog.json"

.NOTES
    - Ensure that the Entra ID application has the `GroupMember.Read.All` application permission granted with admin consent.
    - The certificate must be installed in the local machine's certificate store and associated with the Entra ID application.
    - The account executing the script must have the necessary permissions to modify the on-premises AD group.
    - Requires PowerShell 5.1 or later and the following modules:
        - Microsoft.Graph (Install-Module Microsoft.Graph -Scope CurrentUser)
        - ActiveDirectory (Included with RSAT on Windows)
#>

function Sync-EntraIDGroupToOnPremAD {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $true)]
        [string]$AzureGroupId,

        [Parameter(Mandatory = $true)]
        [string]$OnPremGroupDN,

        [Parameter(Mandatory = $false)]
        [string]$LogFilePath
    )

    # Prevent management of built-in groups
    if ($OnPremGroupDN -like "*Builtin*") {
        Write-Error "Built-in groups cannot be managed."
        return
    }

    # Additional system groups that should not be managed
    $forbiddenGroups = @(
        "Domain Computers",
        "Domain Controllers",
        "Schema Admins",
        "Enterprise Admins",
        "Cert Publishers",
        "Domain Admins",
        "Domain Users",
        "Domain Guests",
        "Group Policy Creator Owners",
        "RAS and IAS Servers",
        "Allowed RODC Password Replication Group",
        "Denied RODC Password Replication Group",
        "Read-only Domain Controllers",
        "Enterprise Read-only Domain Controllers",
        "Cloneable Domain Controllers",
        "Protected Users",
        "Key Admins",
        "Enterprise Key Admins",
        "DnsAdmins",
        "DnsUpdateProxy"
    )

    # Check if the group is in the forbidden list
    if ($forbiddenGroups -contains $OnPremGroupDN) {
        Write-Error "The specified group cannot be managed."
        return
    }

    # This gets the eligible users and how long their eligibility is for
    # Can be used to make sure the group memberships are correct and nothing has been added in some other way.
    # Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance  -Filter "groupId eq 'b8a91352-aa76-4b4a-8413-e4e85fc17137'" | fl *
    #
    # This gets the eligible users that have activated their eligibility (should be the same as the members in the group at any given time)
    # Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleInstance  -Filter "groupId eq 'b8a91352-aa76-4b4a-8413-e4e85fc17137'" | fl *

    # Import required modules
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Groups -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.Governance
    Import-Module ActiveDirectory -ErrorAction Stop

    ### **Function Definitions**

    # Function to connect to Microsoft Graph using certificate-based authentication
    function Connect-MicrosoftGraphCert {
        param (
            [string]$TenantId,
            [string]$ClientId,
            [string]$CertificateThumbprint
        )

        try {
            # Retrieve the certificate from the local machine store
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }

            if (-not $cert) {
                throw "Certificate with thumbprint '$CertificateThumbprint' not found in LocalMachine\My store."
            }

            # Connect to Microsoft Graph
            Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -Certificate $cert -Scopes "GroupMember.Read.All", "User.Read.All", "PrivilegedAssignmentSchedule.Read.AzureADGroup" -ErrorAction Stop

        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph: $_"
            throw
        }
    }

    # Function to retrieve members from an Entra ID group. This must be a group that is PIM-enabled as this ensures membership is managed by granting eligibility by a priveliged group admin
    # and group adminisrators are not allowed to add members. Members must follow the configured PIM workflow such as providing a reason for adding themselves and setting the timeframe for the membership.
    function Get-EntraIDGroupMembers {
        param (
            [string]$GroupId
        )

        try {
            # Check that the group is PIM-enabled and throw exception if not.
            $group = Get-MgGroup -GroupId $GroupId -ErrorAction Stop

            # Initialize an empty array to store UPNs
            $memberUPNs = @()

            # Retrieve all members with paging
            $members = Get-MgGroupMember -GroupId $GroupId -All -ConsistencyLevel eventual -ErrorAction Stop

            foreach ($member in $members) {
                if ($member.'@odata.type' -eq "#microsoft.graph.user") {
                    $user = Get-MgUser -UserId $member.Id -Property "UserPrincipalName" -ErrorAction SilentlyContinue
                    if ($user) {
                        $memberUPNs += $user.UserPrincipalName
                    }
                }
            }

            return $memberUPNs
        }
        catch {
            Write-Error "Error fetching Entra ID group members: $_"
            throw
        }
    }

    # Function to retrieve members from an on-premises AD group
    function Get-OnPremADGroupMembers {
        param (
            [string]$GroupName
        )

        try {
            # Retrieve all user members recursively
            $members = Get-ADGroupMember -Identity $GroupName -Recursive -ErrorAction Stop | Where-Object {
                $_.objectClass -eq "user"
            }

            # Extract UserPrincipalName for each member
            $memberUPNs = foreach ($member in $members) {
                $user = Get-ADUser -Identity $member.SamAccountName -Properties UserPrincipalName -ErrorAction SilentlyContinue
                if ($user) {
                    $user.UserPrincipalName
                }
            }

            return $memberUPNs
        }
        catch {
            Write-Error "Error fetching On-Prem AD group members: $_"
            throw
        }
    }

    # Function to Update on-premises AD group members with Entra ID group members
    function Update-OnPremADGroup {
        param (
            [string[]]$AzureMembers,
            [string[]]$OnPremMembers,
            [string]$OnPremGroupDN
        )

        # Determine members to add (in Azure but not in On-Prem)
        $membersToAdd = $AzureMembers | Where-Object { $_ -notin $OnPremMembers }

        # Determine members to remove (in On-Prem but not in Azure)
        $membersToRemove = $OnPremMembers | Where-Object { $_ -notin $AzureMembers }

        # Initialize arrays to track successful additions, removals, and failures
        $successfulAdds = @()
        $successfulRemoves = @()
        $failedAdds = @()
        $failedRemoves = @()

        # Add new members
        foreach ($userUPN in $membersToAdd) {
            try {
                $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$userUPN'" -ErrorAction Stop
                Add-ADGroupMember -Identity $OnPremGroupDN -Members $adUser -ErrorAction Stop
                $successfulAdds += $userUPN
            }
            catch {
                $failedAdds += @{
                    UserPrincipalName = $userUPN
                    ErrorMessage      = $_.Exception.Message
                }
            }
        }

        # Remove old members
        foreach ($userUPN in $membersToRemove) {
            try {
                $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$userUPN'" -ErrorAction Stop
                Remove-ADGroupMember -Identity $OnPremGroupDN -Members $adUser -Confirm:$false -ErrorAction Stop
                $successfulRemoves += $userUPN
            }
            catch {
                $failedRemoves += @{
                    UserPrincipalName = $userUPN
                    ErrorMessage      = $_.Exception.Message
                }
            }
        }

        return @{
            AddedMembers   = $successfulAdds
            RemovedMembers = $successfulRemoves
            FailedAdds     = $failedAdds
            FailedRemoves  = $failedRemoves
        }
    }

    ### **Main Execution Flow**

    try {
        # Step 1: Connect to Microsoft Graph
        Connect-MicrosoftGraphCert -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint

        # Step 2: Extract members from Entra ID and On-Premises AD
        $azureGroupMembers = Get-EntraIDGroupMembers -GroupId $AzureGroupId
        $onPremGroupMembers = Get-OnPremADGroupMembers -GroupName $OnPremGroupDN

        # Step 3: Update On-Premises AD Group
        $reconciliationResult = Update-OnPremADGroup -AzureMembers $azureGroupMembers -OnPremMembers $onPremGroupMembers -OnPremGroupName $OnPremGroupDN

        # Step 4: Prepare JSON Tracking Object
        $timestamp = (Get-Date).ToString("o")  # ISO 8601 format

        $jsonObject = @{
            $onPremGroupDN                = $onPremGroupDN
            AzureGroupId                  = $AzureGroupId
            OnPremGroupMembersBeforeSync  = $onPremGroupMembers
            AzureGroupMembers             = $azureGroupMembers
            MembersAddedToOnPremGroup     = $reconciliationResult.AddedMembers
            MembersRemovedFromOnPremGroup = $reconciliationResult.RemovedMembers
            MembersFailedToAdd            = $reconciliationResult.FailedAdds
            MembersFailedToRemove         = $reconciliationResult.FailedRemoves
            Timestamp                     = $timestamp
        }

        $jsonOutput = $jsonObject | ConvertTo-Json -Depth 10

        # Step 5: Output or Log the JSON Object
        if ($PSBoundParameters.ContainsKey('LogFilePath') -and -not [string]::IsNullOrWhiteSpace($LogFilePath)) {
            try {
                $jsonOutput | Out-File -FilePath $LogFilePath -Encoding UTF8 -Force
            }
            catch {
                Write-Warning "Failed to write JSON output to file: $_"
                Write-Output $jsonOutput
            }
        }
        else {
            Write-Output $jsonOutput
        }
    }
    catch {
        Write-Error "An error occurred during synchronization: $_"
    }
    finally {
        # Disconnect from Microsoft Graph
        Disconnect-MgGraph
        # Optionally, you can log disconnection if needed
    }
}
