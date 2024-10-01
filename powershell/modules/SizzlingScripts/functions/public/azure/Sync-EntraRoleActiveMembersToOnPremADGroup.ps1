<#
.SYNOPSIS
    Synchronizes activated Entra role members to an on-premises Active Directory (AD) group, tracking changes in a JSON object.

.DESCRIPTION
    This script connects to Microsoft Graph using certificate-based authentication to retrieve members with an active assignment for a specified Entra role.
    It then retrieves members of a specified on-premises AD group, compares the two lists, updates the on-premises AD group by
    adding members that have the active role assignment but are not in the on-prem AD group, and removing members that are in the
    on-prem AD group but no longer have the active role assignment. Additionally, it tracks the changes by creating a JSON object
    containing detailed information about the synchronization process, including any failures encountered during the add/remove operations.

.PARAMETER TenantId
    The Azure tenant ID.

.PARAMETER ClientId
    The Application (client) ID of the Entra ID app registration.

.PARAMETER CertificateThumbprint
    The thumbprint of the certificate used for authentication.

.PARAMETER EntraRoleName
    The display name of the Entra role to synchronize active members from.

.PARAMETER OnPremGroupDN
    The Distinguished Name (DN) of the on-premises AD group to synchronize to.

.PARAMETER MaxChangesAllowed
    (Optional) The maximum number of membership changes allowed in a single run. Default is 10.

.PARAMETER LogFilePath
    (Optional) The file path where the JSON output will be saved. If not specified, the JSON output will be written to the console.

.EXAMPLE
    Sync-EntraRoleActiveMembersToOnPremADGroup `
        -TenantId "your-tenant-id" `
        -ClientId "your-client-id" `
        -CertificateThumbprint "your-cert-thumbprint" `
        -EntraRoleName "Your Custom Role Name" `
        -OnPremGroupDN "CN=YourOnPremGroup,OU=Groups,DC=yourdomain,DC=com" `
        -MaxChangesAllowed 5 `
        -LogFilePath "C:\Logs\RoleSyncLog.json" `
        -WhatIf

.NOTES
    - Ensure that the Entra ID application has the `RoleManagement.Read.Directory` and `Directory.Read.All` application permissions granted with admin consent.
    - The certificate must be installed in the local machine's certificate store and associated with the Entra ID application.
    - The account executing the script must have the necessary permissions to modify the on-premises AD group.
    - Requires PowerShell 5.1 or later and the following modules:
        - Microsoft.Graph.Authentication
        - Microsoft.Graph.Identity.Governance
        - Microsoft.Graph.Users
        - ActiveDirectory (Included with RSAT on Windows)
#>

function Sync-EntraRoleActiveMembersToOnPremADGroup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $true)]
        [string]$EntraRoleName,

        [Parameter(Mandatory = $true)]
        [string]$OnPremGroupDN,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [int]$MaxChangesAllowed = 10,

        [Parameter(Mandatory = $false)]
        [string]$LogFilePath
    )

    # Initialize variables
    $errors = New-Object System.Collections.ArrayList
    $warnings = New-Object System.Collections.ArrayList
    $jsonObject = [ordered]@{
        Parameters = [ordered]@{
            TenantId          = $TenantId
            ClientId          = $ClientId
            EntraRoleName     = $EntraRoleName
            OnPremGroupDN     = $OnPremGroupDN
            MaxChangesAllowed = $MaxChangesAllowed
            LogFilePath       = $LogFilePath
            Timestamp         = (Get-Date).ToString("o")
        }
        Errors     = $errors
        Warnings   = $warnings
    }

    # Function to output the JSON result
    function Output-JsonResult {
        param (
            [Hashtable]$Data
        )

        $jsonOutput = $Data | ConvertTo-Json -Depth 10

        if ($PSBoundParameters.ContainsKey('LogFilePath') -and -not [string]::IsNullOrWhiteSpace($LogFilePath)) {
            try {
                $jsonOutput | Out-File -FilePath $LogFilePath -Encoding UTF8 -Force
            }
            catch {
                [void]$warnings.Add("Failed to write JSON output to file: $_")
                $jsonOutput
            }
        }
        else {
            # Output to console if no logfile is specified or if writing to logfile failed
            $jsonOutput
        }
    }

    # Prevent management of built-in groups
    if ($OnPremGroupDN -like "*Builtin*") {
        [void]$errors.Add("Built-in groups cannot be managed.")
        Output-JsonResult -Data $jsonObject
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
    $onPremGroupName = ($OnPremGroupDN -split ",")[0] -replace "^CN=", ""
    if ($forbiddenGroups -contains $onPremGroupName) {
        [void]$errors.Add("The specified group '$onPremGroupName' cannot be managed.")
        Output-JsonResult -Data $jsonObject
        return
    }

    # Import required modules
    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        [void]$errors.Add("Failed to import required modules: $_")
        Output-JsonResult -Data $jsonObject
        return
    }

    # Function Definitions

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
                [void]$errors.Add("Certificate with thumbprint '$CertificateThumbprint' not found in LocalMachine\My store.")
                return $false
            }

            # Connect to Microsoft Graph with required scopes for role management
            Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -Certificate $cert -ErrorAction Stop

            return $true
        }
        catch {
            [void]$errors.Add("Failed to connect to Microsoft Graph: $_")
            return $false
        }
    }

    # Function to retrieve active and eligible members of a specified Entra role
    function Get-EntraRoleMembers {
        param (
            [string]$RoleName
        )

        try {
            # Retrieve the role definition
            $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$RoleName'"

            # Check if the role was found
            if ($null -eq $roleDefinition) {
                [void]$errors.Add("Role with display name '$RoleName' not found.")
                return $null
            }

            $roleDefinitionId = $roleDefinition.Id

            # Get eligible assignments for the specific role
            $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance `
                -Filter "roleDefinitionId eq '$roleDefinitionId'" -ExpandProperty "*" -All

            # Filter assignments to only include users
            $userEligibleAssignments = $eligibleAssignments | Where-Object {
                $_.Principal.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.user"
            }

            # Get the active assignments for the role
            $activeAssignments = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance `
                -Filter "roleDefinitionId eq '$roleDefinitionId'" -ExpandProperty "*" -All

            # Filter assignments to only include users
            $userActiveAssignments = $activeAssignments | Where-Object {
                $_.Principal.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.user"
            }

            # Process eligible user assignments
            $eligibleEntraUserData = $userEligibleAssignments | ForEach-Object {
                [pscustomobject]@{
                    PrincipalId       = $_.Principal.Id
                    DisplayName       = $_.Principal.AdditionalProperties.displayName
                    UserPrincipalName = $_.Principal.AdditionalProperties.userPrincipalName
                    StartDateTime     = $_.StartDateTime
                    EndDateTime       = $_.EndDateTime
                    MemberType        = $_.MemberType
                    RoleName          = $_.RoleDefinition.DisplayName
                    RoleID            = $_.RoleDefinition.Id
                    Status            = "Eligible"
                }
            }

            # Process active user assignments
            $activeEntraUserData = $userActiveAssignments | ForEach-Object {
                [pscustomobject]@{
                    PrincipalId       = $_.Principal.Id
                    DisplayName       = $_.Principal.AdditionalProperties.displayName
                    UserPrincipalName = $_.Principal.AdditionalProperties.userPrincipalName
                    AssignmentType    = $_.AssignmentType
                    StartDateTime     = $_.StartDateTime
                    EndDateTime       = $_.EndDateTime
                    MemberType        = $_.MemberType
                    RoleName          = $_.RoleDefinition.DisplayName
                    RoleID            = $_.RoleDefinition.Id
                    Status            = "Active"
                }
            }

            # Return both lists as a single object with two properties
            return @{
                EligibleUsers = $eligibleEntraUserData
                ActiveUsers   = $activeEntraUserData
            }
        }
        catch {
            [void]$errors.Add("An error occurred in Get-EntraRoleMembers: $_")
            return $null
        }
    }

    # Function to retrieve members from an on-premises AD group
    function Get-OnPremAdGroupMembers {
        param (
            [string]$GroupDN
        )

        try {
            # Retrieve all user members recursively
            $members = Get-ADGroupMember -Identity $GroupDN -Recursive -ErrorAction Stop | Where-Object {
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
            [void]$errors.Add("Error fetching on-premises AD group members: $_")
            return $null
        }
    }

    # Function to Update on-premises AD group members based on Entra role active members
    function Update-OnPremAdGroup {
        param (
            [string[]]$entraUPNs,
            [string[]]$onPremMembers,
            [string]$onPremGroupDN
        )

        # Convert Entra ID UPNs to on-prem UPNs
        $entraActiveOnPremUPNs = New-Object System.Collections.ArrayList
        foreach ($upn in $entraUPNs) {
            try {
                # Fetch user details from Microsoft Graph
                $onPremUPN = (Get-MgUser -UserId $upn -Property "onPremisesUserPrincipalName").onPremisesUserPrincipalName

                if (-not [string]::IsNullOrWhiteSpace($onPremUPN)) {
                    [void]$entraActiveOnPremUPNs.Add($onPremUPN)
                }
                else {
                    [void]$warnings.Add("On-Prem UPN is empty for cloud UPN: $upn")
                }
            }
            catch {
                [void]$warnings.Add("Failed to retrieve on-prem UPN for '$upn'. Error: $_")
            }
        }

        # Determine members to add (in Entra active roles but not in On-Prem AD group)
        $membersToAdd = $entraActiveOnPremUPNs | Where-Object { $_ -notin $onPremMembers }

        # Determine members to remove (in On-Prem AD group but not in Entra active roles)
        $membersToRemove = $onPremMembers | Where-Object { $_ -notin $entraActiveOnPremUPNs }

        # Initialize change counter
        $changeCount = 0

        # Initialize arrays to track successful additions, removals, and failures
        $successfulAdds = New-Object System.Collections.ArrayList
        $successfulRemoves = New-Object System.Collections.ArrayList
        $failedAdds = New-Object System.Collections.ArrayList
        $failedRemoves = New-Object System.Collections.ArrayList

        # Add new members
        foreach ($userUPN in $membersToAdd) {
            if ($changeCount -ge $MaxChangesAllowed) {
                [void]$warnings.Add("Maximum changes reached ($MaxChangesAllowed). Stopping further additions.")
                break
            }
            if ($PSCmdlet.ShouldProcess("Add $userUPN to group $onPremGroupDN")) {
                try {
                    $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$userUPN'" -ErrorAction Stop
                    Add-ADGroupMember -Identity $onPremGroupDN -Members $adUser -ErrorAction Stop
                    [void]$successfulAdds.Add($userUPN)
                    $changeCount++
                }
                catch {
                    $failedAdd = @{
                        UserPrincipalName = $userUPN
                        ErrorMessage      = $_.Exception.Message
                    }
                    [void]$failedAdds.Add($failedAdd)
                    [void]$warnings.Add("Failed to add '$userUPN' to on-prem AD group '$onPremGroupDN'. Error: $_")
                }
            }
        }

        # Remove old members
        foreach ($userUPN in $membersToRemove) {
            if ($changeCount -ge $MaxChangesAllowed) {
                [void]$warnings.Add("Maximum changes reached ($MaxChangesAllowed). Stopping further removals.")
                break
            }
            if ($PSCmdlet.ShouldProcess("Remove $userUPN from group $onPremGroupDN")) {
                try {
                    $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$userUPN'" -ErrorAction Stop
                    Remove-ADGroupMember -Identity $onPremGroupDN -Members $adUser -Confirm:$false -ErrorAction Stop
                    [void]$successfulRemoves.Add($userUPN)
                    $changeCount++
                }
                catch {
                    $failedRemove = @{
                        UserPrincipalName = $userUPN
                        ErrorMessage      = $_.Exception.Message
                    }
                    [void]$failedRemoves.Add($failedRemove)
                    [void]$warnings.Add("Failed to remove '$userUPN' from on-prem AD group '$onPremGroupDN'. Error: $_")
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

    # Main Execution Flow
    try {
        # Step 1: Connect to Microsoft Graph
        $graphConnected = Connect-MicrosoftGraphCert -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint

        if (-not $graphConnected) {
            Output-JsonResult -Data $jsonObject
            return
        }

        # Step 2: Extract members from Entra role and On-Premises AD
        $entraRoleMembers = Get-EntraRoleMembers -RoleName $EntraRoleName
        if ($null -eq $entraRoleMembers) {
            Output-JsonResult -Data $jsonObject
            return
        }

        $entraEligibleMembers = $entraRoleMembers['EligibleUsers']
        $entraActiveMembers = $entraRoleMembers['ActiveUsers']
        $entraActiveUPNs = $entraActiveMembers.UserPrincipalName
        $onPremGroupMembersBeforeSync = Get-OnPremAdGroupMembers -GroupDN $OnPremGroupDN

        # Update JSON object with retrieved data
        $jsonObject['EntraActiveMembers'] = $entraActiveMembers
        $jsonObject['EntraEligibleMembers'] = $entraEligibleMembers
        $jsonObject['OnPremGroupMembersBeforeSync'] = $onPremGroupMembersBeforeSync

        # Step 3: Update On-Premises AD Group
        $reconciliationResult = Update-OnPremAdGroup -entraUPNs $entraActiveUPNs -onPremMembers $onPremGroupMembersBeforeSync -onPremGroupDN $OnPremGroupDN

        # Step 4: Get on-prem group members after synchronization
        $onPremGroupMembersAfterSync = Get-OnPremAdGroupMembers -GroupDN $OnPremGroupDN

        # Step 5: Update JSON object with reconciliation results
        $jsonObject['MembersAddedToOnPremGroup'] = $reconciliationResult.AddedMembers
        $jsonObject['MembersRemovedFromOnPremGroup'] = $reconciliationResult.RemovedMembers
        $jsonObject['MembersFailedToAdd'] = $reconciliationResult.FailedAdds
        $jsonObject['MembersFailedToRemove'] = $reconciliationResult.FailedRemoves
        $jsonObject['OnPremGroupMembersAfterSync'] = $onPremGroupMembersAfterSync
        $jsonObject['TotalChanges'] = $reconciliationResult.AddedMembers.Count + $reconciliationResult.RemovedMembers.Count
    }
    catch {
        [void]$errors.Add("An error occurred during synchronization: $_")
    }
    finally {
        # Disconnect from Microsoft Graph
        Disconnect-MgGraph | Out-Null

        # Output the JSON result
        Output-JsonResult -Data $jsonObject
    }
}
