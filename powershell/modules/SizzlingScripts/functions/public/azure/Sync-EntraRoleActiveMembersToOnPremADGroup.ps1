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

.PARAMETER LogFilePath
    (Optional) The file path where the JSON output will be saved. If not specified, the JSON output will be written to the console.

.EXAMPLE
    Sync-EntraRoleActiveMembersToOnPremADGroup `
        -TenantId "your-tenant-id" `
        -ClientId "your-client-id" `
        -CertificateThumbprint "your-cert-thumbprint" `
        -EntraRoleName "Your Custom Role Name" `
        -OnPremGroupDN "CN=YourOnPremGroup,OU=Groups,DC=yourdomain,DC=com" `
        -LogFilePath "C:\Logs\RoleSyncLog.json"

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
    [CmdletBinding()]
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
    $onPremGroupName = ($OnPremGroupDN -split ",")[0] -replace "CN=", ""
    if ($forbiddenGroups -contains $onPremGroupName) {
        Write-Error "The specified group '$onPremGroupName' cannot be managed."
        return
    }

    # Import required modules
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
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

            # Connect to Microsoft Graph with required scopes for role management
            Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -NoWelcome

        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph: $_"
            throw
        }
    }

    # Function to retrieve active members of a specified Entra role
    function Get-EntraRoleMembers {
        param (
            [string]$RoleName
        )

        try {
            # Retrieve the role definition
            $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$RoleName'"

            # Check if the role was found
            if ($null -eq $roleDefinition) {
                Write-Error "Role with display name '$RoleName' not found."
                return $null
            }

            $RoleDefinitionId = $roleDefinition.Id

            # Get eligible assignments for the specific role
            $EligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance `
                -Filter "roleDefinitionId eq '$RoleDefinitionId'" -ExpandProperty "*"

            # Filter assignments to only include users
            $UserEligibleAssignments = $EligibleAssignments | Where-Object {
                $_.Principal.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.user"
            }

            # Get the active assignments for the role
            $ActiveAssignments = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance `
                -Filter "roleDefinitionId eq '$RoleDefinitionId'" -ExpandProperty "*"

            # Filter assignments to only include users
            $UserActiveAssignments = $ActiveAssignments | Where-Object {
                $_.Principal.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.user"
            }

            # Process eligible user assignments
            $EligibleEntraUserData = $UserEligibleAssignments | ForEach-Object {
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
            $ActiveEntraUserData = $UserActiveAssignments | ForEach-Object {
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
                EligibleUsers = $EligibleEntraUserData
                ActiveUsers   = $ActiveEntraUserData
            }
        }
        catch {
            Write-Error "An error occurred: $_"
            return $null
        }
    }


    # Function to retrieve members from an on-premises AD group
    function Get-OnPremADGroupMembers {
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
            Write-Error "Error fetching on-premises AD group members: $_"
            throw
        }
    }

    # Function to Update on-premises AD group members based on Entra role active members
    function Update-OnPremADGroup {
        param (
            $entraUPNs,
            $OnPremMembers,
            $OnPremGroupDN
        )

        # Convert Entra ID UPNs to on-prem UPNs
        $entraActiveRoleMemberOnPremUPNs = New-Object System.Collections.ArrayList
        foreach ($upn in $entraUPNs) {
            try {
                # Fetch user details from Microsoft Graph
                $onPremUPN = (Get-MgUser -UserId $upn -Property "onPremisesUserPrincipalName" -ErrorAction Stop).onPremisesUserPrincipalName
                $entraActiveRoleMemberOnPremUPNs.Add($onPremUPN) | Out-Null
            }
            catch {
                Write-Warning "Failed to retrieve on-prem UPN: $upn. Error: $_"
            }
        }

        # Determine members to add (in Entra active roles but not in On-Prem AD group)
        $membersToAdd = $entraActiveRoleMemberOnPremUPNs | Where-Object { $_ -notin $OnPremMembers }

        # Determine members to remove (in On-Prem AD group but not in Entra active roles)
        $membersToRemove = $OnPremMembers | Where-Object { $_ -notin $entraActiveRoleMemberOnPremUPNs }

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

        # Step 2: Extract members from Entra role and On-Premises AD
        $entraRoleMembers = Get-EntraRoleMembers -RoleName $EntraRoleName
        $entraEligibleRoleMembers = $entraRoleMembers['EligibleUsers']
        $entraActiveRoleMembers = $entraRoleMembers['ActiveUsers']
        $entraActiveRoleMemberUPNs = $entraActiveRoleMembers.UserPrincipalName
        $onPremGroupMembers = Get-OnPremADGroupMembers -GroupDN $OnPremGroupDN

        # Step 3: Update On-Premises AD Group
        $reconciliationResult = Update-OnPremADGroup -entraUPNs $entraActiveRoleMemberUPNs -OnPremMembers $onPremGroupMembers -OnPremGroupDN $OnPremGroupDN

        # Step 4: Prepare JSON Tracking Object
        $timestamp = (Get-Date).ToString("o")  # ISO 8601 format

        $jsonObject = @{
            OnPremGroupDN                 = $OnPremGroupDN
            EntraRoleName                 = $EntraRoleName
            EntraActiveRoleMembers        = $entraActiveRoleMembers
            EntraEligibleRoleMembers      = $entraEligibleRoleMembers
            OnPremGroupMembersBeforeSync  = $onPremGroupMembers
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
        Disconnect-MgGraph | Out-Null
        Write-Output "Disconnected from Microsoft Graph."
    }
}
