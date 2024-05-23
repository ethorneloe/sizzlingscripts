<# 
.SYNOPSIS
    Assigns specified app roles to a managed identity.

.DESCRIPTION
    This function assigns specified app roles to a managed identity. 
    It uses the Microsoft Graph PowerShell module to handle authentication and role assignment.

.PARAMETER TenantId
    The tenant ID where the managed identity resides.

.PARAMETER ManagedIdentityName
    The display name of the managed identity (either system-assigned or user-assigned).

.PARAMETER GraphApiRoles
    An array of app roles to assign to the managed identity.

.PARAMETER GraphApplicationId
    The application ID for Microsoft Graph (default is "00000003-0000-0000-c000-000000000000").

.EXAMPLE
    Set-GraphApiRolesForManagedIdentity -TenantId "a3186524-d3d5-4820-8cb5-9ad21badb14a" -ManagedIdentityName "myUserMSI" -GraphApiRoles "Directory.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.ReadWrite.All", "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

.NOTES
    Ensure you have the necessary permissions to assign roles to the managed identity.
    This script installs and imports the Microsoft Graph PowerShell modules if they are not already installed.
#>

function Set-GraphApiRolesForManagedIdentity {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TenantId,

        [Parameter(Mandatory=$true)]
        [string]$ManagedIdentityName,

        [Parameter(Mandatory=$true)]
        [string[]]$GraphApiRoles,

        [string]$GraphApplicationId = "00000003-0000-0000-c000-000000000000" # Default Graph App ID, don't change this.
    )

    # Install the Microsoft Graph modules if not already installed
    $requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications")
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Install-Module -Name $module -Scope CurrentUser -Force
        }
    }

    # Import the necessary modules
    Import-Module Microsoft.Graph.Authentication
    Import-Module Microsoft.Graph.Applications

    # Connect to Microsoft Graph with appropriate scopes
    Connect-MgGraph -Scopes "Application.ReadWrite.All", "RoleManagement.ReadWrite.Directory" -TenantId $TenantId

    # Get the managed identity (MSI) using Microsoft Graph
    $ManagedIdentityServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq '$ManagedIdentityName'"
    
    # Get the Microsoft Graph service principal using Microsoft Graph
    $GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$GraphApplicationId'"

    # Filter the AppRoles based on the required GraphApiRoles
    $AppRolesToAssign = $GraphServicePrincipal.AppRoles | Where-Object {($_.Value -in $GraphApiRoles) -and ($_.AllowedMemberTypes -contains "Application")}

    foreach ($AppRole in $AppRolesToAssign) {
        try {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityServicePrincipal.Id -PrincipalId $ManagedIdentityServicePrincipal.Id -ResourceId $GraphServicePrincipal.Id -AppRoleId $AppRole.Id -Verbose
        } catch {
            throw "Unable to assign $($AppRole.Value) to $ManagedIdentityName - Error: $_"
        }
    }
}