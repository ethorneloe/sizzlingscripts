<#
.SYNOPSIS
Updates and synchronizes Microsoft Graph PowerShell SDK modules across PowerShell 7 and PowerShell 5.1 environments.

.DESCRIPTION
The Update-GraphPowerShellSDK function manages the installation, updating, and synchronization of specified Microsoft Graph modules across different PowerShell environments. It is designed to ensure that only specified modules are maintained across systems, removing unmanaged modules, installing missing ones, and ensuring consistency between PowerShell 7 and PowerShell 5.1.

.PARAMETER ManagedGraphModules
Specifies the Microsoft Graph modules to manage. This includes installation, updates, and removal of modules not listed.

.PARAMETER VersionToDeploy
Specifies the version of the modules to deploy. The default is 'latest', which installs the most recent version available.

.PARAMETER RemoveExistingVersions
Determines whether to remove existing versions of Graph modules before installing new ones. Defaults to $false.

.PARAMETER ReportingOnly
Runs the function in a report-only mode where no changes are made, only the planned actions are reported. Defaults to $true.

.PARAMETER PowerShell51ModulePathsToClear
Specifies the paths where PowerShell 5.1 modules are located. Modules in these paths will be cleared of any Graph modules before updating.

.PARAMETER PowerShell51GraphModuleDestination
Defines the destination path in the PowerShell 5.1 environment where the updated Graph modules from PowerShell 7 will be copied.

.EXAMPLE
$params = @"
{
    "ManagedGraphModules": [
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications",
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Microsoft.Graph.Identity.SignIns",
        "Microsoft.Graph.Reports",
        "Microsoft.Graph.Users.Actions"
    ],
    "VersionToDeploy": "latest",
    "RemoveExistingVersions": true,
    "ReportingOnly": false
}
"@ | ConvertFrom-Json -AsHashtable

Update-GraphPowerShellSDK @params

This example updates the specified Graph modules across both PowerShell 7 and PowerShell 5.1 environments. It removes existing versions of the modules before installing the latest ones and applies the changes rather than just reporting them.

.NOTES
Administrative privileges are required to install, update, and remove modules from the AllUsers scope. Ensure that PowerShellGet and PSResource modules are up-to-date and properly configured before running this script.

Should be run in pwsh to leverage the newer PowerShellGet capabilities
#>

function Update-GraphPowerShellSDK {

    param (
        [Parameter(Mandatory = $true)]
        [object[]]$ManagedGraphModules,

        [string]$VersionToDeploy = 'latest',

        [boolean]$RemoveExistingVersions = $false,

        [boolean]$ReportingOnly = $true,

        [object[]]$PowerShell51ModulePathsToClear = @("C:\Program Files\WindowsPowerShell\Modules", "C:\WINDOWS\System32\WindowsPowerShell\v1.0\Modules"),

        [string]$PowerShell51GraphModuleDestination = "C:\Program Files\WindowsPowerShell\Modules"
    )
    # Helper Function definitions

    # Input validation on the Graph Module Names supplied and the version
    function Test-ManagedGraphModules {
    
        if ($null -eq $ManagedGraphModules -or $ManagedGraphModules.Count -eq 0) {
            throw "The ManagedGraphModules parameter cannot be null or empty."
        }
    
        foreach ($module in $ManagedGraphModules) {
            # Find the module with all versions available in the repository
            try {
                $availableModules = Find-PSResource -Name $module -Version *
                if (-not $availableModules) {
                    throw "'$module' is not a valid module name, or PSGallery could not be reached."
                }
            }
            catch {
                throw "'$module' specified in ManagedGraphModules parameter is not a valid module name, or PSGallery could not be reached. Error - $_"
            }
    
            $availableVersions = $availableModules | Select-Object -ExpandProperty Version
    
            # Check if any of the desired versions is not available
            if ($VersionToDeploy.toLower() -eq 'latest') {
                continue 
            }
            elseif (-not ($VersionToDeploy -in $availableVersions)) {
                throw "Version $VersionToDeploy of module $module is not available in the repository."
            }
        }
    }
    
    # Installs the required managed modules
    function Install-ManagedGraphModules {
        param (
            [Parameter(Mandatory = $true)]
            $toInstall
        )
        foreach ($module in $toInstall) {
            if ($VersionToDeploy -ne 'latest') {
                Install-PSResource -Scope AllUsers -Name $module -Confirm:$false -Quiet -TrustRepository -ErrorAction Stop -Version $VersionToDeploy   
                Write-Output "Installed $module version $VersionToDeploy"
            }
            else {
                Install-PSResource -Scope AllUsers -Name $module -Confirm:$false -Quiet -TrustRepository -ErrorAction Stop
                Write-Output "Installed $module using latest available version"
            }
            
        }
    }

    # Remove graph modules installed that are not part of the list of managed modules
    function Remove-UnmanagedGraphModules {
        param (
            [Parameter(Mandatory = $true)]
            $toRemove
        )
        $containsAuthModule = $false
        foreach ($module in $toRemove) {
            if ($module -eq "Microsoft.Graph.Authentication") {
                $containsAuthModule = $true
                continue 
            } 
            else {
                Uninstall-PSResource -Scope AllUsers -Name $module -Confirm:$false -ErrorAction Stop -Version *
                Write-Output "Removed module: $module"
            }
        }
        if ($containsAuthModule) {
            Uninstall-PSResource -Scope AllUsers -Name 'Microsoft.Graph.Authentication' -Confirm:$false -ErrorAction Stop -Version *
            Write-Output "Removed module: Microsoft.Graph.Authentication"
        }
    }


    # Update installed managed modules in the PowerShell 7 AllUsers location
    function Update-ManagedGraphModules {
        param (
            [Parameter(Mandatory = $true)]
            $toUpdate
        )
        foreach ($module in $toUpdate) {
            if ($VersionToDeploy -ne 'latest') {
                Update-PSResource -Scope AllUsers -Name $module -Confirm:$false -Quiet -TrustRepository -ErrorAction Stop -Version $VersionToDeploy
                Write-Output "Updated $module to version $VersionToDeploy"
            }
            else {
                Update-PSResource -Scope AllUsers -Name $module -Confirm:$false -Quiet -TrustRepository
                Write-Output "Updated $module to latest available version"
            }
        
        }
    }

    # Remove all graph modules from user profile locations. This ensures any testing run in the context of a profile uses the AllUsers modules
    # as the service account does
    function Remove-UserProfileGraphModules {
        $profiles = Get-ChildItem -Path "C:\Users" -Directory | Sort-Object Name

        # Counting the profiles based on the sorted list so that this can be checked without placing named folders into logs
        $count = 0
        foreach ($profile in $profiles) {
            $modulePaths = @(
                "$($profile.FullName)\Documents\PowerShell\Modules",
                "$($profile.FullName)\Documents\WindowsPowerShell\Modules"
            )
            foreach ($path in $modulePaths) {
                if (Test-Path $path) {
                    $FoldersToRemove = Get-ChildItem -Path $path -Filter "Microsoft.Graph*" -Directory -ErrorAction SilentlyContinue
                    if ($FoldersToRemove.Count -gt 0) {
                        try {
                            $FoldersToRemove | Remove-Item -Recurse -Confirm:$false -Force -ErrorAction Stop
                            Write-Output "Cleared graph modules from user profile $count"
                        }
                        catch {
                            throw "Unable to clear graph modules in user profile $count"
                        }
                    }
                }
            }
            $count++
        }
    }

    # Remove graph modules from the AllUsers PowerShell 5.1 location
    function Remove-AllUsersPS51GraphModules {
        foreach ($path in $PowerShell51ModulePathsToClear) {
            # Check if the path exists before trying to remove items
            if (Test-Path $path) {
                $foldersToRemove = Get-ChildItem -Path $path -Filter "Microsoft.Graph*" -Directory -ErrorAction SilentlyContinue
                if ($foldersToRemove.Count -gt 0) {
                    try {
                        $foldersToRemove | Remove-Item -Recurse -Confirm:$false -Force -ErrorAction Stop
                        Write-Output "Cleared graph modules at $path"
                    }
                    catch {
                        throw "Unable to clear graph modules at $path - $_"
                    }
                }
            }
            else {
                throw "Path does not exist: $path"
            }
        }
    }

    # Copies graph modules that have been installed and updated in the 7 AllUsers location to the 5.1 AllUsers location
    function Sync-GraphModulesFrom7To51 {
        $sourcePath = (Get-InstalledPsResource -Scope AllUsers | Where-Object { $_.Name -like "*Graph*" } | Select-Object -First 1).InstalledLocation

        if ([string]::IsNullOrEmpty($sourcePath)) {
            throw "No Graph Modules found in PowerShell 7 AllUsers scope"
        }

        $graphFoldersToCopy = Get-ChildItem -Path $sourcePath -Filter "Microsoft.Graph*" | Sort-Object Name
        $destinationPath = $PowerShell51GraphModuleDestination

        foreach ($folder in $graphFoldersToCopy) {
            try {
                Copy-Item -Path $folder.FullName -Destination $destinationPath -Recurse -Force
            }
            catch {
                throw "Unable to copy $($folder.FullName) - $_"
            }
        }

        $graphFoldersCopied = Get-ChildItem -Path $destinationPath -Filter "Microsoft.Graph*" | Sort-Object Name
        if ($null -ne (Compare-Object -ReferenceObject $graphFoldersToCopy -DifferenceObject $graphFoldersCopied -Property Name)) {
            Write-Error "Graph module deployment mismatch between PS7 and PS5.1"
            Write-Output "Source Path: $sourcePath"
            Write-Output ""
            Write-Output "Destination Path: $destinationPath"
            Write-Output ""
            Write-Output "Modules from Source:"
            $graphFoldersToCopy
            Write-Output ""
            Write-Output "Modules in Destination:"
            $graphFoldersCopied
        }
    }

    function Get-UserProfilesWithGraphModulesCount {
        $profiles = Get-ChildItem -Path "C:\Users" -Directory | Sort-Object Name  
        # Counting the profiles based on the sorted list so that this can be checked without placing named folders into logs
        $count = 0
        :outerLoop foreach ($profile in $profiles) {
            $modulePaths = @(
                "$($profile.FullName)\Documents\PowerShell\Modules",
                "$($profile.FullName)\Documents\WindowsPowerShell\Modules"
            )
            foreach ($path in $modulePaths) {
                if (Test-Path $path) {
                    $GraphModuleFolders = Get-ChildItem -Path $path -Filter "Microsoft.Graph*" -Directory -ErrorAction SilentlyContinue
                    if (($GraphModuleFolders | Measure-Object).Count -gt 0) {
                        $count++
                        continue outerLoop
                    }                    
                }
            }
        }
        return $count
    }

    # Get initial state of installed Modules
    $installedGraphModules = Get-InstalledPsResource -Scope AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "Microsoft.Graph*" } | Select-Object -ExpandProperty Name -Unique

    if (-not $installedGraphModules) {
        $installedGraphModules = @()
    }

    # Convert to sets for efficient comparison
    $installedSet = [System.Collections.Generic.HashSet[string]]$installedGraphModules
    $managedSet = [System.Collections.Generic.HashSet[string]]$managedGraphModules

    # Get latest version in the gallery
    $latestVersion = Find-PSResource -Name "Microsoft.Graph" | Select-Object -ExpandProperty Version

    # Calculate diffs. If we are removing existing versions then there is nothing to update, and the specified version will be installed.
    if (($RemoveExistingVersions)) {
        $toRemove = $installedGraphModules
        $toInstall = $managedGraphModules
    }
    else {
        $toRemove = $installedSet.Where({ -not $managedSet.Contains($_) })
        $toInstall = $managedSet.Where({ -not $installedSet.Contains($_) })

        $installedVersionObject = New-Object System.Version(Get-InstalledPsResource -Scope AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "Microsoft.Graph.Authentication" } | Select-Object -ExpandProperty Version)
        $latestVersionObject = New-Object System.Version($latestVersion)

        # Compare versions
        $result = $installedVersionObject.CompareTo($latestVersionObject)

        # If we are on a smaller version then we need to update
        if ($result -le 0) {
            $toUpdate = $managedSet.Where({ $installedSet.Contains($_) })
        }
    }


    # Check Input
    Test-ManagedGraphModules
    # Apply changes if not in reporting only mode
    if (-not $ReportingOnly) {
        Remove-UserProfileGraphModules
        Remove-AllUsersPS51GraphModules
        if ($toRemove) { Remove-UnmanagedGraphModules -toRemove $toRemove }
        if ($toInstall) { Install-ManagedGraphModules -toInstall $toInstall }
        if ($toUpdate) { Update-ManagedGraphModules -toUpdate $toUpdate }
        Sync-GraphModulesFrom7To51
    }

    # Set VersionToDeploy for better readability in output
    if ($VersionToDeploy.ToLower() -eq 'latest') {
        $VersionToDeploy = "latest($latestVersion)" 
    }

    Write-Output ""
    Write-Output "Desired Graph Module State:"
    Write-Output ""
    Write-Output "Version: $VersionToDeploy"
    Write-Output ""
    Write-Output "Modules:"
    Write-Output ""
    $ManagedGraphModules

    Write-Output ""
    Write-Output ""
    Write-Output "Deployed Graph Module State"
    Write-Output ""
    $UserProfilesWithGraphModulesCount = Get-UserProfilesWithGraphModulesCount
    Write-Output ""
    Write-Output "$UserProfilesWithGraphModulesCount user profiles have graph modules installed"
    Write-Output ""
    Write-Output "Get-InstalledPsResource(pwsh)"
    Write-Output ""
    Get-InstalledPsResource -Scope AllUsers | Where-Object { $_.Name -like "Microsoft.Graph*" } | Select-Object Name, Version
    Write-Output ""
    Write-Output "Get-Module(PowerShell 5.1 AllUsers Location)"
    Get-Module -ListAvailable | Where-Object { $_.path -like "$PowerShell51GraphModuleDestination\Microsoft.Graph*" }

    Write-Output ""
    if ($ReportingOnly) {
        Write-Output "Graph Modules that would be installed with version: $VersionToDeploy"
        $toInstall
        Write-Output ""
        Write-Output "Graph Modules already installed that would be updated to version: $VersionToDeploy"
        $toUpdate
        Write-Output ""
        Write-Output "Graph Modules that would be removed:"
        $toRemove
    }
    else {
        Write-Output "Graph Modules that were installed with version: $VersionToDeploy"
        $toInstall
        Write-Output ""
        Write-Output "Graph Modules already installed that were updated with version: $VersionToDeploy"
        $toUpdate
        Write-Output ""
        Write-Output "Graph Modules that were removed:"
        $toRemove
    }
}
