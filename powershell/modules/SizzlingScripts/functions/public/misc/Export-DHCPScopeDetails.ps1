<#
.SYNOPSIS
    Retrieves DHCP scope information, including reservations and leases, and exports the details to a CSV file.

.DESCRIPTION
    This PowerShell function retrieves the specified DHCP scope information, reservations, and leases based on the provided ScopeID or ScopeName.
    The output is a CSV file containing an overview of the scope, including the name, start and end IP addresses, lease duration, description,
    and scope options. The report also contains details about leases and reservations, including the IP addresses, names, and MAC addresses.

    Make sure to run this on a server that has the dhcp cmdlets available(RSAT Tools).

.PARAMETER DHCPServer
    The DHCP server's IP address or hostname.

.PARAMETER Scope
    The ScopeID or ScopeName to retrieve information from.

.PARAMETER ReportPath
    The path to save the generated CSV report.

.EXAMPLE
    Get-DHCPScopeDetails -DHCPServer "Your_DHCP_Server" -Scope "10.0.0.0" -ReportPath "C:\Reports\DHCPReport.csv"

    Retrieves DHCP scope information for the scope with ScopeID "10.0.0.0" on the specified DHCP server and exports the details to a CSV file at "C:\Reports\DHCPReport.csv".
#>
function Export-DHCPScopeDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DHCPServer,
        [Parameter(Mandatory = $true)]
        [string]$Scope,
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
    )

    # Find the scope by ScopeID or ScopeName
    $TargetScope = Get-DhcpServerv4Scope -ComputerName $DHCPServer | Where-Object { ($_.ScopeId -eq $Scope) -or ($_.Name -eq $Scope) }

    if ($null -eq $TargetScope) {
        Write-Error "Scope not found."
        return
    }

    # Get scope options
    $ScopeOptions = Get-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $TargetScope.ScopeId

    # Get reservations and leases
    $Reservations = Get-DhcpServerv4Reservation -ComputerName $DHCPServer -ScopeId $TargetScope.ScopeId
    $Leases = Get-DhcpServerv4Lease -ComputerName $DHCPServer -ScopeId $TargetScope.ScopeId

    # Create report data
    $ReportData = @()
    $ReportData += [PSCustomObject]@{
        Type          = 'Scope'
        Name          = $TargetScope.Name
        IPAddress     = ''
        MACAddress    = ''
        StartIP       = $TargetScope.StartRange
        EndIP         = $TargetScope.EndRange
        LeaseDuration = $TargetScope.LeaseDuration
        Description   = $TargetScope.Description
    }

    ForEach ($Option in $ScopeOptions) {
        $OptionValues = $Option.Value -join ', '
        $ReportData += [PSCustomObject]@{
            Type          = "Option $($Option.OptionId)"
            Name          = ''
            IPAddress     = ''
            MACAddress    = ''
            StartIP       = ''
            EndIP         = ''
            LeaseDuration = ''
            Description   = $OptionValues
        }
    }

    ForEach ($Reservation in $Reservations) {
        $ReportData += [PSCustomObject]@{
            Type          = 'Reservation'
            Name          = $Reservation.Name
            IPAddress     = $Reservation.IPAddress
            MACAddress    = $Reservation.ClientId
            StartIP       = ''
            EndIP         = ''
            LeaseDuration = ''
            Description   = ''
        }
    }

    ForEach ($Lease in $Leases) {
        $ReportData += [PSCustomObject]@{
            Type          = 'Lease'
            Name          = $Lease.HostName
            IPAddress     = $Lease.IPAddress
            MACAddress    = $Lease.ClientId
            StartIP       = ''
            EndIP         = ''
            LeaseDuration = ''
            Description   = ''
        }
    }

    # Export report data to CSV
    $ReportData | Export-Csv -Path $ReportPath -NoTypeInformation
    Write-Output "Report generated at $ReportPath"
}
