<#
.SYNOPSIS
Filters rows in CSV files based on a user-specified PowerShell script block and outputs them to a single CSV file.

.DESCRIPTION
This function reads all CSV files in a given directory and filters rows based on a user-supplied PowerShell script block or expression. All filtered rows are saved in a single output CSV file.

.PARAMETER csvDir
The directory where the CSV files are located.

.PARAMETER whereExpression
The PowerShell script block or expression to evaluate for each row.

.PARAMETER outputPath
The directory where the single output CSV file will be saved.

.PARAMETER IncludeHeaders
Boolean switch to indicate whether or not to include headers in the output file.

.PARAMETER IncludeTimestamp
Boolean switch to indicate whether or not to include the file's last modified timestamp in the output file.

.EXAMPLE
Get-FilteredCSVData -csvDir "C:\Path\To\CSVFiles" -whereExpression {(($_.ActionsTaken -ne 'None') -and ($_.DNSObject -ne 'Not found'))} -outputPath "C:\Path\To\Output\file.csv" -IncludeHeaders -IncludeTimestamp

.NOTES
#>

function Get-FilteredCSVData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$csvDir,

        [Parameter(Mandatory = $true)]
        [string]$whereExpression,

        [Parameter(Mandatory = $true)]
        [string]$outputPath,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeHeaders,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeTimestamp
    )

    # Create an empty array to hold all filtered rows
    $allFilteredRows = @()

    # Verify the source directory exists
    if (Test-Path $csvDir -PathType Container) {
        $csvFiles = Get-ChildItem -Path $csvDir -Filter *.csv
        if ($csvFiles.Count -eq 0) {
            Write-Output "No CSV files found in the directory."
            return
        }

        # Extract headers from the first CSV file if IncludeHeaders switch is on
        if ($IncludeHeaders) {
            $headers = Get-Content $csvFiles[0].FullName -First 1
            if ($IncludeTimestamp) {
                $headers += ",Timestamp"
            }
            $headers += ",FileName"
        }

        # Iterate through each CSV file in the directory
        $csvFiles | ForEach-Object {
            $csvPath = $_.FullName
            $lastModified = $_.LastWriteTime
            $fileName = $_.Name

            # Read the CSV file into a variable
            $csvData = Import-Csv -Path $csvPath

            # Generate the script block for the Where-Object cmdlet
            $scriptBlock = [scriptblock]::Create($whereExpression)

            # Filter the rows based on the user-supplied script block
            $filteredRows = $csvData | Where-Object $scriptBlock

            # Add timestamp and filename if needed
            $filteredRows | ForEach-Object {
                if ($IncludeTimestamp) {
                    Add-Member -InputObject $_ -MemberType NoteProperty -Name "Timestamp" -Value $lastModified
                }
                Add-Member -InputObject $_ -MemberType NoteProperty -Name "FileName" -Value $fileName

                $allFilteredRows += $_
            }
        }

        # Write all the filtered rows to a single CSV file
        if ($allFilteredRows.Count -gt 0) {
            if ($IncludeHeaders) {
                $headers | Set-Content -Path $outputPath
            }
            $allFilteredRows | Export-Csv -Path $outputPath -NoTypeInformation -Append
        }
    }
    else {
        Write-Output "Source directory does not exist."
    }
}