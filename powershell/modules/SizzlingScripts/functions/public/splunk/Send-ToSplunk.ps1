<#
.SYNOPSIS
Sends data to Splunk.

.DESCRIPTION
The Send-ToSplunk function submits data to Splunk using the provided API key and server endpoint.

.PARAMETER Data
A string (in JSON or CSV format) containing data to be sent to Splunk.

.PARAMETER File
A file (in JSON or CSV format) containing data to be sent to Splunk.  If in JSON format, it is assumed that the file has the following format where a field name
contains an array of values representing each object you will send to Splunk with consistent property names.

{
    "FieldName":  [
                 {
                    "Property1":  "value1",
                    "Property2":  "value2"
                 },
                 {
                    "Property1":  "value1",
                    "Property2":  "value2"
                 }
              ]
}

.PARAMETER SplunkServer
The endpoint of the Splunk server.

.PARAMETER ApiKey
The API key for Splunk submission.

.PARAMETER SourceType
The source type for Splunk.

.PARAMETER Source
The source for Splunk.

.PARAMETER Index
The index for Splunk.

.PARAMETER Format
The format of Data. Can be "json" or "csv".

.PARAMETER TimestampField
Use this if your Json or csv data has a field with a timestamp and you want that to be used as the timestamp in Splunk, rather than the time when the script
executes.

.EXAMPLE
Send-ToSplunk -Data $data -SplunkServer "http://splunk-server-endpoint" -ApiKey "Your-API-Key" -SourceType "type_here" -Source "source_here" -Index "index_here" -Format "json" -TimestampField "dateTime"

Send-ToSplunk -File $file -SplunkServer "http://splunk-server-endpoint" -ApiKey "Your-API-Key" -SourceType "type_here" -Source "source_here" -Index "index_here" -Format "json"

Send-ToSplunk -File 'C:\path\filename.json' -SplunkServer "http://splunk-server-endpoint" -ApiKey "Your-API-Key" -SourceType "type_here" -Source "source_here" -Index "index_here" -Format "json"

.NOTES
#>

function Send-ToSplunk {
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Data')]
        [string]$Data,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [ValidateScript({ Test-Path $_ -PathType Leaf })] # ensures the path points to a file
        [string]$File,

        [Parameter(Mandatory = $true)]
        [string]$SplunkServer,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$SourceType,

        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Index,

        [Parameter(Mandatory = $true)]
        [ValidateSet("json", "csv")]
        [string]$Format,

        [Parameter(Mandatory = $false)]
        [string]$TimestampField = $null
    )

    $Headers = @{
        Authorization = $ApiKey
    }

    if ($PSCmdlet.ParameterSetName -eq 'File') {
        $Data = Get-Content $File -Raw
    }

    if ($Format -eq 'json') {
        try {
            [pscustomobject]$Data = $Data | ConvertFrom-Json
            if ($null -eq $Data) {
                write-output "Received null data object for $SourceType"
                return
            }
            $PropertyName = $Data | Get-Member -MemberType Properties | select-object -First 1 | Select-Object -ExpandProperty Name
            $Data = $Data.$PropertyName
        }
        catch {
            Write-Error ("Provided data is not valid JSON and could not be converted for processing. Error: " + $($_.Exception.Message))
            return -1
        }
    }
    elseif ($Format -eq 'csv') {
        [pscustomobject]$Data = $Data | ConvertFrom-Csv
    }

    $Data | ForEach-Object {

        $MaxRetries = 5
        $RetryCount = 0
        $Delay = 2

        do {
            try {
                # If the timestamp field was not specified, the timestamp value is the epoch time up to now
                # else it is the time up to the timestamp supplied by the field.
                if ([string]::IsNullOrEmpty($TimestampField)) {
                    $TimestampValue = Convert-DateToEpoch -ConvertToUTC

                }
                else {
                    $TimestampValue = Convert-DateToEpoch -Time $_.$TimestampField -ConvertToUTC
                }

                $Body = @{
                    host       = $env:computername
                    time       = [int64]$TimestampValue
                    sourcetype = $SourceType
                    source     = $Source
                    index      = $Index
                    event      = $_
                } | ConvertTo-Json -Compress -Depth 99

                
                $Headers
                $Body
                $Response = Invoke-RestMethod -Uri $SplunkServer -Method Post -Headers $Headers -Body $Body -ErrorAction Stop
                break
            }
            catch {

                # Check if the exception is a WebException to handle connectivity issues
                if ($_.Exception -is [System.Net.WebException]) {
                    if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::NameResolutionFailure) {
                        Write-Error "The server $SplunkServer could not be resolved. It may not exist or there might be a DNS issue."
                        return -1
                    }
                    elseif ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::ConnectFailure) {
                        Write-Error "Unable to connect to the server $SplunkServer. It might be down or there might be a network issue."
                        return -1
                    }
                }

                # If there was an HTTP response (i.e., the server was reached but returned an error)
                if ($_.Exception.Response) {
                    $StatusCode = [int]$_.Exception.Response.StatusCode

                    # Check for specific status codes
                    if ($StatusCode -eq 400) {
                        # Bad Request
                        Write-Error ("Bad Request. Check the format of your http post headers and body. Also make sure the index you are using exists, along with any other config on the Splunk side. Error: " + $($_.Exception.Message))
                        return -1
                    }
                    elseif ($StatusCode -eq 401) {
                        # Not Authorized
                        Write-Error ("Authorization failed. Please check your API key. Error: " + $($_.Exception.Message))
                        return -1
                    }
                    elseif ($StatusCode -eq 403) {
                        # Forbidden
                        Write-Error ("Access forbidden. The provided account or API key may not have the necessary permissions. Error: " + $($_.Exception.Message))
                        return -1
                    }
                    else {
                        Write-Error ("An error occurred: " + $($_.Exception.Message) + "Attempt $RetryCount out of $MaxRetries")
                        $RetryCount++
                        Start-Sleep -Seconds ($Delay * $RetryCount)  # Exponential backoff
                    }
                }
                else {
                    # If there's no HTTP response and it's not a WebException, it's another type of error.
                    Write-Error ("An error occurred: " + $($_.Exception.Message))
                    return -1
                }
            }
        } while ($RetryCount -lt $MaxRetries)

        if ($RetryCount -eq $MaxRetries) {
            Write-Error ("Maximum retries reached while trying to send data to Splunk server. Response: $Response")
        }
    }
}
