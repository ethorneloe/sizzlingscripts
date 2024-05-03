<#
.SYNOPSIS
Sends GitHub organization metrics to Splunk.

.DESCRIPTION
This function retrieves data from specified GitHub organization APIs and forwards it to Splunk for logging and analysis. It authenticates with GitHub using a provided GitHub App's private key, App ID, and Installation ID to generate an access token. This token is then used to authenticate API requests. The function supports multiple data sources (GitHub APIs) specified in the DataForSplunk hashtable.

.PARAMETER SplunkServer
The hostname or IP address of the Splunk server where the data will be sent.

.PARAMETER ApiKey
The API key used for authenticating with the Splunk server.

.PARAMETER Index
The Splunk index where the GitHub metrics will be stored.

.PARAMETER GitHubAppKey
The base64 encoded private key of the GitHub App, used to authenticate with GitHub and retrieve an access token.

.PARAMETER InstallationId
The installation ID of the GitHub App. This ID is specific to the organization where the App is installed.

.PARAMETER AppId
The ID of the GitHub App. Used along with the private key to authenticate and generate an access token.

.PARAMETER OrgName
The name of the GitHub Organisation.

.PARAMETER DataForSplunk
A hashtable where keys are descriptive names of the GitHub metrics being collected, and values are the corresponding GitHub API URLs. Each key-value pair specifies a source of metrics data and its API endpoint.

.EXAMPLE
Try to use the convention below for Splunk Sources.
$DataForSplunk = @{
    "github:orgs:splunkpoc:repos" = "https://api.github.com/orgs/myorg/repos";
    "github:orgs:splunkpoc:members" = "https://api.github.com/orgs/myorg/members";
}

Send-GitHubOrgMetricsToSplunk -SplunkServer "splunk.mydomain.com" -ApiKey "mySplunkApiKey" -Index "github_metrics" -GitHubAppKey "base64PrivateKey" -InstallationId "12345678" -AppId "87654321" -OrgName "splunkpoc" -DataForSplunk $DataForSplunk

This example sends metrics about an organization's repositories and members from GitHub to a specified Splunk server. The metrics are retrieved using a GitHub App's credentials and the specified API endpoints.

.NOTES
Ensure that the GitHub App has sufficient permissions to access the data specified in the DataForSplunk hashtable.

Also ensure you use https://splunkinputdomainname/services/collector/event

Ensure that this runs with Powershell Core as the -FollowRelLink for handling pagination is only available in core

Finally make sure to configure the apikey for Splunk as "Splunk <yourkey>"
#>

function Send-GitHubOrgMetricsToSplunk {
    param (
        [Parameter(Mandatory)]
        [string]$SplunkServer,

        [Parameter(Mandatory)]
        [string]$ApiKey,

        [Parameter(Mandatory)]
        [string]$Index,

        [Parameter(Mandatory)]
        [string]$GitHubAppKey,

        [Parameter(Mandatory)]
        [string]$InstallationId,

        [Parameter(Mandatory)]
        [string]$AppId,

        [Parameter(Mandatory)]
        [string]$OrgName,

        [Parameter(Mandatory)]
        [hashtable]$DataForSplunk
    )

    # These are used in the DataForSplunk Hashtable to indicate that the call to the api and the corresponding splunk source need to be created
    # for each available repo, workflow, or item required.
    $RepoPlaceholder = '<REPO>'
    $WorkflowPlaceholder = '<WORKFLOW_ID>'

    # Generate the GitHub access token.  Note that the token will be different for each org, as each org needs its own GitHub App
    # with the same perms configured for this purpose.  This is why this function is done per org.
    $token = New-GitHubAccessToken -GitHubAppKeyString $GitHubAppKey -InstallationId $InstallationId -AppId $AppId

    # Headers for GitHub API requests
    $headers = @{
        "Accept"               = "application/vnd.github+json"
        "Authorization"        = "Bearer $token"
        "X-GitHub-Api-Version" = "2022-11-28"
    }

    # Get a list of all repos for the org.  Use the orgname to get all the repo names
    try {
        $OrgRepos = Invoke-RestMethod -Uri "https://api.github.com/orgs/$OrgName/repos" -Headers $headers -Method Get -UseBasicParsing -FollowRelLink
    }
    catch {
        Write-Error ("Unable to get repos from $OrgName.  Error - $($_.Exception.Message)")
        return -1
    }

    #Get a list of all the workflows for all repos
    $OrgWorkflows = New-Object System.Collections.ArrayList
    foreach ($Repo in $OrgRepos) {
        #write-output "https://api.github.com/repos/$OrgName/$($Repo.Name)/actions/workflows"
        $workflows = (Invoke-RestMethod -Uri "https://api.github.com/repos/$OrgName/$($Repo.Name)/actions/workflows" -Headers $headers -Method Get -UseBasicParsing -FollowRelLink).workflows
        foreach ($workflow in $workflows) {
            [void]$OrgWorkflows.Add($workflow)
        }
    }

    # Maintain a list of responses. If any fail, log the error but continue on to the next API endpoint.
    # Only add the ones that do not fail to the list to be added to Splunk.
    $ApiResponses = New-Object System.Collections.ArrayList

    # Helper function for adding api responses to the array list above.  Only api responses that contain
    # a non null value will be added to the list.  Empty responses are not converted to data with zero values.
    function Add-ResponseToArrayList {
        param (
            [System.Collections.ArrayList]$ApiResponses,
            $response,
            $splunkSource
        )

        foreach ($property in $response.PSObject.Properties) {
            if ($null -ne $property.Value -and '' -ne $property.Value) {
                # Create the response data object
                $ResponseData = [PSCustomObject]@{
                    Response     = $response
                    SplunkSource = $splunkSource
                }
                # Add the response data object to the ArrayList
                [void]$ApiResponses.Add($ResponseData)
                # Since we only need one non-null property to add the response, break after adding
                break
            }
        }
    }

    # Loop through each key in the hashtable of splunk sources and use the corresponding API endpoint defined in DataForSplunk.  If a template is used
    # like <REPO> then we need to loop through each repo and make a call to the corresponding endpoint by replacing the repo values in the templated Splunk source and api call
    # For example "github:org:splunkpoc:repos:<REPO>:actions:workflows:<WORKFLOW_ID>:timing" = "https://api.github.com/repos/SplunkPOC/<REPO>/actions/workflows/<WORKFLOW_ID>/timing"
    foreach ($key in $DataForSplunk.Keys) {

        # This will replace the workflow ID and repo placeholder values based on the repos and workflows for this GitHub Org.
        if ( ($key -match $RepoPlaceholder) -and ($key -match $WorkflowPlaceholder) ) {
            foreach ($repo in $OrgRepos) {
                $RepoWorkflows = $OrgWorkflows | Where-Object { $_.URL -match $repo.name }
                foreach ($workflow in $RepoWorkflows) {
                    # String replace both the repo and workflow ID in the splunk source and GitHub API strings. Using ToLower to keep things consistent within Splunk as it is
                    # case sensitive.
                    $SplunkSource = ($key.replace($RepoPlaceholder, $repo.Name).replace($WorkflowPlaceholder, $workflow.ID)).ToLower()
                    $ApiEndpoint = ($DataForSplunk[$key]).replace($RepoPlaceholder, $repo.Name).replace($WorkflowPlaceholder, $workflow.ID)
                    try {
                        $response = Invoke-RestMethod -Uri $ApiEndpoint -Headers $headers -Method Get -UseBasicParsing -FollowRelLink
                        Add-ResponseToArrayList -ApiResponses $ApiResponses -response $response -splunkSource $SplunkSource

                    }
                    catch {
                        # PowerShell exceptions for HTTP errors include the response status code
                        if ($_.Exception.Response) {
                            $statusCode = $_.Exception.Response.StatusCode.value__
                            Write-Error "Unable to retrieve data for endpoint $ApiEndpoint - Status code: $statusCode`nError - $($_.Exception.Message)"
                        }
                        else {
                            # Handle other errors (e.g., network issues)
                            Write-Error "Unable to access API endpoint $ApiEndpoint Error - $($_.Exception.Message)"
                        }
                    }
                }
            }
        }
        elseif ($key -match $RepoPlaceholder) {
            foreach ($repo in $OrgRepos) {
                $SplunkSource = ($key.replace($RepoPlaceholder, $repo.Name)).ToLower()
                $ApiEndpoint = ($DataForSplunk[$key]).replace($RepoPlaceholder, $repo.Name)
                try {
                    $response = Invoke-RestMethod -Uri $ApiEndpoint -Headers $headers -Method Get -UseBasicParsing -FollowRelLink
                    Add-ResponseToArrayList -ApiResponses $ApiResponses -response $response -splunkSource $SplunkSource
                }
                catch {
                    # PowerShell exceptions for HTTP errors include the response status code
                    if ($_.Exception.Response) {
                        $statusCode = $_.Exception.Response.StatusCode.value__
                        Write-Error "Unable to retrieve data for endpoint $ApiEndpoint - Status code: $statusCode`nError - $($_.Exception.Message)"
                    }
                    else {
                        # Handle other errors (e.g., network issues)
                        Write-Error "Unable to access API endpoint $ApiEndpoint Error - $($_.Exception.Message)"
                    }
                }
            }
        }
        else {
            try {
                $ApiEndpoint = $DataForSplunk[$key]
                $SplunkSource = $key.ToLower()
                $response = Invoke-RestMethod -Uri $ApiEndpoint -Headers $headers -Method Get -UseBasicParsing -FollowRelLink
                Add-ResponseToArrayList -ApiResponses $ApiResponses -response $response -splunkSource $SplunkSource
            }
            catch {
                # PowerShell exceptions for HTTP errors include the response status code
                if ($_.Exception.Response) {
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    Write-Error "Unable to retrieve data for endpoint $ApiEndpoint - Status code: $statusCode`nError - $($_.Exception.Message)"
                }
                else {
                    # Handle other errors (e.g., network issues)
                    Write-Error "Unable to access API endpoint $ApiEndpoint `nError - $($_.Exception.Message)"
                }
            }
        }
    }

    #Send all the collected repsonses to Splunk
    foreach ($ApiResponse in $ApiResponses) {
        #Format the data as JSON to suit the Splunk function
        $Data = [PSCustomObject]@{
            ApiResponseData = $ApiResponse.Response
        }
        $Data = $Data | ConvertTo-Json -Depth 99

        $splunkParams = @{
            Data         = $Data
            SplunkServer = $SplunkServer
            ApiKey       = $ApiKey
            SourceType   = $ApiResponse.SplunkSource
            Source       = $ApiResponse.SplunkSource
            Index        = $Index
            Format       = "json"
        }

        Send-ToSplunk @splunkParams
    }
}