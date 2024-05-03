<#
.SYNOPSIS
Copies scheduled tasks from a source server to the local machine the script is run on.

.DESCRIPTION
The Import-ScheduledTasksFromServer function exports scheduled tasks from a specified taskpath (folder within the Scheduled Tasks console) on a source server and imports them into the same taskpath on the local machine. The tasks are imported to run under a specified service account.

.PARAMETER SourceServer
The name or IP address of the source server from which tasks will be exported.

.PARAMETER TaskPath
The taskpath of the tasks to be copied (folder within the Scheduled Tasks console). Blocks the use of the root taskpath to ensure only custom user created taskpaths are used for imports.

.PARAMETER serviceAccountCredential
PSCredential for the account the tasks are already configured with.  This ensures the same account is used for the import. If not provided, the script will prompt for credentials.

.EXAMPLE
Import-ScheduledTasksFromServer -SourceServer "Server01" -TaskPath "\MyTasks\" -serviceAccountCredential $Credential

This example copies all scheduled tasks from the "\MyTasks\" taskpath on "Server01" to localhost, setting them to run under the account provided via $Credential.

Run Get-ScheduledTask on the source server to find the taskpath value required.

.NOTES
Ensure that WinRM is enabled and properly configured on the source server for remote commands to execute successfully.

This function is designed for a specific use case where all the tasks are present under a specific folder in task scheduler and all run with the same service account.
Make sure the service account has log on as a batch job rights before running this.  Make sure to execute this with admin privileges.

Folder contents still need to be manually copied across to the new server and configured properly.  Currently the script only imports the tasks and not the files
referenced in the actions portion of the scheduled tasks.

Tasks on the destination server with the same name in the same taskpath will be overwritten.
#>

function Import-ScheduledTasksFromServer {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourceServer,

        [Parameter(Mandatory = $true)]
        [string]$TaskPath,

        [PSCredential]$serviceAccountCredential
    )

    # Ensure the root task folder is not selected
    if ($TaskPath.Trim() -eq "\") {
        throw "Importing from the root taskpath is not supported. Supply a child taskpath such as \CustomPath\"
    }

    # Prompt for credentials if not provided.  $null simply suppresses output to the console.
    if ($null -eq $serviceAccountCredential) {
        $serviceAccountCredential = Get-Credential $null
    }

    # Check WinRM with a basic command
    try {
        $testCommand = { Get-Process -Name "System" }
        Invoke-Command -ComputerName $SourceServer -ScriptBlock $testCommand -ErrorAction Stop | Out-Null
    }
    catch {
        throw "Failed to connect to $SourceServer via WinRM. Ensure that WinRM is configured and the server is accessible."
    }

    # Script block for exporting tasks and serializing them along with their names
    $exportScriptBlock = {
        param($folder)
        $tasks = Get-ScheduledTask -TaskPath $folder
        $arrayList = New-Object System.Collections.ArrayList
        foreach ($task in $tasks) {
            $taskName = $task.TaskName
            $xml = Export-ScheduledTask -TaskName $taskName -TaskPath $folder
            # Custom object to hold both name and XML
            $obj = [PSCustomObject]@{
                TaskName = $taskName
                TaskXml  = $xml
            }
            $arrayList.Add($obj) | Out-Null
        }
        $arrayList
    }

    # Execute the export script block on the source server and store the results
    $serializedTasksWithNames = Invoke-Command -ComputerName $SourceServer -ScriptBlock $exportScriptBlock -ArgumentList $TaskPath

    # If we are not using -whatif then loop through the tasks and import them to localhost, else just display the tasks that would be imported
    if ($PSCmdlet.ShouldProcess("localhost", "Import tasks")) {
        foreach ($task in $serializedTasksWithNames) {
            $taskName = $task.TaskName
            $taskXml = $task.TaskXml
            Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force -TaskPath $TaskPath -User $serviceAccountCredential.GetNetworkCredential().UserName -Password $serviceAccountCredential.GetNetworkCredential().Password | Out-Null
        }
    }
    else {
        Write-Output "`nWould import the following tasks to localhost:`n"
        $serializedTasksWithNames | Select-Object TaskName
    }
}