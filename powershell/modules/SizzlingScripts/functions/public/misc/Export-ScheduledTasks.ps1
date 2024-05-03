<#
.SYNOPSIS
   Exports scheduled tasks with specified conditions to a CSV file.

.DESCRIPTION
   This function exports scheduled tasks that meet the specified conditions from a list of task paths to a CSV file.
   The conditions are:
   - Task name does not start with "User_Feed"
   - Task author is not "Microsoft Corporation"

.PARAMETER TaskPaths
   An array of strings representing the task paths to search for scheduled tasks.

.PARAMETER ExportFilePath
   The file path where the exported CSV file will be saved.

.EXAMPLE
   Export-ScheduledTasks -TaskPaths @("\", "\ITP\") -ExportFilePath "TaskSchedulerExport.csv"

.INPUTS
   TaskPaths: System.String[]
   ExportFilePath: System.String

.OUTPUTS
   None
#>
function Export-ScheduledTasks {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Array of task paths to search for scheduled tasks.")]
        [ValidateNotNullOrEmpty()]
        [string[]]$TaskPaths,

        [Parameter(Mandatory = $true, HelpMessage = "File path to save the exported CSV file.")]
        [ValidateNotNullOrEmpty()]
        [string]$ExportFilePath
    )

    function Get-FilteredTasks {
        param (
            [string]$TaskPath
        )

        $tasks = Get-ScheduledTask -TaskPath $TaskPath | Select-Object -Property *

        $filteredTasks = $tasks | Where-Object {
            ($_.TaskName -notlike "User_Feed*") -and ($_.Author -ne "Microsoft Corporation")
        }

        return $filteredTasks
    }

    $tasks = @()

    foreach ($taskPath in $TaskPaths) {
        $tasks += Get-FilteredTasks -TaskPath $taskPath
    }

    $taskList = @()

    foreach ($task in $tasks) {

        $taskInfo = Get-ScheduledTaskInfo -TaskPath $task.TaskPath -TaskName $task.TaskName
        $action = $task.Actions[0]

        $scriptPath = ($action.Arguments | Select-String -Pattern '(?:\w:|\\\\|\.\\).*\.\w+' -AllMatches).Matches.Value

        $taskDetails = [ordered]@{
            "TaskPath"          = $task.TaskPath
            "TaskName"          = $task.TaskName
            "Description"       = $task.Description
            "State"             = $task.State
            "Enabled"           = $task.Settings.Enabled
            "Author"            = $task.Author
            "NextRunTime"       = $taskInfo.NextRunTime
            "LastRunTime"       = $taskInfo.LastRunTime
            "LastTaskResult"    = $taskInfo.LastTaskResult
            "Run As Account"    = $task.Principal.UserID
            "Execute"           = $action.Execute
            "Arguments"         = $action.Arguments
            "Working Directory" = $action.WorkingDirectory
            "ScriptPath"        = $scriptPath -join ", "
        }
        $taskList += New-Object PSObject -Property $taskDetails
    }

    $taskList | Export-Csv -Path $ExportFilePath -NoTypeInformation
    Write-Output "Filtered tasks have been exported to $ExportFilePath"
}