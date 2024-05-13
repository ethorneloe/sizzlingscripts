<#
.SYNOPSIS
Converts Unicode curly quotes to their ANSI single or double quote equivalents.

.DESCRIPTION
This function processes input data to replace Unicode curly single quotes (‘ and ’) and double quotes (“ and ”) with their ANSI equivalents (' and "). It can handle strings, arrays of strings, and objects containing string properties.

.EXAMPLE
PS> Convert-UnicodeCurlyQuotesToAnsi -InputData "‘Hello, World!’"
'Hello, World!'

This example converts Unicode curly single quotes in the input string to ANSI single quotes.

.EXAMPLE
PS> Convert-UnicodeCurlyQuotesToAnsi -InputData @("‘Example’", "“Test”")
@("'Example'", '"Test"')

This example shows how the function can process an array of strings, replacing both types of curly quotes with their ANSI equivalents.

.PARAMETERS
-InputData
The input data that contains Unicode curly quotes. It can be a single string, an array of strings, or an object with string properties.

.NOTES
The function dynamically handles different types of input and ensures all strings within those inputs have their Unicode curly quotes replaced with ANSI quotes.
#>

function Convert-UnicodeCurlyQuotesToAnsi {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object]$InputData
    )

    Process {
        if ($InputData -is [String]) {
            # Handle string directly
            $InputData = $InputData -replace [char]0x2018, "'"
            $InputData = $InputData -replace [char]0x2019, "'"
            $InputData = $InputData -replace [char]0x201C, '"'
            $InputData = $InputData -replace [char]0x201D, '"'
            $InputData
        }
        elseif ($InputData -is [Array]) {
            # Handle each element if it is an array
            for ($i = 0; $i -lt $InputData.Length; $i++) {
                if ($InputData[$i] -is [String]) {
                    $InputData[$i] = $InputData[$i] -replace [char]0x2018, "'"
                    $InputData[$i] = $InputData[$i] -replace [char]0x2019, "'"
                    $InputData[$i] = $InputData[$i] -replace [char]0x201C, '"'
                    $InputData[$i] = $InputData[$i] -replace [char]0x201D, '"'
                }
            }
            $InputData
        }
        elseif ($InputData -is [PSObject]) {
            # Handle properties if it is an object
            $InputData.PSObject.Properties | ForEach-Object {
                if ($_.Value -is [string]) {
                    $_.Value = $_.Value -replace [char]0x2018, "'"
                    $_.Value = $_.Value -replace [char]0x2019, "'"
                    $_.Value = $_.Value -replace [char]0x201C, '"'
                    $_.Value = $_.Value -replace [char]0x201D, '"'
                }
            }
            $InputData
        }
    }
}