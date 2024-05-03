# Import Dependencies - Make sure these are also added to the psd1 file

# Import-Module -Name 'DependencyModule1' -MinimumVersion '2.0.0'
# Import-Module -Name 'DependencyModule2' -MinimumVersion '3.1.0'

# Load private functions
$privateFunctions = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'functions/private') -Filter *.ps1 -Recurse
foreach ($privateFunction in $privateFunctions) {
    . $privateFunction.FullName
}

# Load public functions
$publicFunctions = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'functions/public') -Filter *.ps1 -Recurse
foreach ($publicFunction in $publicFunctions) {
    . $publicFunction.FullName
}

# Export public functions
Export-ModuleMember -Function $publicFunctions.Basename