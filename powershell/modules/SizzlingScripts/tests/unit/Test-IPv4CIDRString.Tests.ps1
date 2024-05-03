Describe "Test-IPv4CIDRString Tests" {
    BeforeAll {
        Import-Module ./powershell/modules/SizzlingScripts -Force
    }

    It "Validates standard correct IPv4 CIDR notation" {
        { Test-IPv4CIDRString '192.168.1.1/24' } | Should -Not -Throw
        Test-IPv4CIDRString '192.168.1.1/24' | Should -Be $true
    }

    It "Throws an exception when IP address is invalid" {
        { Test-IPv4CIDRString '192.168.300.1/24' } | Should -Throw "Each segment of the IP address must be a number between 0 and 255 for input: 192.168.300.1/24"
    }

    It "Throws an exception when subnet mask is too large" {
        { Test-IPv4CIDRString '192.168.1.1/33' } | Should -Throw "Invalid subnet mask for input: 192.168.1.1/33"
    }

    It "Throws an exception when subnet mask is negative" {
        { Test-IPv4CIDRString '192.168.1.1/-1' } | Should -Throw "Invalid subnet mask for input: 192.168.1.1/-1"
    }

    It "Throws an exception when CIDR is missing subnet mask" {
        { Test-IPv4CIDRString '192.168.1.1' } | Should -Throw "Invalid CIDR format for input: 192.168.1.1"
    }

    It "Throws an exception when CIDR notation has an incorrect delimiter" {
        { Test-IPv4CIDRString '192.168.1.1-24' } | Should -Throw "Invalid CIDR format for input: 192.168.1.1-24"
    }

    It "Throws an exception when input is an empty string" {
        { Test-IPv4CIDRString '' } | Should -Throw "Cannot validate argument on parameter 'cidr'. The argument is null or empty. Provide an argument that is not null or empty, and then try the command again."
    }

    It "Throws an exception when IP part contains non-numeric characters" {
        { Test-IPv4CIDRString '192.168.1.abc/24' } | Should -Throw "Each segment of the IP address must be a number between 0 and 255 for input: 192.168.1.abc/24"
        { Test-IPv4CIDRString '192.168.1./24' } | Should -Throw "Each segment of the IP address must be a number between 0 and 255 for input: 192.168.1./24"
        { Test-IPv4CIDRString '11.1..0/16' } | Should -Throw "Each segment of the IP address must be a number between 0 and 255 for input: 11.1..0/16"
        { Test-IPv4CIDRString '11.1.1./16' } | Should -Throw "Each segment of the IP address must be a number between 0 and 255 for input: 11.1..0/16"
    }

    It "Throws an exception when IPv4 CIDR notation is without dots" {
        { Test-IPv4CIDRString '192168124/24' } | Should -Throw "IP address must have exactly three dots for input: 192168124/24"
    }

    It "Throws an exception when CIDR notation has extra spaces" {
        { Test-IPv4CIDRString ' 192.168.1.1 / 24 ' } | Should -Throw "Spaces are not permitted in the input:  192.168.1.1 / 24 "
        { Test-IPv4CIDRString '172. .100.0/16' } | Should -Throw "Spaces are not permitted in the input: 172. .100.0/16"
        { Test-IPv4CIDRString '172. 20.100.0/16' } | Should -Throw "Spaces are not permitted in the input: 172. 20.100.0/16"
    }

    It "Validates with minimum subnet mask" {
        { Test-IPv4CIDRString '192.168.1.1/0' } | Should -Not -Throw
        Test-IPv4CIDRString '192.168.1.1/0' | Should -Be $true
    }

    It "Validates with maximum subnet mask" {
        { Test-IPv4CIDRString '192.168.1.1/32' } | Should -Not -Throw
        Test-IPv4CIDRString '192.168.1.1/32' | Should -Be $true
    }

    It "Throws an exception when value is not between 0-255" {
        { Test-IPv4CIDRString '192.256.1.1/32' } | Should -Throw "Each segment of the IP address must be a number between 0 and 255 for input: 192.256.1.1/32"
        { Test-IPv4CIDRString '1003.2.1.1/21' } | Should -Throw "Each segment of the IP address must be a number between 0 and 255 for input: 1003.2.1.1/21"
        { Test-IPv4CIDRString '-20.2.1.1/21' } | Should -Throw "Each segment of the IP address must be a number between 0 and 255 for input: -20.2.1.1/21"
    }

    It "Throws an exception when there are leading zeros except for zero itself" {
        { Test-IPv4CIDRString '192.168.001.1/24' } | Should -Throw "Leading zeros are not allowed except for 0 itself in input: 192.168.001.1/24"
    }
}
