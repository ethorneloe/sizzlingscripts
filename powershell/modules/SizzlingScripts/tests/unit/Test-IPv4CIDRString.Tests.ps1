Describe "Test-IPv4CIDRString Tests" {
    BeforeAll {
        Import-Module ./powershell/modules/SizzlingScripts -Force
    }

    It "Validates standard correct IPv4 CIDR notation" {
        { Test-IPv4CIDRString '192.168.1.1/24' } | Should -Not -Throw
        Test-IPv4CIDRString '192.168.1.1/24' | Should -Be $true
    }

    It "Throws an exception when IP address is invalid" {
        { Test-IPv4CIDRString '192.168.300.1/24' } | Should -Throw "Invalid IP address."
    }

    It "Throws an exception when subnet mask is too large" {
        { Test-IPv4CIDRString '192.168.1.1/33' } | Should -Throw "Invalid subnet mask."
    }

    It "Throws an exception when subnet mask is negative" {
        { Test-IPv4CIDRString '192.168.1.1/-1' } | Should -Throw "Invalid subnet mask."
    }

    It "Throws an exception when CIDR is missing subnet mask" {
        { Test-IPv4CIDRString '192.168.1.1' } | Should -Throw "Invalid CIDR format."
    }

    It "Throws an exception when CIDR notation has an incorrect delimiter" {
        { Test-IPv4CIDRString '192.168.1.1-24' } | Should -Throw "Invalid CIDR format."
    }

    It "Throws an exception when input is an empty string" {
        { Test-IPv4CIDRString '' } | Should -Throw "Invalid CIDR format."
    }

    It "Throws an exception when IP part contains non-numeric characters" {
        { Test-IPv4CIDRString '192.168.1.abc/24' } | Should -Throw "Invalid IP address."
    }

    It "Throws an exception when IPv4 CIDR notation is without dots" {
        { Test-IPv4CIDRString '192168124/24' } | Should -Throw "Invalid IP address."
    }

    It "Throws an exception when CIDR notation has extra spaces" {
        { Test-IPv4CIDRString ' 192.168.1.1 / 24 ' } | Should -Throw "Invalid CIDR format."
    }

    It "Validates with minimum subnet mask" {
        { Test-IPv4CIDRString '192.168.1.1/0' } | Should -Not -Throw
        Test-IPv4CIDRString '192.168.1.1/0' | Should -Be $true
    }

    It "Validates with maximum subnet mask" {
        { Test-IPv4CIDRString '192.168.1.1/32' } | Should -Not -Throw
        Test-IPv4CIDRString '192.168.1.1/32' | Should -Be $true
    }

    It "Throws an exception when CIDR has additional invalid characters" {
        { Test-IPv4CIDRString '192.168.1.1/24s' } | Should -Throw "Invalid subnet mask."
    }

    It "Throws an exception when there are missing parts in the IP address" {
        { Test-IPv4CIDRString '192.168/24' } | Should -Throw "Invalid IP address."
    }
}
