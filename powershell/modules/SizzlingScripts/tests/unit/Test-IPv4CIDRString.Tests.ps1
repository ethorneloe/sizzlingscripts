Describe "Test-IPv4CIDRString Tests" {

    It "Validates standard correct IPv4 CIDR notation" {
        Test-IPv4CIDRString '192.168.1.1/24' | Should -Be $true
    }

    It "Rejects when IP address is invalid" {
        Test-IPv4CIDRString '192.168.300.1/24' | Should -Be $false
    }

    It "Rejects when subnet mask is too large" {
        Test-IPv4CIDRString '192.168.1.1/33' | Should -Be $false
    }

    It "Rejects when subnet mask is negative" {
        Test-IPv4CIDRString '192.168.1.1/-1' | Should -Be $false
    }

    It "Rejects when CIDR is missing subnet mask" {
        Test-IPv4CIDRString '192.168.1.1' | Should -Be $false
    }

    It "Rejects malformed CIDR notation with incorrect delimiter" {
        Test-IPv4CIDRString '192.168.1.1-24' | Should -Be $false
    }

    It "Rejects empty string input" {
        Test-IPv4CIDRString '' | Should -Be $false
    }

    It "Rejects when IP part contains non-numeric characters" {
        Test-IPv4CIDRString '192.168.1.abc/24' | Should -Be $false
    }

    It "Rejects IPv4 CIDR notation without dots" {
        Test-IPv4CIDRString '192168124/24' | Should -Be $false
    }

    It "Rejects CIDR notation with extra spaces" {
        Test-IPv4CIDRString ' 192.168.1.1 / 24 ' | Should -Be $false
    }

    It "Validates with minimum subnet mask" {
        Test-IPv4CIDRString '192.168.1.1/0' | Should -Be $true
    }

    It "Validates with maximum subnet mask" {
        Test-IPv4CIDRString '192.168.1.1/32' | Should -Be $true
    }

    It "Rejects when CIDR has additional invalid characters" {
        Test-IPv4CIDRString '192.168.1.1/24s' | Should -Be $false
    }

    It "Rejects with missing parts in the IP address" {
        Test-IPv4CIDRString '192.168/24' | Should -Be $false
    }
}
