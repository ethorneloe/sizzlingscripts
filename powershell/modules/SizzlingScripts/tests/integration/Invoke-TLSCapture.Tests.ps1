BeforeAll {
    Import-Module ./powershell/modules/SizzlingScripts -Force
}

Describe "Invoke-TLSCapture Tests" {
    Context "Integration Test with Web Requests" {
        It "Should capture data during script block execution" {
            # Define a script block that generates network traffic
            $scriptBlock = {
                Invoke-WebRequest "https://github.com" | Out-Null
            }

            # Run the function with a script block that generates TLS and DNS traffic.  Change interface name as required.
            $results = Invoke-TLSCapture -InterfaceName "Ethernet0" -ScriptBlock $scriptBlock

            # Check that data was captured
            $results.ClientHellos.Count | Should -BeGreaterThan 0
            $results.ServerHellos.Count | Should -BeGreaterThan 0
            $results.DNSQueries.Count | Should -BeGreaterThan 0
            $results.DNSResponses.Count | Should -BeGreaterThan 0

            # Additional checks for the Protocol field
            foreach ($query in $results.DNSQueries) {
                $query.Protocol | Should -Be 'dns'
            }

            foreach ($hello in $results.ClientHellos) {
                $hello.Protocol | Should -Be 'tls'
            }

            # Validate IP address formats in the captured data
            $ipAddressRegex = '^\d+\.\d+\.\d+\.\d+$'
            $allEntries = $results.ClientHellos + $results.ServerHellos + $results.DNSQueries + $results.DNSResponses

            foreach ($entry in $allEntries) {
                $entry.SourceIP | Should -Match $ipAddressRegex
                $entry.DestinationIP | Should -Match $ipAddressRegex
            }
        }
    }
}