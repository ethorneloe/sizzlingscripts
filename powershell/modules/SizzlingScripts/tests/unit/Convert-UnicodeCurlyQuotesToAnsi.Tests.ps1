Describe 'Convert-UnicodeCurlyQuotesToAnsi Tests' {

    BeforeAll {
        Import-Module ./powershell/modules/SizzlingScripts -Force
    }

    Context 'Single String Input' {
        It 'Replaces curly single and double quotes in a string' {
            $inputString = "This is a `u{201C}test`u{201D} with `u{2018}quotes`u{2019}"
            $expectedString = "This is a ""test"" with 'quotes'"
            $result = $inputString | Convert-UnicodeCurlyQuotesToAnsi
            $result | Should -BeExactly $expectedString
        }
    }

    Context 'Array of Strings Input' {
        It 'Replaces curly quotes in each string within an array' {
            $inputArray = @("String with `u{201C}quotes`u{201D}", "Another `u{2018}test`u{2019}")
            $expectedArray = @("String with ""quotes""", "Another 'test'")
            $result = $inputArray | Convert-UnicodeCurlyQuotesToAnsi
            $result | Should -BeExactly $expectedArray
        }
    }

    Context 'PSObject Input' {
        It 'Replaces curly quotes in string properties of an object' {
            $inputObject = [PSCustomObject]@{
                Name  = "John"
                Quote = "Here’s a `u{201C}remarkable`u{201D} quote"
            }
            $expectedQuote = "Here's a ""remarkable"" quote"
            $result = $inputObject | Convert-UnicodeCurlyQuotesToAnsi
            $result.Quote | Should -BeExactly $expectedQuote
        }
    }
}
