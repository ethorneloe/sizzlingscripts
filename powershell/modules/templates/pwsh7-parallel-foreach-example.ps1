# Sample script demonstrating pwsh 7 parallel loop with references to variables defined outside the loop scope and a concurrent
# bag for threadsafe operations.

# Define several arrays with sample phrases
$array1 = @('test one', 'a sample', 'another test', 'something else')
$array2 = @('one more test', 'nothing here', 'test again', 'final example')
$array3 = @('begin test', 'end now', 'restart', 'last test case')

# Combine all arrays into a list for looping
$allPhrases = @($array1, $array2, $array3)

$wordToFind = "test"

# Create a thread-safe concurrent bag to store results
$results = [System.Collections.Concurrent.ConcurrentBag[string]]::new()

# Loop through each array in parallel and collect phrases containing 'tes'
$allPhrases | ForEach-Object -Parallel {
    $_results = $using:results
    $_wordToFind = $using:wordToFind
    foreach ($phrase in $_) {
        # Check if the phrase contains 'tes'
        if ($phrase -like "*$_wordToFind*") {
            # Add the phrase to the concurrent bag
            $_results.Add($phrase)
        }
    }
}

# Display the results after the parallel execution
$results.GetEnumerator() | ForEach-Object {
    Write-Output "Phrase found: $_"
}