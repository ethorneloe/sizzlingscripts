function Get-ExpiringAppSecretsAndCerts {
    param (
        [int]$days = 30,
        [string]$identityId
    )

    $expiringApps = @()

    # Authenticate using the managed identity
    Connect-AzAccount -Identity -AccountId $identityId | Out-Null

    $subscriptions = Get-AzSubscription

    foreach ($subscription in $subscriptions) {
        Set-AzContext -SubscriptionId $subscription.Id

        $appRegistrations = Get-AzADApplication

        foreach ($app in $appRegistrations) {
            $secrets = Get-AzADAppCredential -ObjectId $app.Id

            foreach ($secret in $secrets) {
                $expiryDate = [datetime]$secret.EndDateTime

                #if ($expiryDate -lt (Get-Date).AddDays($days)) {
                    $expiringApps += [PSCustomObject]@{
                        SubscriptionId    = $subscription.Id
                        SubscriptionName  = $subscription.Name
                        AppId             = $app.AppId
                        AppName           = $app.DisplayName
                        SecretOrCertType  = if ($secret.Type -eq 'AsymmetricX509Cert') { 'Certificate' } else { 'Secret' }
                        SecretName        = $secret.DisplayName
                        ExpiryDate        = $expiryDate
                    }
                #}
            }
        }
    }

    return $expiringApps
}

# Example of calling the function inside a runbook
$identityId = "xxx-xxx-xxxx"  # Replace with your managed identity ID
$expiringApps = Get-ExpiringAppSecretsAndCerts -days 30 -identityId $identityId

# Output the results
$expiringApps | Format-Table -AutoSize
