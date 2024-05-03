<#
.SYNOPSIS
Sends a notification message to Microsoft Teams using webhooks.

.DESCRIPTION
This function sends a message to a Microsoft Teams channel using webhooks. It supports multiple card types including Basic and Detailed cards, each with customizable fields. The function ensures that only one card type is selected per invocation.

.PARAMETER WebhookUrl
The URL of the Microsoft Teams webhook where the message will be sent.

.PARAMETER BasicCard
Indicates that a basic card will be sent. Cannot be combined with other card types.

.PARAMETER DetailedCard
Indicates that a detailed card will be sent. Cannot be combined with other card types.

.PARAMETER ActivityTitle
The title of the activity. Used in both basic and detailed cards.

.PARAMETER DetailedText
The main text content of the card. Used in both basic and detailed cards.

.PARAMETER Facts
Optional. An array of hashtable objects representing facts for a detailed card.

.PARAMETER ImageUrl
Optional. The URL of an image to be included in a detailed card.

.PARAMETER ActionTitle
Optional. The title of an action button in a detailed card.

.PARAMETER ActionUrl
Optional. The URL for an action button in a detailed card.

.EXAMPLE
Send-TeamsNotification -WebhookUrl "https://outlook.office.com/webhook/..." -BasicCard -ActivityTitle "Basic Card Title" -DetailedText "This is the content of the basic card."

Sends a basic card to the specified Microsoft Teams channel.

.EXAMPLE
$facts = @(
    @{ "name" = "Fact 1"; "value" = "This is fact one" },
    @{ "name" = "Fact 2"; "value" = "This is fact two" }
)

Send-TeamsNotification -WebhookUrl "https://outlook.office.com/webhook/..." -DetailedCard -ActivityTitle "Detailed Card Title" -DetailedText "This is detailed content." -Facts $facts -ImageUrl "https://example.com/image.jpg" -ActionTitle "More Info" -ActionUrl "https://example.com"

Sends a detailed card with facts, an image, and an action button to the specified Microsoft Teams channel.

#>
function Send-TeamsNotification {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$WebhookUrl, # The webhook URL to which the message will be sent

        [Parameter(ParameterSetName = "BasicCard")]
        [switch]$BasicCard, # Flag to indicate a basic card is being sent

        [Parameter(ParameterSetName = "DetailedCard")]
        [switch]$DetailedCard, # Flag to indicate a detailed card is being sent

        [Parameter(ParameterSetName = "BasicCard")]
        [Parameter(ParameterSetName = "DetailedCard")]
        [Parameter(Mandatory = $true)]
        [string]$ActivityTitle, # The title of the activity, used in both basic and detailed cards

        [Parameter(ParameterSetName = "BasicCard")]
        [Parameter(ParameterSetName = "DetailedCard")]
        [Parameter(Mandatory = $true)]
        [string]$DetailedText, # The main text content of the card

        [Parameter(ParameterSetName = "DetailedCard")]
        [Parameter(Mandatory = $false)]
        [hashtable[]]$Facts, # Optional facts for the detailed card

        [Parameter(ParameterSetName = "DetailedCard")]
        [Parameter(Mandatory = $false)]
        [string]$ImageUrl, # Optional image URL for the detailed card

        [Parameter(ParameterSetName = "DetailedCard")]
        [Parameter(Mandatory = $false)]
        [string]$ActionTitle, # Optional action button title for the detailed card

        [Parameter(ParameterSetName = "DetailedCard")]
        [Parameter(Mandatory = $false)]
        [string]$ActionUrl # Optional action button URL for the detailed card
    )

    # Validate that only one card type is selected
    $selectedCardTypes = @($BasicCard.IsPresent, $DetailedCard.IsPresent) | Where-Object { $_ -eq $true }
    if ($selectedCardTypes.Count -ne 1) {
        throw "Please specify exactly one card type (-BasicCard, -DetailedCard)."
    }

    #
    if (!($ActionTitle -and $ActionUrl) -and ($DetailedCard)) {
        throw "Make sure you have defined both the action title and the action url."
    }

    $payload = $null

    if ($BasicCard) {
        # Constructing the payload for a Basic Card
        $payload = @{
            "@type"    = "MessageCard"
            "@context" = "http://schema.org/extensions"
            "summary"  = $ActivityTitle
            "sections" = @(
                @{
                    "activityTitle" = $ActivityTitle
                    "text"          = $DetailedText
                }
            )
        } | ConvertTo-Json -Depth 10
    }
    elseif ($DetailedCard) {
        # Constructing the payload for a Detailed Card
        $section = @{
            "activityTitle" = $ActivityTitle
            "text"          = $DetailedText
        }

        if ($Facts) {
            $section["facts"] = $Facts
        }

        if ($ImageUrl) {
            $section["images"] = @(@{"image" = $ImageUrl })
        }

        $payload = @{
            "@type"    = "MessageCard"
            "@context" = "http://schema.org/extensions"
            "summary"  = $ActivityTitle
            "sections" = @($section)
        }

        if ($ActionTitle -and $ActionUrl) {
            $payload["potentialAction"] = @(
                @{
                    "@type"   = "OpenUri"
                    "name"    = $ActionTitle
                    "targets" = @(@{"os" = "default"; "uri" = $ActionUrl })
                }
            )
        }

        $payload = $payload | ConvertTo-Json -Depth 10
    }

    if ($null -ne $payload) {
        # Sending the constructed payload to the Teams webhook
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -ContentType 'application/json' -Body $payload
    }
    else {
        Write-Error "No card type selected."
    }
}