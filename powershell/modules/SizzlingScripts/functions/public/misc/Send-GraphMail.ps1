
#Test changes
function Send-GraphMail {
    param (
        [Parameter(Mandatory = $true)]
        [string] $ClientID,
        [Parameter(Mandatory = $true)]
        [string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)]
        [string] $Tenant,
        [Parameter(Mandatory = $true)]
        [string] $Subject,
        [Parameter(Mandatory = $true)]
        [string] $Body,
        [Parameter(Mandatory = $true)]
        [string[]] $ToRecipients,
        [Parameter(Mandatory = $false)]
        [string[]] $CcRecipients,
        [Parameter(Mandatory = $false)]
        [string[]] $BccRecipients,
        [Parameter(Mandatory = $true)]
        [string] $Sender,
        [Parameter(Mandatory = $false)]
        [string] $AttachmentPath,
        [Parameter(Mandatory = $false)]
        [string] $AttachmentName,
        [Parameter(Mandatory = $false)]
        [ValidateSet(
            "text/plain",
            "text/csv",
            "text/html")]
        [string] $AttachmentContentType,
        [switch] $SaveToSentItems
    )

    Import-Module Microsoft.Graph.Users.Actions

    # Throw an error whenever some attachment params are set but not all of them.  We need all three together.
    if (($null -ne $AttachmentPath) -or ($null -ne $AttachmentName) -or ($null -ne $AttachmentContentType)) {
        if (($null -eq $AttachmentPath) -or ($null -eq $AttachmentName) -or ($null -eq $AttachmentContentType)) {
            throw "If one attachment parameter is provided, then all attachment parameters (AttachmentPath, AttachmentName, AttachmentContentType) must be provided."
        }
    }

    Connect-MgGraph -ClientID $ClientID -CertificateThumbprint $CertificateThumbprint -Tenant $Tenant > $null

    $ToRecipientsParam = @()
    $CcRecipientsParam = @()
    $BccRecipientsParam = @()

    # Add users to ToRecipients, CcRecipients, and BccRecipients param arrays
    foreach ($email in $ToRecipients) {
        $ToRecipientsParam += @{ emailAddress = @{ address = $email } }
    }
    foreach ($email in $CcRecipients) {
        $CcRecipientsParam += @{ emailAddress = @{ address = $email } }
    }
    foreach ($email in $BccRecipients) {
        $BccRecipientsParam += @{ emailAddress = @{ address = $email } }
    }

    # Compose message
    $params = @{
        Message         = @{
            subject       = $Subject
            body          = @{
                contentType = "html"
                content     = $Body
            }
            toRecipients  = $ToRecipientsParam
            ccRecipients  = $CcRecipientsParam
            bccRecipients = $BccRecipientsParam

        }
        saveToSentItems = $SaveToSentItems
    }

    if ($AttachmentPath -and $AttachmentName -and $AttachmentContentType) {
        $AttachmentContentBytes = [System.IO.File]::ReadAllBytes($AttachmentPath)
        $AttachmentContent = [System.Convert]::ToBase64String($AttachmentContentBytes)

        $Attachment = @{
            "@odata.type" = "#microsoft.graph.fileAttachment"
            ContentBytes  = $AttachmentContent
            Name          = $AttachmentName
            ContentType   = $AttachmentContentType
        }

        # Add the attachment to the message parameters
        $params.Message.attachments = @($Attachment)
    }

    Send-MgUserMail -UserId $Sender -BodyParameter $params
}
