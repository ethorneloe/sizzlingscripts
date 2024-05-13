<#
.SYNOPSIS
    Captures TLS handshake data using tshark and parses it into PowerShell objects.

.DESCRIPTION
    This function starts a tshark capture for TLS handshakes on a specified network interface, parses the output, and converts it into a collection of PowerShell objects. It captures details like source and destination IP addresses, TLS versions, cipher suites, and more.

.PARAMETER InterfaceName
    The name of the network interface on which to capture traffic.

.EXAMPLE
    $ScriptBlock = {
        invoke-webrequest "https://github.com"
    }
    Invoke-TLSCapture -ScriptBlock $ScriptBlock -InterfaceName "Ethernet0"
#>
Function Invoke-TLSCapture {
    param (

        [Parameter()]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $true)]
        [string]$InterfaceName
    )

    # Configure tshark params
    $outputFile = New-TemporaryFile
    $maxCaptureTime = 600
    $tsharkPath = "C:\Program Files\Wireshark\tshark.exe"

    $tsharkArgs = "-i $InterfaceName " +
    "-Y `"tls.handshake.type == 1 || tls.handshake.type == 2 || dns.flags.opcode == 0`" " +
    "-T fields " +
    "-e frame.time " +
    "-e frame.protocols " +
    "-e ip.src " +
    "-e ip.dst " +
    "-e tls.handshake.type " +
    "-e tls.record.version " +
    "-e tls.handshake.version " +
    "-e tls.handshake.ciphersuite " +
    "-e tls.handshake.extensions.supported_version " +
    "-e tls.handshake.sig_hash_alg " +
    "-e tls.handshake.extensions_server_name " +
    "-e dns.flags.response " +
    "-e dns.qry.name " +
    "-e dns.resp.name " +
    "-e dns.resp.type " +
    "-e dns.cname " +
    "-e dns.a " +
    "-E separator=`"|`" " +
    "-E occurrence=a " +
    "-a duration:$($maxCaptureTime)"

    $tsharkProcess = Start-Process -FilePath $tsharkPath -ArgumentList $tsharkArgs -RedirectStandardOutput $outputFile -PassThru -WindowStyle hidden

    # Small time buffer before starting the scriptblock
    Start-Sleep -Seconds 5

    try {
        Invoke-Command -ScriptBlock $ScriptBlock
    }
    catch {
        Write-Error "An error occurred: $_"
    }
    finally {

        if (!$tsharkProcess.HasExited) {
            Stop-Process -Id $tsharkProcess.Id -Force
        }

        # Parse the output file into PowerShell objects
        $results = Get-Content $outputFile | ForEach-Object {
            if ($_ -notmatch "\|") { continue }
            $fields = $_ -split '\|'
            $protocols = $fields[1].split(':')

            if ('tls' -in $protocols) {
                [PSCustomObject]@{
                    Timestamp               = $fields[0]
                    Protocol                = $fields[1]
                    SourceIP                = $fields[2]
                    DestinationIP           = $fields[3]
                    HandshakeType           = ($fields[4] -split ',').trim() | Convert-TLSContentTypeFromDecimal
                    RecordVersion           = ($fields[5] -split ',').trim() | Convert-TLSContentTypeFromDecimal
                    HandShakeVersion        = ($fields[5] -split ',').trim() | Convert-TLSVersionFromHex
                    CipherSuites            = ($fields[6] -split ',').trim() | Convert-CipherSuiteFromHex
                    SupportedVersions       = ($fields[7] -split ',').trim() | Convert-TLSVersionFromHex
                    SignatureHashAlgorithms = ($fields[8] -split ',').trim() | Convert-SigHashAlgoFromHex
                    ServerName              = $fields[9]
                }
            }
            elseif ('dns' -in $protocols) {
                [PSCustomObject]@{
                    Timestamp          = $fields[0]
                    Protocol           = $fields[1]
                    SourceIP           = $fields[2]
                    DestinationIP      = $fields[3]
                    DNSResponseFlag    = $fields[11]
                    DNSQueryName       = $fields[12]
                    DNSResponseName    = $fields[13] -split ','
                    DNSResponseType    = $fields[14] -split ',' | ForEach-Object { @{ "1" = "A"; "5" = "CNAME" }[$_] }
                    DNSResponseCname   = $fields[15] -split ','
                    DNSResponseAddress = $fields[16] -split ','
                }
            }
        }

        try {
            # Clean up temporary files.  This will clean all trace files in the current profile temp dir
            $outputFile | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
            Get-ChildItem -Path "$env:TEMP" -Filter "*.pcapng" -Recurse -File | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch {
            throw "Unable to remove $outputFile and temp files under $($env:TEMP) - $($_.exception.message)"
        }
    }

    return $results
}




#dns.resp.name == "ipv4-eau-oi-ods-cses-b.australiaeast.cloudapp.azure.com"
#dns.flags.response == 0 is a client query
#dns.flags.response == 1 is a client response
#