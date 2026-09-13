# Advanced Elastic Stack Import Script for Challenge: Calculated!
function New-CalcNetworkRedHerring {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Sequence
    )

    $domains = @(
        "telemetry.microsoft-update.net",
        "cdn.windows-security.org",
        "status.office-sync.com",
        "content.edge-delivery.net",
        "metrics.cloud-insights.io",
        "download.browser-check.com",
        "api.device-health.net",
        "ntp.time-service.org",
        "assets.update-catalog.com",
        "reports.endpoint-watch.io"
    )
    $domain = $domains[($Sequence - 1) % $domains.Count]
    $timestamp = (Get-Date -AsUTC).AddSeconds(-(Get-Random -Minimum 7200 -Maximum 2592001)).ToString("o")
    $sourceIp = "10.42.7.$(10 + (($Sequence - 1) % 240))"
    $destinationIp = "198.51.100.$(10 + (($Sequence - 1) % 240))"
    $sourcePort = Get-Random -Minimum 49152 -Maximum 65536
    $processId = 5000 + $Sequence

    return [PSCustomObject]@{
        '@timestamp' = $timestamp
        message = "Network connection detected"
        tags = @("network", "sysmon", "endpoint")
        ecs = [PSCustomObject]@{ version = "9.5.0" }
        event = [PSCustomObject]@{
            action = "connection_attempt"
            category = @("network")
            kind = "event"
            type = @("connection")
            outcome = "unknown"
            provider = "Microsoft-Windows-Sysmon"
            code = "3"
            created = $timestamp
            ingested = (Get-Date -AsUTC).ToString("o")
        }
        agent = [PSCustomObject]@{ type = "endpoint"; name = "elastic-agent"; version = "9.5.3" }
        observer = [PSCustomObject]@{ vendor = "Elastic"; product = "Elastic Defend"; type = "endpoint" }
        host = [PSCustomObject]@{
            name = "not_nics_machine"
            hostname = "not_nics_machine"
            os = [PSCustomObject]@{ name = "Microsoft Windows"; type = "windows"; platform = "windows"; version = "10.0" }
        }
        process = [PSCustomObject]@{
            name = "calc.exe"
            executable = "C:\Windows\System32\calc.exe"
            command_line = "C:\Windows\System32\calc.exe"
            pid = $processId
            entity_id = "{$([guid]::NewGuid())}"
            parent = [PSCustomObject]@{ name = "explorer.exe"; executable = "C:\Windows\explorer.exe"; pid = 1337 }
        }
        source = [PSCustomObject]@{ address = $sourceIp; ip = $sourceIp; port = $sourcePort; domain = "workstation.lab" }
        destination = [PSCustomObject]@{ address = $destinationIp; ip = $destinationIp; port = 443; domain = $domain }
        url = [PSCustomObject]@{ domain = $domain; full = "https://$domain/telemetry/client/$Sequence"; scheme = "https" }
        network = [PSCustomObject]@{ direction = "egress"; transport = "tcp"; protocol = "https" }
        related = [PSCustomObject]@{ ip = @($sourceIp, $destinationIp); hosts = @("workstation.lab", $domain) }
    } | ConvertTo-Json -Depth 10 -Compress
}

function challenge {
    # This function is designed to be executed in the context of the "Calculated!" challenge. It performs the necessary steps to import data into the Elastic Stack environment.
    # Create a document in the Elastic Stack that will be detected by the Calculator Connection rule.
    $dateRandom = (Get-Date -AsUTC).AddSeconds(-(Get-Random -Minimum 7200 -Maximum 2592001)).ToString("o")
    $challenge = [PSCustomObject]@{
        '@timestamp' = $dateRandom
        message = "Network connection detected"
        tags = @("network", "sysmon", "endpoint")
        ecs = [PSCustomObject]@{
            version = "9.5.0"
        }
        event = [PSCustomObject]@{
            action = "connection_attempt"
            category = @("network")
            kind = "event"
            type = @("connection")
            outcome = "unknown"
            provider = "Microsoft-Windows-Sysmon"
            code = "3"
            created = $dateRandom
            ingested = (Get-Date -AsUTC).ToString("o")
        }
        agent = [PSCustomObject]@{
            type = "endpoint"
            name = "elastic-agent"
            version = "9.5.3"
        }
        observer = [PSCustomObject]@{
            vendor = "Elastic"
            product = "Elastic Defend"
            type = "endpoint"
        }
        host = [PSCustomObject]@{
            name = "not_nics_machine"
            hostname = "not_nics_machine"
            os = [PSCustomObject]@{
                name = "Microsoft Windows"
                type = "windows"
                platform = "windows"
                version = "10.0"
            }
        }
        process = [PSCustomObject]@{
            name = "calc.exe"
            executable = "C:\Windows\System32\calc.exe"
            command_line = "C:\Windows\System32\calc.exe"
            pid = 4268
            entity_id = "{8f4d2c10-9e75-4d8e-a9a1-calc4268}"
            parent = [PSCustomObject]@{
                name = "scvhost.exe"
                executable = "C:\Users\Default\AppData\Local\Temp\System32\scvhost.exe"
                pid = 1180
            }
        }
        source = [PSCustomObject]@{
            address = "10.42.7.23"
            ip = "10.42.7.23"
            port = 51742
            domain = "workstation.lab"
        }
        destination = [PSCustomObject]@{
            address = "198.51.100.42"
            ip = "198.51.100.42"
            port = 443
            domain = "updates.secureyodomainfool.net"
        }
        url = [PSCustomObject]@{
            domain = "updates.secureyodomainfool.net"
            full = "https://updates.secureyodomainfool.net/update?q=99,116,102,95,99,97,108,99,95,103,111,101,115,95,116,104,101,95,119,101,97,115,101,108"
            scheme = "https"
        }
        network = [PSCustomObject]@{
            direction = "egress"
            transport = "tcp"
            protocol = "https"
        }
        related = [PSCustomObject]@{
            ip = @("10.42.7.23", "198.51.100.42")
            hosts = @("workstation.lab", "updates.secureyodomainfool.net")
        }
    } | ConvertTo-Json -Depth 10 -Compress

    $redHerrings = @(1..99 | ForEach-Object { New-CalcNetworkRedHerring -Sequence $_ })
    $documents = @($redHerrings + $challenge)
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $documents -batchSize 100

    return Write-Debug "✅ elastic_import_script.ps1 executed"
}
