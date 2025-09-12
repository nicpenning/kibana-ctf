function challenge {
    # Lookup mode settings
    $lookupSettings = '{"settings": {"index": {"mode": "lookup"}}}'

    # Create threat-related documents
    $docA1 = [PSCustomObject]@{
        '@timestamp' = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
        ip = "192.168.1.100"
        file = @{ name = "evil.exe"}
        alert = "Malicious file detected"
    } | ConvertTo-Json
    $docA2 = [PSCustomObject]@{
        '@timestamp' = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
        ip = "10.0.0.5"
        file = @{ name = "normal.docx"}
        alert = "Benign file"
    } | ConvertTo-Json

    # Ingest threat-related documents
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $docA1
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $docA2

    # Create join-threat-data lookup index
    $result = Invoke-RestMethod -Method PUT -Uri "$Elasticsearch_URL/join-threat-data" -Body $lookupSettings -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck

    # Create logs-join-b index and add threat-related documents
    $docB1 = [PSCustomObject]@{
        '@timestamp' = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
        ip = "192.168.1.100"
        file = @{ name = "evil.exe"}
        threat_level = "high"
        description = "This is a super evil malware binary, beware! e2N0Zl9qb2luaW5nX2lzX3Bvd2VyZnVsfQ=="
    } | ConvertTo-Json
    $docB2 = [PSCustomObject]@{
        '@timestamp' = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
        ip = "10.0.0.5"
        file = @{ name = "normal.docx"}
        threat_level = "low"
        description = "Typical word document that isn't too sus. Z2ltbWVfZGFfbG9ncw=="
    } | ConvertTo-Json
    
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $docB1 -customUrl "$Elasticsearch_URL/join-threat-data/_doc/1"
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $docB2 -customUrl "$Elasticsearch_URL/join-threat-data/_doc/2"
    Write-Host "Join challenge data imported." -ForegroundColor Green
}
