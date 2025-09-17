function challenge {
    $futureDate = ($(Get-Date -AsUTC).AddYears(30)).ToString("o")
    $challenge = [PSCustomObject]@{
        '@timestamp' = $futureDate
        message = "hello from the future"
        custom_field = "{ctf_where_we_goin_we_dont_need_roads}"
    } | ConvertTo-Json
    
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $challenge

    return Write-Debug "✅ elastic_import_script.ps1 executed"
}