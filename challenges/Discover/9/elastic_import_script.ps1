function challenge {
    $dateNow = ($(Get-Date -AsUTC)).ToString("o")
    $challenge = [PSCustomObject]@{
        '@timestamp' = $dateNow
        message = "Just a regular event log, nothing to see here."
        tags = @("e2","N0","Zl","9o","YX","lf","aW","5f","dG","hl","X2","5l","ZW","Rs","ZV","9z","dG","Fj","a3","0=")
    } | ConvertTo-Json

    $count = 0
    do{
        $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $challenge
        $count++
    }while($count -lt 100)

    return Write-Host "Challenge 9 imported." -ForegroundColor Green
}