function challenge {
    $dateNow = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
    $challenge = [PSCustomObject]@{
        '@timestamp' = $dateNow
        message = "This log contains a secret flag, almost: {ctf_regex_for_the_win_`$matchMe}"
        host = [PSCustomObject]@{
            name = "regex_machine"
        }
        process = [PSCustomObject]@{
            name = "regex.exe"
            command_line = "`$matchMe = '(:|\:)(-)(\)|\))'; run --pattern-match `$matchMe"
        }
    } | ConvertTo-Json

    Invoke-Ingest-Elasticsearch-Documents -documentToIngest $challenge

    return Write-Host "Challenge 16 imported." -ForegroundColor Green
}
