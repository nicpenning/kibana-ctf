# Advanced Elastic Stack Import Script for Challenge: But wait, there's moar.
function challenge {
    # Create the process-create event that explains where calc.exe came from.
    $dateRandom = (Get-Date -AsUTC).AddSeconds(-(Get-Random -Minimum 2592002 -Maximum 5184001)).ToString("o")
    $challenge = [PSCustomObject]@{
        '@timestamp' = $dateRandom
        message = "SCV ready! Supply depot complete. scvhost.exe spawned calc.exe."
        tags = @("process", "sysmon", "endpoint", "terran", "scv")
        ecs = [PSCustomObject]@{
            version = "9.5.0"
        }
        event = [PSCustomObject]@{
            action = "process_started"
            category = @("process")
            kind = "event"
            type = @("start")
            outcome = "success"
            provider = "Microsoft-Windows-Sysmon"
            code = "1"
            created = $dateRandom
            ingested = (Get-Date -AsUTC).ToString("o")
        }
        agent = [PSCustomObject]@{
            type = "endpoint"
            name = "elastic-agent"
            version = "9.5.4"
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
            name = "scvhost.exe"
            executable = "C:\Users\Default\AppData\Local\Temp\System32\scvhost.exe"
            command_line = "C:\Users\Default\AppData\Local\Temp\System32\scvhost.exe --build-order supply-depot --rally-point vespene --payload 7b,63,74,66,5f,61,70,74,5f,33,31,33,33,37,5f,6d,6f,61,72,5f,76,65,73,70,65,6e,65,5f,67,61,73,5f,69,73,5f,72,65,71,75,69,72,65,64,7d"
            args = @(
                "C:\Users\Default\AppData\Local\Temp\System32\scvhost.exe",
                "--build-order", "supply-depot",
                "--rally-point", "vespene",
                "--payload", "7b,63,74,66,5f,61,70,74,5f,33,31,33,33,37,5f,6d,6f,61,72,5f,76,65,73,70,65,6e,65,5f,67,61,73,5f,69,73,5f,72,65,71,75,69,72,65,64,7d"
            )
            pid = 1180
            entity_id = "{8f4d2c10-9e75-4d8e-a9a1-scv1180}"
            parent = [PSCustomObject]@{
                name = "explorer.exe"
                executable = "C:\Windows\explorer.exe"
                pid = 1337
            }
        }
    } | ConvertTo-Json -Depth 10

    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $challenge

    return Write-Debug "✅ elastic_import_script.ps1 executed"
}
