<#
.Synopsis
    This script is designed to setup the Kibana CTF created by Nicholas Penning. The goal of the script is to ease the
    setup process of deploying CTFd and an Elastic Stack for trying out this CTF. The latest versions of Elasticsearch,
    Kibana, and CTFd will be used. https://github.com/nicpenning/kibana-ctf

.DESCRIPTION
    This script is designed to setup the Kibana CTF created by Nicholas Penning. The goal of the script is to ease the
    setup process of deploying CTFd and an Elastic Stack for trying out this CTF. The latest versions of Elasticsearch,
    Kibana, and CTFd will be used. The script will provide many options such as deploying CTFd, the Elastic stack and
    importing the challenges into CTFd and the appropriate challenges into the Elastic stack. 

    WARNING: Challenges may be revealed if inspecting certain files in this project. Trust is the only layer between
    seeing and not seeing the challenge solutions. With this, if you are hosting this CTF, it is possible for players
    to find this repo and reveal all solutions. Honesty is the best policy here. The plan is to randomize the flags to
    keep make it a bit harder to reveal the secrets, but that won't stop persistant users to reveal all flags and
    solutions. Please don't spoil the fun!! :D

    Requirements:
        1. Internet Access (At least elastic.co & github.com)
        2. CTFd Instance (Token needs to be manually created and retrieved)
        3. Elasticsearch and Kibana Instance

    Tested for Elastic Stack 8.17+/9.0+ and CTFd 3.7.4+

    Variable Options
    -Elasticsearch_URL "https://127.0.0.1:9200"
    -Kibana_URL "http://127.0.0.1:5601"
    -CTFd_URL "http://127.0.0.1:8000"
    -CTF_Start_Date "12/24/2024 12:00 PM" (default - Now) # To do
    -CTF_End_Date "12/24/2024 1:00 PM" (default - 1 hour from Start Date) # To do
    -CTFd_Randomize_Flags "False" (default False) # To do

.EXAMPLE
   .\Invoke-Kibana-CTF-Setup.ps1 -Elasticsearch_URL "http://127.0.0.1:9200" -Kibana_URL "https://127.0.0.1:5601" -CTFd_URL "http://127.0.0.1:8000" -CTF_Start_Date "12/24/2024 12:00 PM" -CTF_End_date "12/24/2024 3:00PM"
#>

Param (
    # -Elasticsearch URL. (default - https://127.0.0.1:9200)
    [Parameter(Mandatory=$false)]
    $Elasticsearch_URL = "https://127.0.0.1:9200",

    # Kibana URL. (default - http://127.0.0.1:5601)
    [Parameter(Mandatory=$false)]
    $Kibana_URL = "http://127.0.0.1:5601",
    
    # CTFd URL. (default - http://127.0.0.1:8000)
    [Parameter(Mandatory=$false)]
    $CTFd_URL = "http://127.0.0.1:8000",

    # CTF Start Date. (default - Now - To Do)
    [Parameter(Mandatory=$false)]
    $CTF_Start_Date = $([Math]::Floor([System.DateTimeOffset]::Now.ToUnixTimeSeconds())),

    # CTF End Date URL. (default - 1 hour from Start Date - To Do)
    [Parameter(Mandatory=$false)]
    $CTF_End_Date = $([math]::Round(($((Get-Date).AddHours(1)).ToUniversalTime() - [datetime]'1970-01-01T00:00:00Z').TotalSeconds)),

    # Random CTF flags to make answer unique everytime. (default - false - To Do - NOT USABLE)
    [Parameter(Mandatory=$false)]
    $CTFd_Randomize_Flags = "false" 
)

Begin {

    # CTFd Variables
    $CTFd_URL_API = $CTFd_URL+"/api/v1"

    # CTFd config.ini path
    $ctfd_iniPath = "..\CTFd\CTFd\config.ini"

    # Extract custom settings from configuration.psd1
    $configPath = "./configuration.psd1"
    $configurationSettings = Import-PowerShellDataFile $configPath 
    
    if($configurationSettings.Elasticsearch_URL -ne "https://127.0.0.1:9200"){
        $Elasticsearch_URL = $configurationSettings.Elasticsearch_URL
        Write-Host "💾 Modifed Elasticsearch URL detected in configuration.psd1, using $Elasticsearch_URL" -ForegroundColor Yellow
    }
    if($configurationSettings.Kibana_URL -ne "http://127.0.0.1:5601"){
        $Kibana_URL = $configurationSettings.Kibana_URL
        Write-Host "💾 Modifed Kibana URL detected in configuration.psd1, using $Kibana_URL" -ForegroundColor Yellow
    }
    # Elasticsearch Variables
    $indexName = "logs-kibana-ctf"
    $ingestIndexURL = $Elasticsearch_URL+"/$indexName/_doc"
    $ingestBulkIndexURL = $Elasticsearch_URL+"/$indexName/_bulk"
    $indexTemplateURL = $Elasticsearch_URL+"/_index_template/$indexName"
    $ctfUserRoleURL = $Elasticsearch_URL+"/_security/role/Kibana CTF"
    $ctfUserCreateURL = $Elasticsearch_URL+"/_security/user/kibana-ctf"
    $indexTemplate = Get-Content ./setup/Elastic/index_template.json
    $ctfUserRole = Get-Content ./setup/Elastic/kibana_ctf_role.json
    $ctfUserCreate = Get-Content ./setup/Elastic/kibana_ctf_user.json
    $kibanaCTFSpace = Get-Content ./setup/Elastic/kibana_ctf_space.json

    # Custom Function for updating PowerShell Data Files (.psd1)
    function Update-Psd1Value {
        [CmdletBinding(DefaultParameterSetName = 'Direct')]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path,

            [Parameter(Mandatory = $true)]
            [string]$Key,

            [Parameter(ParameterSetName = 'Direct', Mandatory = $true)]
            [object]$Value,

            [Parameter(ParameterSetName = 'Prompt', Mandatory = $true)]
            [switch]$Prompt,

            [Parameter(ParameterSetName = 'Prompt')]
            [switch]$AsSecureString
        )

        if (-not (Test-Path $Path)) {
            throw "❌ PSD1 file not found: $Path"
        }

        try {
            # Load PSD1 as hashtable
            $config = Import-PowerShellDataFile -Path $Path

            # If prompting is enabled
            if ($PSCmdlet.ParameterSetName -eq 'Prompt') {
                if ($AsSecureString) {
                    $Value = Read-Host "Enter value for [$Key]" -AsSecureString |
                        ForEach-Object { [System.Net.NetworkCredential]::new("", $_).Password }
                } else {
                    $Value = Read-Host "Enter value for [$Key]"
                }
            }

            # Update/Add the key
            $config[$Key] = $Value

            # Rebuild PSD1 as text (no extra trailing lines)
            $lines = @("@{")
            foreach ($k in ($config.Keys | Sort-Object)) {
                $v = $config[$k]

                if ($v -is [string]) {
                    $escaped = $v.Replace("'", "''")
                    $lines += "    $k = '$escaped'"
                }
                elseif ($v -is [bool]) {
                    $lines += "    $k = $($v.ToString().ToLower())"
                }
                else {
                    $lines += "    $k = $v"
                }
            }
            $lines += "}"

            # Write back to file (no trailing newline)
            #[System.IO.File]::WriteAllLines($Path, $lines, [System.Text.Encoding]::UTF8)
            Set-Content -Path (Resolve-Path $Path) -Value $lines -Encoding UTF8 -Force

            Write-Host "✅ Updated [$Key] in $Path" -ForegroundColor Green
        }
        catch {
            throw "❌ Failed to update PSD1 file: $_"
        }
    }

    function Get-CTFd-Creds {
        # Check for existing token in configuration.psd1
        $configurationSettings = Import-PowerShellDataFile $configPath

        # Check for token
        if ($configurationSettings.ContainsKey("CTFd_Access_Token") -and `
            -not [string]::IsNullOrWhiteSpace($configurationSettings.CTFd_Access_Token) -and `
            -not ($configurationSettings.CTFd_Access_Token -eq "ctfd_access_token")) {

            $CTFd_Access_Token = $configurationSettings.CTFd_Access_Token
            Write-Host "🚩 CTFd Access Token detected in $ConfigPath" -ForegroundColor Green
        } else {
            Write-Host "`n🗝️ Access Token can be generated here:" -ForegroundColor Cyan
            Write-Host "   http://127.0.0.1:8000/settings -> Access Tokens -> Set Expiration -> Generate" -ForegroundColor Cyan

            $CTFd_Access_Token = Read-Host "Enter the token for the administrator account. Starts with ctfd_" -MaskInput

            # Persist with helper function
            try{
                Update-Psd1Value -Path $configPath -Key "CTFd_Access_Token" -Value $CTFd_Access_Token
            }catch{
                Write-Host "❌ Failed to update the configuration.psd1 file with the CTFd Access Token." -ForegroundColor Red
            }

            Write-Host "💾 CTFd Access Token saved to $configPath for future use." -ForegroundColor Green
        }

        return $CTFd_Access_Token
    }

    function Invoke-Setup-CTFd-Preset-Admin {
        param(
            [string]$ctfName = "Kibana CTF"
        )
        # Read the INI file into memory
        $iniContent = Get-Content $ctfd_iniPath -Raw

        # Helper to generate a secure random string
        function New-SecureString {
            param(
                [int]$Length = 32
            )
            $bytes = New-Object byte[] $Length
            [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)

            # URL-safe base64 (good for passwords/tokens)
            return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
        }

        # Generate values
        $CTFd_Admin_User   = "ctfd_admin"
        $CTFd_Admin_Pass   = New-SecureString -Length 32
        $CTFd_Access_Token  = "ctfd_"+$(New-SecureString -Length 48)   # API tokens usually longer
        $CTFd_Preset_Configs = '{"setup": "true","ctf_name": "' + $ctfName + '"}'

        # Update text directly using regex (reliable for INI files)
        $iniContent = $iniContent -replace "(?m)^PRESET_ADMIN_NAME\s*=.*","PRESET_ADMIN_NAME = $CTFd_Admin_User"
        $iniContent = $iniContent -replace "(?m)^PRESET_ADMIN_PASSWORD\s*=.*","PRESET_ADMIN_PASSWORD = $CTFd_Admin_Pass"
        $iniContent = $iniContent -replace "(?m)^PRESET_ADMIN_TOKEN\s*=.*","PRESET_ADMIN_TOKEN = $CTFd_Access_Token"
        $iniContent = $iniContent -replace "(?m)^PRESET_CONFIGS\s*=.*","PRESET_CONFIGS = $CTFd_Preset_Configs"

        # Save the updated INI file with generated credentials
        Set-Content -Path $ctfd_iniPath -Value $iniContent

        # Store CTFd Access Token in configuration.psd1
        try{
            Set-Location ../kibana-ctf
            Update-Psd1Value -Path $configPath -Key "CTFd_Access_Token" -Value $CTFd_Access_Token
            Set-Location ../CTFd
            Write-Host "💾 CTFd Access Token saved to $configPath for future use." -ForegroundColor Green
        }catch{
            Write-Host "❌ Failed to update the configuration.psd1 file with the CTFd Access Token." -ForegroundColor Red
            Set-Location ../CTFd
        }

        Write-Host "Finished setting CTFd preset admin credentials, make sure to copy these values for later use."
        Write-Host "    Username: $CTFd_Admin_User"
        Write-Host "    Password: $CTFd_Admin_Pass"
        Write-Host "Access Token: $CTFd_Access_Token"
        pause
    }
    
    function Get-Elastic-Creds {
        return Get-Credential -Message "Enter the credentials for the elastic stack, recommended to use the default elastic account"
    }
    
    function Get-Challenges-From-CTFd {
        return Invoke-RestMethod -Method GET "$CTFd_URL_API/challenges" -ContentType "application/json" -Headers $ctfd_auth
    }

    function Get-CTFd-Admin-Token {
        $ctfd_token = Get-CTFd-Creds
        $ctfd_auth = @{"Authorization" = "Token $ctfd_token"}

        # Validate auth
        try{
            $validate = Invoke-RestMethod -Method GET -Uri "$CTFd_URL_API/pages" -ContentType "application/json" -Headers $ctfd_auth
            if($validate){
                Write-Host "✅ Valid CTFd token provided!" -ForegroundColor Green
            }else{
                Write-Host "❌ Could not validate, try another token or checking your connection to $CTFd_URL_API/pages endpoint."
            }
        }catch{
            Write-Host "Could not validate token, exiting." -ForegroundColor Red
            Write-Debug $_.Exception
            exit
        }
        return $ctfd_auth
    }

    function Invoke-Import-CTFd-Challenge {
        param(
            $challenge_file_path
        )
        $ctfd_challenge = Get-Content $challenge_file_path | ConvertFrom-Json -Depth 10
        # Set connection info
        $ctfd_challenge.connection_info = $ctfd_challenge.connection_info.Replace("http://127.0.0.1:5601",$Kibana_URL)

        Write-Debug "Importing challenge: $($ctfd_challenge.name)"
        $current_challenge = $ctfd_challenge | ConvertTo-Json -Depth 10
        try{
            $import_challenge = Invoke-RestMethod -Method POST "$CTFd_URL_API/challenges" -ContentType "application/json" -Headers $ctfd_auth -Body $current_challenge
            Write-Host "✅ Imported challenge $($ctfd_challenge.name) - $($import_challenge.success)"
        }catch{
            Write-Host "❌ Could not import challenge: $($ctfd_challenge.name) - $($ctfd_challenge.id)"
            Write-Debug $_.Exception
        }
    }

    function Invoke-Import-CTFd-Flag {
        param(
            $flag_file_path
        )
        $ctfd_flag = Get-Content $flag_file_path | ConvertFrom-Json -Depth 10
    
        # Customize Flag : To Do

        $ctfd_flag | ForEach-Object {
            # Get current flag
            $current_flag = $_ | ConvertTo-Json -Compress

            Write-Debug "Importing flags for Challenge ID: $($ctfd_flag.challenge_id)"
            try{
                $import_flag = Invoke-RestMethod -Method POST "$CTFd_URL_API/flags" -ContentType "application/json" -Headers $ctfd_auth -Body $current_flag
                Write-Debug "✅ Imported flag $($_.id) - $($import_flag.success)"
            }catch{
                Write-Host "❌ Could not import flag: $($current_challenge.name) - $($_.id)"
                Write-Debug $_.Exception
            }

            if($CTFd_Randomize_Flags -match "true"){
                Write-Host "Randomizing the the last part of the flag."
                Invoke-Random-Hex-String
            }
        
        }
    }

    function Invoke-Import-CTFd-Hint {
        param(
            $hint_file_path
        )
        $ctfd_hint = Get-Content $hint_file_path | ConvertFrom-Json -Depth 10

        # Get current hint
        $current_hint = $ctfd_hint | ConvertTo-Json -Compress

        Write-Debug "Importing hint for Challenge ID: $($ctfd_hint.challenge_id)"
        try{
            $import_hints = Invoke-RestMethod -Method POST "$CTFd_URL_API/hints" -ContentType "application/json" -Headers $ctfd_auth -Body $current_hint
            Write-Debug "✅ Imported hint $($_.id) - $($import_hints.success)"
        }catch{
            Write-Host "❌ Could not import hint: $($_.id) for challenge id: $($ctfd_hint.challenge_id)"
            Write-Debug $_.Exception
        }
    }

    # Elastic Stack Setup Functions
    function Invoke-CheckForEnv {
        # Check for existing .env file for setup
        # Get Elasticsearch password from .env file
        if (Test-Path .\setup\Elastic\docker_elastic_stack\.env) {
            Write-Host "🐳 Docker .env file detected. Extracting credentials for intialization."
            $env = Get-Content .\setup\Elastic\docker_elastic_stack\.env
            $regExEnv = $env | Select-String -AllMatches -Pattern "ELASTIC_PASSWORD='(.*)'"
            $global:elasticsearchPassword = $regExEnv.Matches.Groups[1].Value
            if ($elasticsearchPassword) {
                Write-Host "🔐 Password for user elastic has been found and will be used." -ForegroundColor Green
                return "True", $elasticsearchPassword
            }
        } else {
            Write-Debug "No .env file detected in \docker\.env"
            return "False"
        }
    }
    
    function Invoke-CheckForDockerInUse {
        # Check to see if docker compose job is already running before starting it up again
        Write-Host "Checking to make sure Docker isn't already running."
        $jobs = Get-Job
        $dockerInUse = $($jobs.Command | ForEach-Object { $_ | select-string "docker compose up" })
        if ($dockerInUse) {
            Write-Host "🐳 Docker found to be running" -ForegroundColor Yellow
            return "True"
        } else {
            Write-Debug "Docker was not found to be running"
            return "False"
        }
    }
    
    function Invoke-CheckForElasticsearchStatus {
        # Check for Elastic stack connectivity to a healthy cluster
        Write-Host "🔎 Waiting for Elasticsearch to be accessible."
    
        $healthAPI = $Elasticsearch_URL+"/_cluster/health"
        Write-Debug "Using the URL: $healthAPI"
        # Keep checking for a healthy cluster that can be used for the initialization process!
        do {
            $trys = 0
            try {
                Write-Debug "Checking to see if the cluster is accessible. Please wait. If this takes more than a minute, make sure Elasticsearch is available."
                $status = Invoke-RestMethod -Method Get -Uri $healthAPI -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck  
            } catch {
                Write-Debug "Waiting for healthy cluster for 5 seconds. Then checking again."
                Write-Debug $_.Exception
                $status
                Start-Sleep -Seconds 5
                $trys++
                if($trys -gt 12){
                    Write-Host "❌ Could not connect to the Elastic cluster. Please make sure it is running and the credentials are correct." -ForegroundColor Red
                    exit
                }
            }
        } until ("yellow" -eq $status.status -or "green" -eq $status.status)
    
        if ("yellow" -eq $status.status -or "green" -eq $status.status) {
            Write-Host "⚙️ Elastic cluster is $($status.status), continuing through the setup process."
            Start-Sleep -Seconds 2
        }
    }

    function Invoke-CheckForKibanaStatus {
        param(
            [string]$KibanaUrl = $Kibana_URL,
            [pscredential]$Credential,
            [int]$MaxRetries = 6,        # number of attempts
            [int]$InitialDelay = 5       # starting delay in seconds
        )

        $attempt = 0
        $delay = $InitialDelay

        while ($attempt -lt $MaxRetries) {
            try {
                Write-Host "🌐 Checking Kibana health at $KibanaUrl (Attempt $($attempt+1)/$MaxRetries)..." -ForegroundColor Cyan

                # Prepare Authorization header if credentials provided
                $headers = @{}
                if ($Credential) {
                    $plainCreds   = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
                    $encodedCreds = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plainCreds))
                    $headers["Authorization"] = "Basic $encodedCreds"
                }

                # Call the status API and parse JSON
                $resp = Invoke-RestMethod -Uri ("{0}/api/status" -f $KibanaUrl) -Headers $headers -TimeoutSec 10 -ErrorAction Stop -SkipCertificateCheck

                # Newer Kibana uses `status.overall.level` (e.g. "available")
                $level = $null
                if ($resp -and $resp.status -and $resp.status.overall -and $resp.status.overall.level) {
                    $level = $resp.status.overall.level
                }

                if ($level -eq "available") {
                    Write-Host "✅ Kibana is: $level." -ForegroundColor Green
                    return $true
                } elseif ($level) {
                    Write-Host "⚠️ Kibana responded but is not 'available'. Level: $level" -ForegroundColor Yellow
                    # continue to retry in case it moves to available
                } else {
                    Write-Host "❌ Unexpected response from Kibana status API." -ForegroundColor Red
                    Write-Host "Response preview: $($resp | ConvertTo-Json -Depth 3)" -ForegroundColor DarkGray
                }
            } catch {
                Write-Host "⚠️ Kibana not yet reachable at $KibanaUrl (attempt $($attempt+1)). Message: $($_.Exception.Message)" -ForegroundColor Yellow
            }

            $attempt++
            if ($attempt -lt $MaxRetries) {
                Write-Host "⏳ Waiting $delay seconds before retry..." -ForegroundColor Cyan
                Start-Sleep -Seconds $delay
                $delay *= 2
            }
        }

        Write-Host "❌ Kibana did not become available after $MaxRetries attempts." -ForegroundColor Red
        return $false
    }

    function Invoke-CheckForInUsePorts {
        $ports = @("9200", "5601")
        Write-Host "🔎 Checking for Elasticsearch (9200) and Kibana (5601) ports being in use before starting docker."
        $portsInUse = @()
        foreach ($port in $ports) {
            $testConnection = Test-Connection -TargetName "localhost" -TcpPort $port
            if ($testConnection) {
                Write-Debug "Port $port is in use."
                $portsInUse += $port
            } else {
                Write-Debug "Port $port is not in use."
            }
        }
        if($portsInUse){
            return $portsInUse
        }else{
            return $false
        }
    }
    
    function Invoke-StartDocker {
        # Check to see if Linux to set VM Max Map Count to ensure Elasticsearch can start
        if($IsLinux) {
            Write-Host "Linux OS detected, setting VM Max Map Count to 262144"
            sudo sysctl -w vm.max_map_count=262144
        }
        
        #Check to see if Docker on Windows
        if($IsWindows) {
            $dockerWSL2 = docker info | Select-String "WSL2"
        
            #Check to see if Docker on Windows is using WSL2 and configure accordingly
            if($dockerWSL2){
                Write-Host "Docker install was detected using WSL2, so an additional setting needs to be configured for memory consumption."
                $wslMaxMem = Read-Host "The following file will be created: "$ENV:USERPROFILE\.wslconfig" `nWould you like to continue?`n1. Yes`n2. No, exit`n(Enter 1 or 2)"
                if($wslMaxMem -eq 1){
                    $maxmem = @"
        [wsl2]
        kernelCommandLine = "sysctl.vm.max_map_count=262144"
"@
                    Write-Host "Creating file $ENV:USERPROFILE\.wslconfig with the contents of:$maxmem"
                    try{
                        $maxmem | Out-File "$ENV:USERPROFILE\.wslconfig"
                        Write-Host "✅ File created!" -ForegroundColor Green
                    }catch{
                        Write-Host "⚠️ File could not be created." -ForegroundColor Red
                    }
                }else{
                    Write-Host "❌ Required WSL file was not created, exiting."
                    Exit
                }
            }else{
                Write-Host "⚠️ Docker install was not detected using WSL2 so you might need to adjust your docker settings to allow additional RAM usage for this setup to work."
                Write-Host "❌ If Elasticsearch never gets working then check your Docker containers to see if they exited and if so, check the logs and see why the failed and fix accordingly."
            }
        }
        
        Write-Host "⏳ Starting up the Elastic stack with docker, please be patient as this can take over 10 minutes to download and deploy the entire stack if this is the first time you executed this step.`nOtherwise this will take just a couple of minutes."
        Set-Location .\setup\Elastic\docker_elastic_stack
        try {
            $composeVersion = docker compose version
            if($composeVersion){
                Write-Debug '"docker compose detected"'
                $checkInUsePorts = Invoke-CheckForInUsePorts
                if($checkInUsePorts){
                    Write-Host "❌ Ports detected already in use. Make sure these ports are available before continuing. Exiting."
                    Set-Location ..\..\..\
                    exit
                }else{
                    docker compose up -d
                }
                Write-Host "✅ Elastic Stack containers started, navigate to $Kibana_URL to ensure it started okay.`nNote: It could a few minutes to get the Elastic stack running so be patient.)" -ForegroundColor Green
            }else{
                Throw '"docker compose" not detected, will now check for docker-compose'
            }
        } catch {
            Write-Debug "docker compose up -d failed - trying docker-compose up -d"
            try {
                $dockerComposeVersion = docker-compose version
                if($dockerComposeVersion){
                    Write-Debug '"docker-compose detected"'
                    docker-compose up -d
                }else{
                    Throw '"docker-compose" not detected.'
                }
            } catch {
                Write-Host "❌ docker compose up -d or docker-compose up -d did not work. Check that you have docker and docker composed installed."
            }
        }
        Set-Location ..\..\..\
    }
    
    function Invoke-StopDocker {
        Write-Debug "Shutting down docker containers for the Elastic stack."
        Set-Location .\setup\Elastic\docker_elastic_stack
        try { 
            docker compose down
        } catch {
            Write-Host "⚠️ Failed to use docker compose down, so trying docker-compose down."
            docker-compose down
        }
        Set-Location ..\..\..\
    }

    function Import-SavedObject {
        Param (
            $filename
        )
        
        $importSavedObjectsURL = $Kibana_URL+"/s/kibana-ctf/api/saved_objects/_import?overwrite=true"
        $kibanaHeader = @{"kbn-xsrf" = "true"; "Authorization" = "$kibanaAuth"}
        $savedObjectsFilePath =  Resolve-Path $filename
    
        $fileBytes = [System.IO.File]::ReadAllBytes($savedObjectsFilePath.path);
        $fileEnc = [System.Text.Encoding]::GetEncoding('UTF-8').GetString($fileBytes);
        $boundary = [System.Guid]::NewGuid().ToString(); 
        $LF = "`r`n";
    
        $bodyLines = ( 
            "--$boundary",
            "Content-Disposition: form-data; name=`"file`"; filename=`"saved_object.ndjson`"",
            "Content-Type: application/octet-stream$LF",
            $fileEnc,
            "--$boundary--$LF" 
        ) -join $LF
    
        $result = Invoke-RestMethod -Method POST -Uri $importSavedObjectsURL -Headers $kibanaHeader -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines -AllowUnencryptedAuthentication -SkipCertificateCheck
        if($result.errors -or $null -eq $result){
            Write-Host "❌ There was an error trying to import $filename"
            $result.errors
        }else{
            Write-Debug "✅ Imported $filename"
        }
    }

    function Invoke-Create-Kibana-CTF-Space {
        Param(
            $Kibana_URL
        )

        $createKibanaCTFSpaceURL = $Kibana_URL+"/api/spaces/space"
        $deleteKibanaCTFSpaceURL = $Kibana_URL+"/api/spaces/space/kibana-ctf"
        $kibanaHeader = @{"kbn-xsrf" = "true"; "Authorization" = "$kibanaAuth"}

        $kibanaCTFSpace = Get-Content ./setup/Elastic/kibana_ctf_space.json

        # Create the space!
        try{
            $result = Invoke-RestMethod -Method POST -Uri $createKibanaCTFSpaceURL -Headers $kibanaHeader -ContentType "application/json" -Body $kibanaCTFSpace -AllowUnencryptedAuthentication -SkipCertificateCheck
        }catch{
            # Delete and try again if Kibana CTF Space already exists.
            Write-Host "⚠️ Failed to create the Kibana CTF space. Going to delete it if it exists and try to create it again." -ForegroundColor Yellow
            Invoke-RestMethod -Method DELETE -Uri $deleteKibanaCTFSpaceURL -Headers $kibanaHeader -ContentType "application/json" -AllowUnencryptedAuthentication -SkipCertificateCheck
            $result = Invoke-RestMethod -Method POST -Uri $createKibanaCTFSpaceURL -Headers $kibanaHeader -ContentType "application/json" -Body $kibanaCTFSpace -AllowUnencryptedAuthentication -SkipCertificateCheck
        }

        if($result.errors -or $null -eq $result){
            Write-Host " ❌There was an error trying to import the Kibana CTF Space." -ForegroundColor Yellow
            $result.errors
        }else{
            Write-Host "✅ Created Kibana CTF Space!"
        }
    }

    function Invoke-Create-Kibana-CTF-User-Role {
        try {
            Write-Host "`n🔧 Creating the Kibana CTF role..." -ForegroundColor Cyan
            $result = Invoke-RestMethod -Method PUT -Uri $ctfUserRoleURL -Body $ctfUserRole -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck

            Write-Host "✅ Kibana CTF role created successfully!" -ForegroundColor Green

            Write-Host "`n👥 This role will be assigned to all CTF players to ensure they have the right access in Kibana." -ForegroundColor Blue
            Write-Host "   (No admin privileges here — just enough to compete fairly!)" -ForegroundColor DarkGray
        } catch {
            Write-Host "❌ Couldn't create the Kibana CTF role." -ForegroundColor Red
            Write-Host "💡 Check Kibana to see if the role already exists." -ForegroundColor Yellow
            Write-Host "Error details: $_" -ForegroundColor DarkGray
        }
    }

    function Invoke-Create-Kibana-CTF-User {
        try {
            Write-Host "`n👤 Creating Kibana CTF user with the proper role mapping..." -ForegroundColor Cyan
            $result = Invoke-RestMethod -Method PUT -Uri $ctfUserCreateURL -Body $ctfUserCreate -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck

            Write-Host "✅ kibana-ctf user created successfully!" -ForegroundColor Green

            Write-Host "`n🔑 Credentials for your shiny new Kibana CTF user:" -ForegroundColor Blue
            Write-Host "   Username : kibana-ctf" -ForegroundColor DarkCyan
            Write-Host "   Password : kibana-ctf--please-change-me" -ForegroundColor DarkCyan

            Write-Host "`n💡 Tip: If you want more players, log in as the 'elastic' superuser and create additional accounts." -ForegroundColor Yellow
            Write-Host "   Just remember to assign them the 'Kibana CTF' role so they can play!" -ForegroundColor Yellow

            Write-Host "`n🕹️ Test your new user by visiting:" -ForegroundColor Cyan
            Write-Host "   $Kibana_URL/s/kibana-ctf/app/home#/" -ForegroundColor Green
            Write-Host "   (Log in with kibana-ctf to confirm access)" -ForegroundColor DarkGray
        } catch {
            Write-Host "❌ Couldn't create kibana-ctf user." -ForegroundColor Red
            Write-Host "💡 Check Kibana to see if the user already exists." -ForegroundColor Yellow
            Write-Host "Error details: $_" -ForegroundColor DarkGray
        }
    }

    function Invoke-Ingest-Elasticsearch-Documents {
        Param (
            $documentToIngest,
            $customUrl,
            [int]$batchSize = 1
        )

        # Case 1: Custom URL (always use PUT)
        if ($null -ne $customUrl) {
            try {
                $result = Invoke-RestMethod -Method PUT -Uri $customUrl -Body $documentToIngest -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck -ErrorAction Stop
                return
            }
            catch {
                $errMsg = $_.ErrorDetails.Message

                if ($errMsg -match '"type": "version_conflict_engine_exception"') {
                    Write-Debug "ℹ️ Document already exists at $customUrl. Proceeding as normal."
                }
                else {
                    Write-Host "❌ Unexpected error ingesting $customUrl" -ForegroundColor Red
                    Write-Host $errMsg -ForegroundColor DarkRed
                    throw  # re-throw so the pipeline breaks on real issues
                }
            }
        }

        # Case 2: Bulk ingest
        if ($batchSize -gt 1) {
            $docs = if ($documentToIngest -is [System.Collections.IEnumerable]) { $documentToIngest } else { @($documentToIngest) }
            $count = 0

            foreach ($batch in ($docs | ForEach-Object -Begin { $tmp=@() } -Process {
                $tmp += $_
                if ($tmp.Count -ge $batchSize) { ,$tmp; $tmp=@() }
            } -End { if ($tmp.Count) { ,$tmp } })) {

                $bulkPayload = New-Object System.Text.StringBuilder
                foreach ($doc in $batch) {
                    [void]$bulkPayload.AppendLine("{""create"":{""_index"":""$indexName""}}")
                    [void]$bulkPayload.AppendLine($doc)
                    $count++
                }

                try {
                    $result = Invoke-RestMethod -Method POST -Uri "$ingestBulkIndexURL" -Body $bulkPayload.ToString() -ContentType "application/x-ndjson" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck
                    if ($count % 1000 -eq 0 -or $count -eq $docs.Count) { Write-Host "📦 Ingested $count / $($docs.Count) docs into [$indexName]" }
                } catch {
                    Write-Host "⚠️ Couldn't bulk ingest CTF data into [$indexName]." -ForegroundColor Yellow
                    Write-Debug "$_"
                }
            }
            return
        }

        # Case 3: Single doc ingest
        if (1 -le $batchSize -and $null -eq $customUrl) {
            try {
                $result = Invoke-RestMethod -Method POST -Uri "$ingestIndexURL" -Body $documentToIngest -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck
            } catch {
                Write-Host "Couldn't ingest CTF data into [$indexName]. If it already exists, this is okay." -ForegroundColor Yellow
                Write-Debug "$_"
            }
        }

        return
    }

    function Invoke-Create-Index-Template {
        try {
            Write-Host "`n📂 Creating Index Template for challenges..." -ForegroundColor Cyan
            $result = Invoke-RestMethod -Method PUT -Uri $indexTemplateURL -Body $indexTemplate -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck
            Write-Host "✅ Index Template created successfully!" -ForegroundColor Green
        } catch {
            Write-Host "❌ Couldn't create Index Template for CTF data." -ForegroundColor Red
            Write-Host "💡 Tip: Check Kibana to see if the Index Template already exists." -ForegroundColor Yellow
            Write-Host "Error details: $_" -ForegroundColor DarkGray
        }
    }

    function Invoke-Generate-FakeEvent {
        <#
        .SYNOPSIS
        Generates a fake event with nested fields for testing purposes. Compliments of ChatGPT.
        
        .DESCRIPTION
        This function creates a fake event with nested fields such as '@timestamp',
        'host' (with subfields 'name', 'ip', 'os'), and a 'message' field.
        The '@timestamp' is a random value between 7 days ago and now, precise to milliseconds.
    
        .EXAMPLE
        $event = Invoke-Generate-FakeEvent
        Write-Output $event
        #>
        param (
            [string[]]$OSTypes = @(
                "Linux Ubuntu",
                "Mac OS X",
                "Unix Solaris",
                "Windows 10",
                "iOS 14",
                "Android 11"
            ),
            [string[]]$OSVersions = @("10.0", "11.0", "22.04", "Monterey", "9.0", "12.1", "7.1.2"),
            [string[]]$Messages = @(
                "User login successful.",
                "File accessed.",
                "System update completed.",
                "Unauthorized access attempt detected.",
                "Scheduled task executed."
            )
        )
    
        # Generate a random timestamp between 7 days ago and now
        $startDate = (Get-Date).AddDays(-7).ToUniversalTime()
        $endDate = (Get-Date).ToUniversalTime()
    
        # Calculate the random timestamp in milliseconds
        $startMillis = $startDate.ToFileTimeUtc() / 10000
        $endMillis = $endDate.ToFileTimeUtc() / 10000
        $randomMillis = Get-Random -Minimum $startMillis -Maximum $endMillis
        $randomTimestamp = ([DateTime]::FromFileTimeUtc($randomMillis * 10000))
    
        # Generate random values for host fields
        $hostName = "host$(Get-Random -Minimum 1 -Maximum 1000)"
        $hostIP = "$((Get-Random -Minimum 10 -Maximum 255)).$((Get-Random -Minimum 0 -Maximum 255)).$((Get-Random -Minimum 0 -Maximum 255)).$((Get-Random -Minimum 0 -Maximum 255))"
        $hostOSName = $OSTypes | Get-Random
        $hostOSVersion = $OSVersions | Get-Random
        $message = $Messages | Get-Random
    
        # Create the event object with nested fields
        $event = @{
            '@timestamp' = $randomTimestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            'host' = @{
                'name' = $hostName
                'ip' = $hostIP
                'os' = @{
                    'name' = $hostOSName
                    'type' = ($hostOSName -split " ")[0].ToLower() # Extract the base type (e.g., "Mac" -> "mac")
                    'version' = $hostOSVersion
                }
            }
            'message' = $message
        }
    
        # Return the event as JSON
        return $event | ConvertTo-JSON -Depth 2 -Compress
    }

    function Invoke-Random-Hex-String {
        $chars = '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' 
        $randomFlagExtension = -join (Get-Random -Count 5 -InputObject $chars)
        return $randomFlagExtension
    }

    # Developer Functions
    function Invoke-Create-New-CTF-Challenge-Wizard {
        # Load challenge categories from manifest
        $rootManifestPath = ".\challenges\challenge_categories.psd1"
        try {
            $rootManifest = Import-PowerShellDataFile -Path $rootManifestPath
            $allCategories = $rootManifest.Categories
            $allCategories
        } catch {
            Write-Host "❌ Failed to load $rootManifestPath. Ensure it is valid PSD1." -ForegroundColor Red
            return
        }
        
        Write-Host "`n🛠️  Invoke-Create-New-CTF-Challenge-Wizard - Create a New CTF Challenge 🚩 " -ForegroundColor Magenta
        Write-Host "=========================================================================`n" -ForegroundColor Cyan

        # Get challenge details from user
        $Challenge_Name = Read-Host "Enter the challenge name"
        $Challenge_Category = Read-Host "Enter the challenge category ($allCategories New)"
        if($Challenge_Category -eq "New"){
            Write-Host "Creating a new challenge category requires updating the $rootmanifestPath file manually. Add the category then run the wizard again." -ForegroundColor Yellow
            Exit
        }elseif($allCategories -contains $Challenge_Category){
            Write-Host "Selected existing category: $Challenge_Category" -ForegroundColor Green
            # Get Challenge category series number from challenge category number in array
            $categorySeriesNumber = ($allCategories.IndexOf($Challenge_Category) + 1) * 1000
            Write-Host "Category series number is: $categorySeriesNumber" -ForegroundColor Green
        }else{
            Write-Host "❌ Invalid category selected. Exiting." -ForegroundColor Red
            Exit
        }

        $Challenge_Required_Kibana_Version = Read-Host "Enter the required Kibana version for the challenge (e.g., 9.2.1)"

        # Create simplified challenge object
        $challengeObject = @"
@{
    Name = `"$Challenge_Name`"
    Category = `"$Challenge_Category`"
    RequiredFiles = @(
        `"ctfd_challenge.json`"
        `"ctfd_flag.json`"
    )
    Resources = @{
        KibanaVersion = `"^$Challenge_Required_Kibana_Version`"
    }
}
"@


        # Determine new challenge number
        $existingChallengesPath = ".\challenges\$($Challenge_Category)"
        if (Test-Path $existingChallengesPath) {
            # Get existing challenge numbers
            $totalChallenges = Get-Item "$existingChallengesPath\*" | Where-Object { $_.PSIsContainer }
            # Get the highest existing challenge number and increment
            $new_challenge_number = ($totalChallenges.count + 1)
            Write-Host "Found $($totalChallenges.count) existing challenges. New challenge number will be: $new_challenge_number" -ForegroundColor Green
        } else {
            Write-Host "Category folder does not exist, something is wrong. Exiting." -ForegroundColor Red
            Exit
        }

        # Create new challenge directory
        New-Item -ItemType Directory -Path ".\challenges\$($Challenge_Category)\$($new_challenge_number)" -Force | Out-Null
        # Save challenge manifest
        Out-File -FilePath ".\challenges\$($Challenge_Category)\$($new_challenge_number)\challenge_manifest.psd1" -InputObject $challengeObject -Encoding UTF8 -Force
        Write-Host "✅ Created new challenge directory and manifest at .\challenges\$($Challenge_Category)\$($new_challenge_number)\challenge_manifest.psd1" -ForegroundColor Green

        # Add required files in new challenge directory based on what is in the manifest
        $Challenge_Description = Read-Host "Enter a brief description for the challenge (will be added to ctfd_challenge.json)"
        $Challenge_Points = Read-Host "Enter the point value for the challenge (will be added to ctfd_challenge.json)"
        $Challenge_Flag = Read-Host "Enter the flag for the challenge (will be added to ctfd_flag.json) {ctf_<your_flag_will_go_here>}"
        $Challenge_Id = $categorySeriesNumber + $new_challenge_number
        $newChallengeImport = Import-PowerShellDataFile -Path ".\challenges\$($Challenge_Category)\$($new_challenge_number)\challenge_manifest.psd1"
        foreach ($requiredFile in $newChallengeImport.RequiredFiles) {
            switch ($requiredFile) {
                "ctfd_challenge.json" {
                    $ctfd_challenge_template = @{
                        id           = [int]$Challenge_Id
                        name         = $Challenge_Name
                        description  = $Challenge_Description
                        max_attempts = 10
                        value        = [int]$Challenge_Points
                        category     = $Challenge_Category
                        type         = "standard"
                        state        = "visible"
                    }
                    $ctfd_challenge_template | ConvertTo-Json -Depth 10 | Out-File -FilePath ".\challenges\$($Challenge_Category)\$($new_challenge_number)\ctfd_challenge.json" -Encoding UTF8
                    Write-Host "✅ Created ctfd_challenge.json template." -ForegroundColor Green
                }
                "ctfd_flag.json" {
                    $ctfd_flag_template = @{
                        id           = $Challenge_Id  # Update this ID after importing the challenge to CTFd
                        challenge_id = $Challenge_Id  # Update this ID after importing the challenge to CTFd
                        type         = "static"
                        content      = "{ctf_$Challenge_Flag}"
                        data         =  "case_insensitive"
                    }
                    $ctfd_flag_template | ConvertTo-Json -Depth 10 | Out-File -FilePath ".\challenges\$($Challenge_Category)\$($new_challenge_number)\ctfd_flag.json" -Encoding UTF8
                    Write-Host "✅ Created ctfd_flag.json template." -ForegroundColor Green
                }
                default {
                    Write-Host "⚠️ Unknown required file type: $requiredFile. Skipping." -ForegroundColor Yellow
                }
            }
        }

        # Ask if user wants a hint to the challenge
        $needHint = Read-Host "Would you like to add a hint to this challenge?`n1. Yes`n2. No`n(Enter 1 or 2)"
        if($needHint -eq 1){
            $Challenge_Hint = Read-Host "Enter the hint for the challenge (will be added to ctfd_hint.json)"
            $ctfd_hint_template = @{
                id           = $Challenge_Id  # Update this ID after importing the challenge to CTFd
                challenge_id = $Challenge_Id  # Update this ID after importing the challenge to CTFd
                content      = $Challenge_Hint
                cost         = 0
            }
            $ctfd_hint_template | ConvertTo-Json -Depth 10 | Out-File -FilePath ".\challenges\$($Challenge_Category)\$($new_challenge_number)\ctfd_hint.json" -Encoding UTF8
            Write-Host "✅ Created ctfd_hint.json template." -ForegroundColor Green
        }

        # Ask if user if they will need an advanced PowerShell import script (elastic_import_script.ps1)
        $needImportScript = Read-Host "Would you like to generate an advanced PowerShell import script for this challenge?`n1. Yes`n2. No`n(Enter 1 or 2)"
        if($needImportScript -eq 1){
            $importScriptContent = @"
# Advanced Elastic Stack Import Script for Challenge: $Challenge_Name
# This script will help you import the necessary resources into Elastic Stack for the challenge.
# Make sure to customize the script as needed before running.
function challenge {

    return Write-Debug "✅ elastic_import_script.ps1 executed"
}
"@

            Out-File -FilePath ".\challenges\$($Challenge_Category)\$($new_challenge_number)\elastic_import_script.ps1" -InputObject $importScriptContent -Encoding UTF8 -Force
            Write-Host "✅ Created elastic_import_script.ps1 template." -ForegroundColor Green
        }

        return "Finished generating new challenge files. Now try to import the new challenge into CTFd and tweak as needed!"

    }
    
    # Main menu options
    $option1 = "[1] 🏁 Deploy CTFd"
    $option2 = "[2] ⚙️ Deploy Elastic Stack"
    $option3 = "[3] 🚩 Import Flags (CTFd) + Challenges (Elastic Stack)"
    $option4 = "[4] 🗑️ Delete CTFd"
    $option5 = "[5] 🗑️ Delete Elastic Stack"
    $option6 = "[6] 🔍 Check for Requirements"
    $option7 = "[7] 🤖 Deploy everything from scratch (Recommended)"
    $option8 = "[8] 🔧 Developer Options (Create/Export/Test Challenges + Manage Stacks)"

    # Challenge category options
    $challenge_option0 = "[0] 🌀 All Challenges         (Recommended)"
    $challenge_option1 = "[1] 🔎 Discover Challenges    (Kibana Discover focus)"
    $challenge_option2 = "[2] 📊 ES|QL Challenges       (ES|QL query practice)"
    $challenge_option3 = "[3] 📈 Dashboards             (Kibana dashboards only)"
    #$challenge_option4 = "[4] 🎯 Hand-pick Challenges   (Choose specific ones)"
    $quit              = "[Q] ❌ Quit"

    # Developer menu options
    $developer_option0 = "[0] 🛠️ Create New CTF Challenge (Template / Wizard)"
    $developer_option1 = "[1] 📥 Import CTF Challenge to CTFd and Elastic Stack"
    $developer_option2 = "[2] 📦 Export Existing CTF Challenge (From CTFd)"
    $developer_option3 = "[3] 🟢 Start Up Elastic Stack (Requires preconfigured docker setup with already imported challenges)"
    $developer_option4 = "[4] 🔴 Shut Down Elastic Stack"
    $developer_option5 = "[5] 🟢 Start Up CTFd (Requires preconfigured docker setup with already imported challenges)"
    $developer_option6 = "[6] 🔴 Shut Down CTFd"
    $developer_option7 = "[7] 🚦Check CTFd and Elastic Stack Status"


    $quit = "Q. Quit"

    function Show-Menu {
        Write-Host ""
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host "   Welcome to the Kibana CTF Setup Script! 🚀" -ForegroundColor Green
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host "What would you like to do?" -ForegroundColor Yellow
        Write-Host ""
        Write-Host $option1 -ForegroundColor White
        Write-Host $option2 -ForegroundColor White
        Write-Host $option3 -ForegroundColor White
        Write-Host $option4 -ForegroundColor White
        Write-Host $option5 -ForegroundColor White
        Write-Host $option6 -ForegroundColor White
        Write-Host $option7 -ForegroundColor White
        Write-Host $option8 -ForegroundColor White
        Write-Host ""
        Write-Host $quit -ForegroundColor Red
        Write-Host ""
    }

    function Show-Developer-Menu {
        Write-Host ""
        Write-Host "=========================================================================================" -ForegroundColor Cyan
        Write-Host "        🔧 Developer Options for Creating, Exporting, and Testing Challenges 🛠️" -ForegroundColor Green
        Write-Host "=========================================================================================" -ForegroundColor Cyan
        Write-Host "What would you like to do?" -ForegroundColor Yellow
        Write-Host ""
        Write-Host $developer_option0 -ForegroundColor White
        #Write-Host $developer_option1 -ForegroundColor White
        #Write-Host $developer_option2 -ForegroundColor White
        Write-Host $developer_option3 -ForegroundColor White
        Write-Host $developer_option4 -ForegroundColor White
        Write-Host $developer_option5 -ForegroundColor White
        Write-Host $developer_option6 -ForegroundColor White
        Write-Host ""
        Write-Host $quit -ForegroundColor Red
        Write-Host ""
    }
    function Show-CTF-Challenges-Menu {
        Write-Host ""
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host "        🚩 Capture The Flag Challenge Import 🚩" -ForegroundColor Green
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host "Which Kibana CTF Challenge Categories would you like to import?" -ForegroundColor Yellow
        Write-Host "Note: This will import CTFd challenges and required Elastic resources." -ForegroundColor Yellow
        Write-Host ""
        Write-Host $challenge_option0 -ForegroundColor White
        Write-Host $challenge_option1 -ForegroundColor White
        Write-Host $challenge_option2 -ForegroundColor White
        Write-Host $challenge_option3 -ForegroundColor White
        #Write-Host $challenge_option4 -ForegroundColor White
        Write-Host ""
        Write-Host $quit -ForegroundColor Red
        Write-Host ""
    }

    function Invoke-CTFd-Deploy {
        # 1. Deploy CTFd
        <# 
        .SYNOPSIS
        Deploys or runs the CTFd Docker instance.

        .DESCRIPTION
        Checks if the CTFd directory exists. If yes, offers to run it. 
        If no, offers to clone, deploy, and run via Docker.
        #>

        Write-Host "`n======================================================" -ForegroundColor Cyan
        Write-Host " 🚩  Invoke-CTFd-Deploy - Challenge Platform Setup  🚩 " -ForegroundColor Magenta
        Write-Host "======================================================`n" -ForegroundColor Cyan
        
        # Check to see if CTFd has been deployed, and if not, ask to deploy.
        try {
            $pathForCTFd = Get-Item ../CTFd -ErrorAction Ignore
        } catch {
            Write-Host "⚠️  No CTFd path detected." -ForegroundColor Yellow
        }

        if ($null -ne $pathForCTFd) {
            $runCTFd = Read-Host "📂 CTFd directory found! Would you like to run CTFd via Docker? (Y/n)"
            if ($runCTFd -match "y" -or $runCTFd -eq "") {
                Set-Location ../CTFd
                Write-Host "`n▶️  Launching CTFd..." -ForegroundColor Green
                Write-Host "   (Hint: Use 'docker compose down' from the CTFd dir to stop)" -ForegroundColor DarkGray
                docker compose up -d
                Set-Location ../kibana-ctf/
                Write-Host "`n✅ CTFd is starting up! Navigate to:" -ForegroundColor Green
                Write-Host "   🌍 $CTFd_URL" -ForegroundColor Cyan
                Write-Host "   (It may take a few minutes for the container to be fully ready)" -ForegroundColor DarkGray
                $ctfd_auth = Get-CTFd-Admin-Token
            } else {
                Write-Host "`n❌ You chose not to run CTFd. Exiting..." -ForegroundColor Yellow
            }
        } else {
            $runCTFd = Read-Host "📂 No CTFd directory found. Would you like to clone and deploy it via Docker? (Y/n)"
            if ($runCTFd -match "y" -or $runCTFd -eq "") {
                Set-Location ../
                Write-Host "`n🔄 Cloning CTFd repo..." -ForegroundColor Cyan
                git clone https://github.com/CTFd/CTFd.git
                Set-Location ./CTFd/
                # Configure CTFd Preset Admin User/Pass
                Write-Host "`n⚙️  Configuring CTFd preset admin user, password and access token..." -ForegroundColor Cyan
                Invoke-Setup-CTFd-Preset-Admin

                Write-Host "`n▶️  Launching CTFd..." -ForegroundColor Green
                docker compose up -d
                Set-Location ../kibana-ctf/
                Write-Host "`n✅ CTFd has been downloaded and is starting up!" -ForegroundColor Green
                Write-Host "   🌍 Navigate to $CTFd_URL to complete setup" -ForegroundColor Cyan
                Write-Host "   (It may take a few minutes for the container to be fully ready)" -ForegroundColor DarkGray
                Write-Host "`n🛠️ Next Step is to follow the wizard and create the admin account and then obtain an Access Key:" -ForegroundColor Green
                Write-Host "`n📖 Refer to the README for the detailed next steps:" -ForegroundColor Green
                Write-Host "   https://github.com/nicpenning/kibana-ctf?tab=readme-ov-file#how-to-get-started" -ForegroundColor Cyan
                Write-Host "`n👉 Once finished, rerun this script and select option 2 to begin Elastic Stack setup." -ForegroundColor Green
                # Setup up Auth header
                $ctfd_auth = Get-CTFd-Admin-Token
            } else {
                Write-Host "`n❌ You chose not to deploy CTFd. Exiting..." -ForegroundColor Yellow
            }
        }
        
        # Retrieve pages from pages.json file and convert it into an object
        $pages_object = Get-Content './setup/CTFd/pages.json' | ConvertFrom-Json -Depth 10
        # $config_object = Get-Content './setup/CTFd/config.json' | ConvertFrom-Json -Depth 10 # Deprecated

        # Import Page(s) 1 by 1
        Write-Debug "Importing $($pages_object.results.count) page(s)"
        $pages_object.results | ForEach-Object {
            # Get current page
            $current_pages = $_ | ConvertTo-Json -Compress

            Write-Debug "Importing page: $($_.title)"
            try{
                $import_pages = Invoke-RestMethod -Method POST "$CTFd_URL_API/pages" -ContentType "application/json" -Headers $ctfd_auth -Body $current_pages
                Write-Host "✅ Imported page $($_.title) - $($import_pages.success)"
            }catch{
                Write-Debug "⚠️ Could not import page."
                Write-Debug "Will try to update the current page."
                try{
                    $update_pages = Invoke-RestMethod -Method PATCH "$CTFd_URL_API/pages/1" -ContentType "application/json" -Headers $ctfd_auth -Body $current_pages
                    Write-Host "✅ Pages updated: $($update_pages.success)"
                }catch{
                    Write-Host "❌ Could not import page: $($_.title)"
                    Write-Host "⚠️ Note: This shouldn't impact the CTF platform if everything else worked."
                    Write-Debug $_.Exception
                }
            }
        }

        <# Import Config (Deprecated)
        Write-Debug "Importing $($config_object.results.count) config option(s)"
        $config_object.results | ForEach-Object {
            # Get current config
            $current_config = $_ | ConvertTo-Json -Compress

            Write-Debug "Importing config option: $($_.key)"
            try{
                $import_config = Invoke-RestMethod -Method POST "$CTFd_URL_API/configs" -ContentType "application/json" -Headers $ctfd_auth -Body $current_config
                Write-Debug "✅ Imported config option: $($_.key) - $($import_config.success)"
            }catch{
                Write-Debug "Could not import config."
                Write-Debug $_.Exception
            }
        }#>

        # Import Logo
        Write-Debug "Importing logo for home page"
        $form = @{
            "page_id" = 1
            "type" = "page"
            "file" = Get-Item -Path "images/kibana-ctf.png"
            "location" = "kibana_ctf_images/kibana-ctf.png"
        }
        $response = Invoke-RestMethod -Method POST -Uri "$CTFd_URL_API/files" -Headers $ctfd_auth -Form $form
        Write-Host "✅ Imported logo file`: $($response.success)"

        Write-Host "`n🏁 Done with Invoke-CTFd-Deploy.`n" -ForegroundColor Magenta
    }

    function Invoke-Elastic-Stack-Deploy {
        # 2. Deploy Elastic Stack
        
        <#
        .SYNOPSIS
            Deploys the Elastic Stack for use with the CTF project.

        .DESCRIPTION
            This function automates the setup of the Elastic Stack environment by:
            1. Checking for existing configuration (.env file).
            2. Offering the option to generate a secure .env file with random credentials.
            3. Starting or restarting the Elastic Stack via Docker Compose.
            4. Configuring Elasticsearch credentials for automated use.
            5. Verifying that Elasticsearch is running and available.
            6. Guiding the user through logging into Kibana.
            7. Bootstrapping required resources (Index Templates, Kibana Space, CTF Role/User).
        #>

        # Check to see if various parts of the project have already been configured to reduce the need for user input.
        # -------------------------------
        # 1. Environment Configuration
        # -------------------------------
        # If no .env file exists, give the user the option to generate one with secure defaults.
        if ($(Invoke-CheckForEnv) -eq "False") {
            Write-Host "Would you like to use docker with this project?"
            Write-Host "[1] Yes, please generate a secure .env file. (Recommended)"
            Write-Host "[2] No thanks, I know what I am doing or I already have a .env file ready to go."
            $dockerChoice = Read-Host "Please Choose (1 or 2)"
        
            if ($dockerChoice -eq "1") {
                # Generate a secure .env file with random credentials for Elasticsearch and Kibana.
                $env = Get-Content .\setup\Elastic\docker_elastic_stack\.env_template

                # Random password for elastic user
                $elasticsearchPassword = -Join ((@('0'..'9';'A'..'Z';'a'..'z';'!';'@';'#')) | Get-Random -Count 32)
                $env = $env.Replace('$elasticsearchPassword', $elasticsearchPassword)

                # Random password for Kibana system user
                $kibanaPassword = -Join ((@('0'..'9';'A'..'Z';'a'..'z';'!';'@';'#')) | Get-Random -Count 32)
                $env = $env.Replace('$kibanaPassword', $kibanaPassword)

                # Random Kibana encryption key
                $kibanaEncryptionKey = -Join ((@('0'..'9';'A'..'Z';'a'..'z';'!';'@';'#')) | Get-Random -Count 32)
                $env = $env.Replace('$kibanaEncryptionKey', $kibanaEncryptionKey)

                # Write the completed .env file
                $env | Out-File .\setup\Elastic\docker_elastic_stack\.env -Force

                Write-Host "✅ New .env file created successfully!" -ForegroundColor Green
                Write-Host "ℹ️  Credentials generated for Elasticsearch and Kibana:" -ForegroundColor Blue
                Write-Host "    Username : elastic"
                Write-Host "    Password : $elasticsearchPassword"
                Pause
            } else {
                Write-Debug "User skipped Docker setup. Assuming manual or pre-existing configuration."
            }
        } else {
            Write-Debug ".env file already exists. Skipping environment generation."
        }
        
        # -------------------------------
        # 2. Docker Startup
        # -------------------------------
        
        if (Invoke-CheckForDockerInUse -eq "False") {
            # Prompt to start Elastic Stack containers
            Write-Host "Would you like to start up the Elastic Stack with Docker?"
            Write-Host "[1] Yes, please run Docker Compose up for me (Recommended)"
            Write-Host "[2] No thanks, I will handle the cluster manually."
            $startStack = Read-Host "Please choose (1 or 2)"

            if ($startStack -eq "1") {
                Invoke-StartDocker
            } elseif ($startStack -eq "2") {
                Write-Debug "User opted to manually start Elasticsearch/Kibana."
            } else {
                Write-Host "❌ Invalid option selected. Exiting." -ForegroundColor Red
                exit
            }
        } elseif (Invoke-CheckForDockerInUse -eq "True") {
            # Optionally restart Docker containers
            Write-Host "Docker is already running. Would you like to restart it?"
            Write-Host "[1] Yes, restart Docker (docker-compose down & up)"
            Write-Host "[2] No, keep it running."
            $restartDocker = Read-Host "Please choose (1 or 2)"

            if ($restartDocker -eq 1) {
                Write-Host "Stopping existing containers..." -ForegroundColor Yellow
                Invoke-StopDocker
                Write-Host "Starting fresh containers..." -ForegroundColor Yellow
                Invoke-StartDocker
            } else {
                Write-Debug "Continuing with currently running Docker instance."
            }
        } else {
            Write-Host "⚠️  Unable to determine Docker status. Exiting." -ForegroundColor Yellow
            exit
        }

        # -------------------------------
        # 3. Credential Handling
        # -------------------------------
        # Use generated password if available, otherwise prompt user.
        if ($elasticsearchPassword) {
            Write-Host "Detected generated credentials — using those for setup." -ForegroundColor Blue
            $elasticsearchPasswordSecure = ConvertTo-SecureString -String "$elasticsearchPassword" -AsPlainText -Force
            $elasticCreds = New-Object System.Management.Automation.PSCredential -ArgumentList "elastic", $elasticsearchPasswordSecure
        } else {
            Write-Host "⚠️ No generated password found. Please enter Elastic user credentials." -ForegroundColor Yellow
            $elasticCreds = Get-Credential elastic
        }

        # Prepare base64 auth string for Kibana API requests
        $elasticCredsBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
            $elasticCreds.UserName + ":" + ($elasticCreds.Password | ConvertFrom-SecureString -AsPlainText)
        ))
        $kibanaAuth = "Basic $elasticCredsBase64"

        # -------------------------------
        # 4. Verify Elasticsearch Status
        # -------------------------------
        Invoke-CheckForElasticsearchStatus

        # Save state to configuration.psd1
        Update-Psd1Value -Path "./configuration.psd1" -Key "initializedElasticStack" -Value "true"

        # -------------------------------
        # 5. User Confirmation for Kibana
        # -------------------------------
        $kibanaStatus = Invoke-CheckForKibanaStatus -KibanaUrl $Kibana_URL -MaxRetries 3 -InitialDelay 90 -credential $elasticCreds
        if($kibanaStatus -eq $false){
            "Took to long for Kibana to start. Please check credentials, Kibana URL, or the Docker logs for errors."
            exit
        }

        Write-Host "Kibana instance is successfully running at --> $Kibana_URL" -ForegroundColor DarkCyan
        Write-Host "Username : elastic`nPassword : $elasticsearchPassword"

        # -------------------------------
        # 6. Bootstrap Required Resources
        # -------------------------------
        # Create Index Template for Challenges
        Invoke-Create-Index-Template

        # Create Kibana CTF Space
        Invoke-Create-Kibana-CTF-Space $Kibana_URL

        # Create Kibana CTF Role Mapping
        Invoke-Create-Kibana-CTF-User-Role

        # Create kibana-ctf user with Kibana CTF Role Mapping
        Invoke-Create-Kibana-CTF-User
    }

    function Invoke-Elastic-and-CTFd-Challenges {
        # Import CTFd and Elastic Stack Challenges
        # Show Menu if script was not provided the choice on execution using the Option_Selected variable
            
        if ($null -eq $CTF_Options_Selected -or $CTF_Options_Selected) {
            Show-CTF-Challenges-Menu
            $CTF_Options_Selected = Read-Host "Enter your choice"
        }

        # Get / Save CTFd Access Token
        $ctfd_auth = Get-CTFd-Admin-Token

        # Get / Save Elasticsearch URL
        if ($configurationSettings.Elasticsearch_URL) {
            $Elasticsearch_URL = $configurationSettings.Elasticsearch_URL
            Write-Host "🔎 Elasticsearch URL detected: $Elasticsearch_URL" -ForegroundColor Green
        } else {
            Write-Host "Elasticsearch URL required." -ForegroundColor Yellow
            $Elasticsearch_URL = Read-Host "Enter full Elasticsearch URL (e.g. https://127.0.0.1:9200)"
            Update-Psd1Value -Path $configPath -Key "Elasticsearch_URL" -Value $Elasticsearch_URL
        }

        # Get / Save Kibana URL
        if ($configurationSettings.Kibana_URL) {
            $Kibana_URL = $configurationSettings.Kibana_URL
            Write-Host "📊 Kibana URL detected: $Kibana_URL" -ForegroundColor Green
        } else {
            Write-Host "Kibana URL required." -ForegroundColor Yellow
            $Kibana_URL = Read-Host "Enter full Kibana URL (e.g. http://127.0.0.1:5601)"
            Update-Psd1Value -Path $configPath -Key "Kibana_URL" -Value $Kibana_URL
        }

        # Configure Elasticsearch credentials for importing saved objects into Kibana.
        # Get elastic user credentials
        Write-Debug "Going to need the password for the elastic user. Checking for generated creds now."
        $elasticCredsCheck = Invoke-CheckForEnv

        # Set passwords via automated configuration or manual input
        # Base64 Encoded elastic:secure_password for Kibana auth
        if($($elasticCredsCheck)[0] -eq "True"){
            $elasticPass = ConvertTo-SecureString -String $($($elasticCredsCheck)[1]) -AsPlainText -Force
        $elasticCreds = New-Object System.Management.Automation.PSCredential("elastic", $elasticPass)
        } else {
            $elasticCreds = Get-Credential elastic
        }
            $elasticCredsBase64 = [convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($($elasticCreds.UserName+":"+$($elasticCreds.Password | ConvertFrom-SecureString -AsPlainText)).ToString()))

        $kibanaAuth = "Basic $elasticCredsBase64"
                    
        # Check Elasticsearch
        Invoke-CheckForElasticsearchStatus

        # Ingest Dummy Documents
        $docCount = 25000
        $batchSize = 2500
        Write-Host "Ingesting $docCount documents in batches of $batchSize..."

        $spinner = @('|','/','-','\'); $i = 0
        Write-Host "⏳ Generating $docCount fake documents..." -ForegroundColor Cyan

        $dummyDocs = foreach ($n in 1..$docCount) {
            Write-Host -NoNewline "`r$($spinner[$i % $spinner.Length]) Generating doc $n of $docCount..."
            $i++
            Invoke-Generate-FakeEvent
        }
        Write-Host "`r✅ Generated $($dummyDocs.Count) fake documents." -ForegroundColor Green

        Invoke-Ingest-Elasticsearch-Documents -documentToIngest $dummyDocs -batchSize $batchSize

        # Import Kibana Dashboard
        Write-Host "📥 Importing Kibana CTF Dashboard"
        Import-SavedObject "./setup/Elastic/kibana_dashboard.ndjson"

        # Import Challenges (if selected)
        if ((0, 1, 2, 3) -contains $CTF_Options_Selected) {
            $rootManifestPath = "./challenges/challenge_categories.psd1"
            if (-not (Test-Path $rootManifestPath)) {
                Write-Host "❌ Root manifest not found at $rootManifestPath." -ForegroundColor Red
                return
            }

            try {
                $rootManifest = Import-PowerShellDataFile -Path $rootManifestPath
                $allCategories = $rootManifest.Categories
            } catch {
                Write-Host "❌ Failed to load $rootManifestPath. Ensure it is valid PSD1." -ForegroundColor Red
                return
            }

            switch ($CTF_Options_Selected) {
                0 { $challengeTypes = $allCategories }
                1 { $challengeTypes = @("Discover") }
                2 { $challengeTypes = @("ES_QL") }
                3 { $challengeTypes = @("Dashboards") }
                default {
                    Write-Host "⚠️ Invalid choice: '$CTF_Options_Selected'" -ForegroundColor Yellow
                    Write-Host "👉 Please enter a valid option (0–3)." -ForegroundColor Cyan
                    $challengeTypes = @()
                }
            }

            foreach ($type in $challengeTypes) {
                Write-Host "`n=== Importing $type Challenges ===" -ForegroundColor Cyan
                $challengeRoot = "./challenges/$type/"
                if (-not (Test-Path $challengeRoot)) {
                    Write-Warning "⚠️ No $type challenges found at $challengeRoot. Skipping..."
                    continue
                }

                $challenges = Get-ChildItem -Directory $challengeRoot | Sort-Object { [int]$_.Name } 
                foreach ($challenge in $challenges) {
                    $challengePath = $challenge.FullName
                    $manifestPath = Join-Path $challengePath "challenge_manifest.psd1"

                    if (-not (Test-Path $manifestPath)) {
                        Write-Host "❌ Missing challenge_manifest.psd1 in $challengePath" -ForegroundColor Red
                        continue
                    }

                        try {
                            $manifest = Import-PowerShellDataFile -Path $manifestPath
                        } catch {
                            Write-Host "❌ Failed to load $manifestPath. Ensure it is a valid PSD1 file." -ForegroundColor Red
                        continue
                    }

                    if (-not $manifest.ContainsKey("RequiredFiles")) {
                        Write-Warning "❌ No RequiredFiles entry in manifest for $type at $challengePath"
                        continue
                    }

                    $requiredFiles = $manifest.RequiredFiles
                    $actualFiles   = Get-ChildItem -Path $challengePath -File | Select-Object -ExpandProperty Name
                    $missingFiles  = $requiredFiles | Where-Object { $_ -notin $actualFiles }

                    if ($missingFiles.Count -eq 0) {
                        Write-Debug "✅ All required files found. Importing Challenge: $($manifest.Name)"
                        $actualFiles | Where-Object { $_ -ne "challenge_manifest.psd1" } | ForEach-Object {
                            switch ($_) {
                                "ctfd_challenge.json"        { Invoke-Import-CTFd-Challenge "$challengePath/$_" }
                                "ctfd_flag.json"             { Invoke-Import-CTFd-Flag "$challengePath/$_" }
                                "ctfd_hint.json"             { Invoke-Import-CTFd-Hint "$challengePath/$_" }
                                "elastic_import_script.ps1"  { . "$challengePath/$_"; challenge }
                                "elastic_saved_objects.ndjson" { Import-SavedObject "$challengePath/$_" }
                                "dynamic_flag.ps1"           { . "$challengePath/$_"; dynamic_flag }
                            }
                        }
                    } else {
                        Write-Host "⚠️ Missing required files for $type challenge. Import skipped." -ForegroundColor Yellow
                        $missingFiles | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
                    }
                }
            }
        }

            Write-Host "`n✅ Setup complete! Your CTF environment is now live and ready to roll!" -ForegroundColor Green
            Write-Host "------------------------------------------------------------"
            Write-Host "🌐 CTFd Platform:"
            Write-Host "   👉 Navigate to $CTFd_URL"
            Write-Host "   👉 Register your player account and start solving challenges!"
            Write-Host ""
            Write-Host "📊 Kibana CTF Playground:"
            Write-Host "   👉 Navigate to $Kibana_URL"
            Write-Host "   👉 Log in with the dedicated CTF account:"
            Write-Host "       username: kibana-ctf"
            Write-Host "       password: kibana-ctf--please-change-me" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "🚀 You’re all set — challenges are waiting and flags are hidden!"
            Write-Host "Sharpen your skills, dive deep into Kibana, and hunt those 🎯 flags!"
            Write-Host "------------------------------------------------------------"
            Write-Host "🔥 Happy Hunting, and may the best analyst win! 🚩" -ForegroundColor Green
    }

    function Invoke-Remove-CTFd {
        $continue = Read-Host "This action is destructive and will remove all CTFd resources such as the containers which in turn will lose all progress, users, flags, etc. Please backup your CTF using the UI if possible (https://docs.ctfd.io/docs/exports/ctfd-exports). If you wish to continue please type in: `nDELETE-CTFd-Instance"
        if($continue -ne "DELETE-CTFd-Instance"){
            Write-Host "Proper response was not entered, exiting."
            $finished = $true
            break
        }
        Write-Host "🗑️ Deleting all CTFd containers and data now using: docker compose down --volumes --rmi all --remove-orphans" -ForegroundColor Yellow

        <# Alternative method to cleaning up CTFd is deleting all challenges - For now, just try to remove the files.
        # Setup up Auth header
        # $ctfd_auth = Get-CTFd-Admin-Token

        # Get Challenges
        # $challenges = Get-Challenges-From-CTFd

        # Remove Challenges 1 by 1
        Write-Host "Removing $($challenges.data.count) challenges"
        $challenges.data | ForEach-Object {
            # Get all challenge details per challenge
            $id = $_.id
            $challenge_info = Invoke-RestMethod -Method Get "$CTFd_URL_API/challenges/$id" -ContentType "application/json" -Headers $ctfd_auth
            Write-Host "Removing challenge: $($challenge_info.data.name)"
            try{
                $remove_challenge = Invoke-RestMethod -Method Delete "$CTFd_URL_API/challenges/$id" -ContentType "application/json" -Headers $ctfd_auth
                Write-Host "Removed challenge $($challenge_info.data.name) - $($remove_challenge.success)"
            }catch{
                Write-Host "Could not remove challenge: $($challenge_info.data.name) - $id"
                Write-Debug $_.Exception
            }
        }
        #>

        # Bringing down CTFd
        Set-Location ../CTFd
        docker compose down --volumes --rmi all --remove-orphans
        Set-Location ../kibana-ctf

        Write-Host "Finished removing CTFd containers. Feel free to delete the CTFd directory (requires Admin privileges) to fully clean CTFd from your system before re-deploying it again."
    }

    function Invoke-Remove-Elastic-Stack {
        $continue = Read-Host "This action is destructive and will remove all Elastic stack resources, if you wish to continue please type in: `nDELETE-KIBANA-CTF"
        if($continue -ne "DELETE-KIBANA-CTF"){
            Write-Host "Proper response was not entered, exiting."
            $finished = $true
            break
        }
        Write-Host "🗑️ Deleting all Elastic stack data now..." -ForegroundColor Yellow
        Set-Location ./setup/Elastic/docker_elastic_stack

        # Bring down the stack
        Write-Host "Bringing down Elastic stack and removing all containers and data using: docker compose down --volumes --rmi all --remove-orphans."
        docker compose down --volumes --rmi all --remove-orphans

        Write-Host "All data has been deleted."
        Set-Location ../../../
    }
}

Process {
    while ($true -ne $finished) {
        # Show Menu if script was not provided the choice on execution using the Option_Selected variable
        if ($null -eq $Option_Selected -or $Option_Selected) {
            Show-Menu
            $Option_Selected = Read-Host "Enter your choice"
        }

        switch ($Option_Selected) {
            '1' {
                # Deploy CTFd
                Invoke-CTFd-Deploy

                $finished = $true
                break
            }
            '2' {
                # Deploy Elastic Stack
                Invoke-Elastic-Stack-Deploy
                
                $finished = $true
                break
            }
            '3' {
                # Import CTFd Flags and Elastic Stack Challenges
                Invoke-Elastic-and-CTFd-Challenges

                $finished = $true
                break
            }
            '4' {
                # Remove CTFd
                Invoke-Remove-CTFd

                $finished = $true
                break
            }
            '5' {
                # Remove Elastic Stack
                Invoke-Remove-Elastic-Stack

                $finished = $true
                break
            }
            '6' {
                # 6. Check for Requirements
                Write-Host "`n🔍 Checking requirements: PowerShell, Docker, and Docker Compose..."

                # PowerShell check
                if ($PSVersionTable.PSVersion.Major -lt 7 -or ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -lt 4)) {
                    Write-Host "⚠️ PowerShell 7.4 or newer is required. Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
                } else {
                    Write-Host "✅ PowerShell requirement met. Version: $($PSVersionTable.PSVersion)"
                }

                # Docker check
                if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
                    Write-Host "⚠️ Docker not found! Please install Docker and ensure it's in your PATH." -ForegroundColor Yellow
                } else {
                    Write-Host "✅ Docker requirement met. Docker is available in PATH."
                }

                # Docker Compose check
                $composeVersion = docker compose version 2>$null
                if ($composeVersion) {
                    Write-Host "✅ Docker Compose requirement met. Detected: $composeVersion"
                } else {
                    Write-Host "⚠️ Docker Compose not detected. Will attempt fallback to 'docker-compose' if needed." -ForegroundColor Yellow
                }

                # (Future) Elastic Stack & CTFd running checks could go here
                Write-Host "`n🎯 Requirements check complete!"
                $finished = $true
                break
            }
            '7' {
                # Deploy all from scratch!

                Invoke-CTFd-Deploy

                Invoke-Elastic-Stack-Deploy

                Invoke-Elastic-and-CTFd-Challenges

                $finished = $true
                break
            }
            '8' {
                # Menu for developer options
                Show-Developer-Menu
                $devOptionSelected = Read-Host "Enter your choice"
                switch ($devOptionSelected) {
                    '0' {
                        # Create New CTF Challenge
                        Write-Host "`n🚧 Developer Option: Create New CTF Challenge 🚧" -ForegroundColor Magenta
                        Invoke-Create-New-CTF-Challenge-Wizard
                        $finished = $true
                        break
                    }
                    '1' {
                        # Import a specific CTF Challenge
                        Write-Host "`n🚧 Developer Option: Import a Specific CTF Challenge 🚧" -ForegroundColor Magenta
                        Write-Host "Still in development..."
                        $finished = $true
                        break
                    }
                    '2' {
                        # Export Existing CTF Challenge from CTFd
                        Write-Host "`n🚧 Developer Option: Export Existing CTF Challenge from CTFd"
                        Write-Host "Still in development..."
                        $finished = $true
                        break
                    }
                    '3' {
                        # Start up Elastic Stack
                        Write-Host "`n🚧 Developer Option: Start up Elastic Stack 🚧" -ForegroundColor Magenta
                        Invoke-StartDocker
                        Write-Host "`n✅ Elastic Stack is running at $Elastic_URL."
                        $finished = $true
                        break
                    }
                    '4' {
                        # Stop Elastic Stack
                        Write-Host "`n🚧 Developer Option: Stop Elastic Stack 🚧" -ForegroundColor Magenta
                        Invoke-StopDocker
                        Write-Host "`n✅ Elastic Stack has been stopped."
                        $finished = $true
                        break
                    }
                    '5'{
                        # Start up CTFd
                        Write-Host "`n🚧 Developer Option: Start up CTFd 🚧"
                        Set-Location ../CTFd
                        docker compose up -d
                        Set-Location ../kibana-ctf/
                        Write-Host "`n✅ CTFd is running at $CTFd_URL"
                        $finished = $true
                        break
                    }
                    '6' {
                        # Stop CTFd
                        Write-Host "`n🚧 Developer Option: Stop CTFd 🚧"
                        Set-Location ../CTFd
                        docker compose down
                        Set-Location ../kibana-ctf/
                        Write-Host "`n✅ CTFd has been stopped."
                        $finished = $true
                        break
                    }
                    default {
                        Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Yellow
                        break
                    }
                }
                break
            }
            {"q","Q"} {
                Write-Host "You selected quit, exiting." -ForegroundColor Yellow

                $finished = $true
                break
            }
            default {
                Write-Host "Invalid choice. Please select a valid option."
                break
            }
        }
    }
}

End {
    Write-Host "🙏🏻 This is the end. Thanks for using this script!"
    $finished = $null
}
