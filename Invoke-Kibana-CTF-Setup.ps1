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
    solutions.

    Requirements:
        1. Internet Access (At least elastic.co & github.com)
        2. CTFd Instance (Token needs to be manually created and retrieved)
        3. Elasticsearch and Kibana Instance

    Tested for Elastic Stack 8.17.0+ and CTFd 3.7.4+

    Variable Options
    -Elasticsearch_URL "https://127.0.0.1:9200"
    -Kibana_URL "https://127.0.0.1:5601"
    -CTFd_URL "http://127.0.0.1:8000"
    -CTF_Start_Date "12/24/2024 12:00 PM" (default - Now)
    -CTF_End_Date "12/24/2024 1:00 PM" (default - 1 hour from Start Date)
    -CTFd_Randomize_Flags "False" (default False) # TO DO

.EXAMPLE
   .\Invoke-Kibana-CTF-Setup.ps1 -Elasticsearch_URL "http://127.0.0.1:9200" -Kibana_URL "https://127.0.0.1:5601" -CTFd_URL "http://127.0.0.1:8000" -CTF_Start_Date "12/24/2024 12:00 PM" -CTF_End_date "12/24/2024 3:00PM"
#>

Param (
    # -Elasticsearch URL. (default - https://127.0.0.1:9200)
    [Parameter(Mandatory=$false)]
    $Elasticsearch_URL = "https://127.0.0.1:9200",

    # Kibana URL. (default - https://127.0.0.1:5601)
    [Parameter(Mandatory=$false)]
    $Kibana_URL = "https://127.0.0.1:5601",
    
    # CTFd URL. (default - https://127.0.0.1:8000)
    [Parameter(Mandatory=$false)]
    $CTFd_URL = "https://127.0.0.1:8000",

    # CTF Start Date. (default - Now)
    [Parameter(Mandatory=$false)]
    $CTF_Start_Date = "https://127.0.0.1:9200",

    # CTF End Date URL. (default - 1 hour from Start Date)
    [Parameter(Mandatory=$false)]
    $CTF_End_Date = "https://127.0.0.1:9200",

    # Random CTF flags to make answer unique everytime. (default - false TO DO)
    [Parameter(Mandatory=$false)]
    $CTFd_Randomize_Flags = "false" 
)

Begin {
    function Get-CTFd-Creds {
        return Read-Host "Enter the token for the administrator account. Starts with ctfd_" -MaskInput
    }
    
    function Get-Elastic-Creds {
        return Get-Credential -Message "Enter the credentials for the elastic stack, recommended to use the default elastic account"
    }
    
    function Get-Challenges-From-CTFd {
        return Invoke-RestMethod -Method GET "$ctfd_url_api/challenges" -ContentType "application/json" -Headers $ctfd_auth
    }

    function Get-CTFd-Admin-Token {
        $ctfd_token = Get-CTFd-Creds
        $ctfd_auth = @{"Authorization" = "Token $ctfd_token"}

        # Validate auth
        try{
            $validate = Invoke-RestMethod -Method GET -Uri "$ctfd_url_api/pages"  -ContentType "application/json" -Headers $ctfd_auth
            if($validate){
                Write-Host "Valid token provided!" -ForegroundColor Green
            }else{
                Write-Host "Could not validate, try another token or checking your connection to $ctfd_url_api/pages endpoint."
            }
        }catch{
            Write-Host "Could not validate token, exiting." -ForegroundColor Red
            $_.Exception
            exit
        }
        return $ctfd_auth
    }

    # Elastic Stack Setup Functions
    function Invoke-CheckForEnv {
        # Check for existing .env file for setup
        # Get Elasticsearch password from .env file
        if (Test-Path .\docker\.env) {
            Write-Host "Docker .env file found! Which likely means you have configured docker for use. Going to extract password to perform initilization."
            $env = Get-Content .\docker\.env
            $regExEnv = $env | Select-String -AllMatches -Pattern "ELASTIC_PASSWORD='(.*)'"
            $global:elasticsearchPassword = $regExEnv.Matches.Groups[1].Value
            if ($elasticsearchPassword) {
                Write-Host "Password for user elastic has been found and will be used." -ForegroundColor Green
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
        Write-Host "Docker found to be running" -ForegroundColor Yellow
        return "True"
        } else {
        Write-Debug "Docker was not found to be running"
        return "False"
        }
    }
    
    function Invoke-CheckForElasticsearchStatus {
        # Check for Elastic stack connectivity to a healthy cluster
        Write-Host "Waiting for Elastic stack to be accessible." -ForegroundColor Blue
    
        $healthAPI = $elasticsearchURL+"/_cluster/health"
        # Keep checking for a healthy cluster that can be used for the initialization process!
        do {
        try {
            Write-Debug "Checking to see if the cluster is accessible. Please wait."
            $status = Invoke-RestMethod -Method Get -Uri $healthAPI -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck  
        } catch {
            Write-Debug "Waiting for healthy cluster for 5 seconds. Then checking again."
            Start-Sleep -Seconds 5
        }
        } until ("green" -eq $status.status)
    
        if ("green" -eq $status.status) {
        Write-Host "Elastic cluster is $($status.status), continuing through the setup process." -ForegroundColor Green
        Start-Sleep -Seconds 2
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
                Write-Host "File created!" -ForegroundColor Green
            }catch{
                Write-Host "File could not be created." -ForegroundColor Red
            }
            }else{
            Write-Host "Required WSL file was not created, exiting."
            Exit
            }
        }else{
            Write-Host "Docker install was not detected using WSL2 so you might need to adjust your docker settings to allow additional RAM usage for this setup to work."
            Write-Host "If Elasticsearch never gets working then check your Docker containers to see if they exited and if so, check the logs and see why the failed and fix accordingly."
        }
        }
        
        Write-Host "Starting up the Elastic stack with docker, please be patient as this can take over 10 minutes to download and deploy the entire stack if this is the first time you executed this step.`nOtherwise this will take just a couple of minutes."
        Set-Location .\docker
        try {
        $composeVersion = docker compose version
        if($composeVersion){
            Write-Debug '"docker compose detected"'
            docker compose up &
        }else{
            Throw '"docker compose" not detected, will now check for docker-compose'
        }
        } catch {
        Write-Debug "docker compose up failed - trying docker-compose up"
        try {
            $dockerComposeVersion = docker-compose version
            if($dockerComposeVersion){
            Write-Debug '"docker-compose detected"'
            docker-compose up &
            }else{
            Throw '"docker-compose" not detected.'
            }
        } catch {
            Write-Host "docker compose up or docker-compose up did not work. Check that you have docker and docker composed installed."
        }
        }
        Set-Location ..\
    }
    
    function Invoke-StopDocker {
        Write-Debug "Shutting down docker containers for the Elastic stack."
        Set-Location .\docker
        try { 
        docker compose down
        } catch {
        Write-Host "Failed to use docker compose down, so trying docker-compose down."
        docker-compose down
        }
        Set-Location ..\
    }

    $option1 = "1. Deploy CTFd"
    $option2 = "2. Import CTFd Challenges, Flags, etc."
    $option3 = "3. Reset CTFd"
    $option4 = "4. Deploy Elastic Stack"
    $option5 = "5. Import Objects and Index Documents for Elastic Stack"
    $option6 = "6. Reset Elastic Stack"
    $option7 = "7. Check for Requirements"
    $option8 = "8. Deploy all from scratch"

    $quit = "Q. Quit"

    function Show-Menu {
        Write-Host "Welcome to the Kibana CTF Setup Script!" -ForegroundColor Blue
        Write-Host "What would you like to do?" -ForegroundColor Yellow
        Write-Host $option1
        Write-Host $option2
        Write-Host $option3
        Write-Host $option4
        Write-Host $option5
        Write-Host $option6
        Write-Host $option7
        Write-Host $option8

        Write-Host $quit
    }

    # CTFd Variables
    $ctfd_url = "http://127.0.0.1:8000"
    $ctfd_url_api = $ctfd_url+"/api/v1"

    # Elastic Stack Variables
    $elasticserach_url = "https://127.0.0.1:9200"
    $kibana_url = "https://127.0.0.1:5601"
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
                # 1. Deploy CTFd

                git clone https://github.com/CTFd/CTFd.git
                cd CTFd
                docker compose up

                $finished = $true
                break
            }
            '2' {
                # 2. Import CTFd Challenges, Flags, Hints, Config, Pages, and Files
                # Setup up Auth header
                $ctfd_auth = Get-CTFd-Admin-Token

                # Retrieve challenges from challenges.json file and convert it into an object
                $challenges_object = Get-Content './CTFd_Events/JSON Configuration Files/challenges.json' | ConvertFrom-Json -Depth 10
                $dynamic_challenges_object = Get-Content './CTFd_Events/JSON Configuration Files/dynamic_challenge.json' | ConvertFrom-Json -Depth 10
                $flags_object = Get-Content './CTFd_Events/JSON Configuration Files/flags.json' | ConvertFrom-Json -Depth 10
                $hints_object = Get-Content './CTFd_Events/JSON Configuration Files/hints.json' | ConvertFrom-Json -Depth 10
                $pages_object = Get-Content './CTFd_Events/JSON Configuration Files/pages.json' | ConvertFrom-Json -Depth 10
                $config_object = Get-Content './CTFd_Events/JSON Configuration Files/config.json' | ConvertFrom-Json -Depth 10
                $files_object = Get-Content './CTFd_Events/JSON Configuration Files/files.json' | ConvertFrom-Json -Depth 10

                # Import Challenges 1 by 1
                Write-Host "Importing $($challenges_object.results.count) challenges"
                Pause
                $challenges_object.results | Sort-Object -Property "next_id" | ForEach-Object {
                    # Get current challenge
                    $current_challenge_object = $_
                    $current_challenge = $_ | ConvertTo-Json -Compress

                    # Check for Dynamic Challenge
                    if($_.type -eq "dynamic"){
                        Write-Host "Dynamic challenge found! Adding additional details before import." -ForegroundColor Yellow
                        # Find the dynamic challenge related to the current challenge being imported and add the details as needed.
                        $dynamic_challenge_details = $dynamic_challenges_object.results | Where-Object {$_.id -eq $current_challenge_object.id}
                        $dynamic_challenge_details.PSObject.Members | Where-Object {$_.MemberType -eq "NoteProperty" -and $_.Name -ne "id"} | ForEach-Object {
                            $current_challenge_object | Add-Member -NotePropertyName $_.Name -NotePropertyValue $_.Value
                        }
                        # Convert new object to JSON and Import!
                        $current_challenge = $current_challenge_object | ConvertTo-Json -Compress -Depth 10
                    }
                    Write-Host "Importing challenge: $($_.name)"
                    try{
                        $import_challenge = Invoke-RestMethod -Method POST "$ctfd_url_api/challenges" -ContentType "application/json" -Headers $ctfd_auth -Body $current_challenge
                        Write-Host "Imported challenge $($current_challenge.name) - $($import_challenge.success)"
                    }catch{
                        Write-Host "Could not import challenge: $($current_challenge.name) - $($_.id)"
                        $_.Exception
                    }
                }

                # Import Flags 1 by 1
                Write-Host "Importing $($flags_object.results.count) flags"
                Pause
                $flags_object.results | ForEach-Object {
                    # Get current flag
                    $current_flag = $_ | ConvertTo-Json -Compress

                    Write-Host "Importing flags for Challenge ID: $($_.challenge_id)"
                    try{
                        $import_flag = Invoke-RestMethod -Method POST "$ctfd_url_api/flags" -ContentType "application/json" -Headers $ctfd_auth -Body $current_flag
                        Write-Host "Imported flag $($_.id) - $($import_flag.success)"
                    }catch{
                        Write-Host "Could not import flag: $($current_challenge.name) - $($_.id)"
                        $_.Exception
                    }
                }

                # Import Hints 1 by 1
                Write-Host "Importing $($hints_object.results.count) hints"
                Pause
                $hints_object.results | ForEach-Object {
                    # Get current flag
                    $current_hints = $_ | ConvertTo-Json -Compress

                    Write-Host "Importing flags for Challenge ID: $($_.challenge_id)"
                    try{
                        $import_hints = Invoke-RestMethod -Method POST "$ctfd_url_api/hints" -ContentType "application/json" -Headers $ctfd_auth -Body $current_hints
                        Write-Host "Imported flag $($_.id) - $($import_hints.success)"
                    }catch{
                        Write-Host "Could not import hint: $($_.id) for challenge id: $($_.challenge_id)"
                        $_.Exception
                    }
                }

                # Import Page(s) 1 by 1
                Write-Host "Importing $($pages_object.results.count) page(s)"
                Pause
                $pages_object.results | ForEach-Object {
                    # Get current flag
                    $current_pages = $_ | ConvertTo-Json -Compress

                    Write-Host "Importing page: $($_.title)"
                    try{
                        $import_pages = Invoke-RestMethod -Method POST "$ctfd_url_api/pages" -ContentType "application/json" -Headers $ctfd_auth -Body $current_pages
                        Write-Host "Imported page $($_.title) - $($import_pages.success)"
                    }catch{
                        Write-Host "Could not import page: $($_.title)"
                        $_.Exception
                    }
                }

                # Import Config
                Write-Host "Importing $($config_object.results.count) config option(s)"
                Pause
                $config_object.results | ForEach-Object {
                    # Get current flag
                    $current_config = $_ | ConvertTo-Json -Compress

                    Write-Host "Importing config option: $($_.key)"
                    try{
                        $import_config = Invoke-RestMethod -Method POST "$ctfd_url_api/configs" -ContentType "application/json" -Headers $ctfd_auth -Body $current_config
                        Write-Host "Imported config option: $($_.key)- $($import_config.success)" -ForegroundColor Green
                    }catch{
                        Write-Host "Could not import config."
                        $_.Exception
                    }
                }

                # Import Files
                Write-Host "Importing $($files_object.results.count) file(s)"
                Pause
                $files_object.results | ForEach-Object {
                    # Get current flag
                    $current_file = $_ | ConvertTo-Json -Compress

                    Write-Host "Importing file: $($_.location)"
                    try{
                        $import_file = Invoke-RestMethod -Method POST "$ctfd_url_api/files" -ContentType "application/json" -Headers $ctfd_auth -Body $current_file
                        Write-Host "Imported file: $($_.location)- $($import_file.success)" -ForegroundColor Green
                    }catch{
                        Write-Host "Could not import config."
                        $_.Exception
                    }
                }

                $finished = $true
                break
            }
            '3' {
                # Reset CTFd
                # Setup up Auth header
                $ctfd_auth = Get-CTFd-Admin-Token

                # Get Challenges
                $challenges = Get-Challenges-From-CTFd

                # Remove Challenges 1 by 1
                Write-Host "Removing $($challenges.data.count) challenges"
                $challenges.data | ForEach-Object {
                    # Get all challenge details per challenge
                    $id = $_.id
                    $challenge_info = Invoke-RestMethod -Method Get "$ctfd_url_api/challenges/$id" -ContentType "application/json" -Headers $ctfd_auth
                    Write-Host "Removing challenge: $($challenge_info.data.name)"
                    try{
                        $remove_challenge = Invoke-RestMethod -Method Delete "$ctfd_url_api/challenges/$id" -ContentType "application/json" -Headers $ctfd_auth
                        Write-Host "Removed challenge $($challenge_info.data.name) - $($remove_challenge.success)"
                    }catch{
                        Write-Host "Could not remove challenge: $($challenge_info.data.name) - $id"
                        $_.Exception
                    }
                }

                $finished = $true
                break
            }
            '4' {
                # 4. Deploy Elastic Stack
                
                # Check to see if various parts of the project have already been configured to reduce the need for user input.
                # 1. Check to see if .env file exists with credentials.
                if ($(Invoke-CheckForEnv) -eq "False") {
                    # Choose to use docker or not. If no .env is found, then ask.
                    $dockerChoice = Read-Host "Would you like to use docker with this project? `
                1. Yes, please generate a secure .env file. (Recommended) `
                2. No thanks, I know what I am doing or I already have a .env file ready to go.`
                Please Choose (1 or 2)"
                
                    if ($dockerChoice -eq "1") {
                    # Generate a .env file with random passwords for Elasticsearch and Kibana. Also generate secure Kibana key for reporting funcationality.
                    $env = Get-Content .\docker\.env_template
                    
                    # Replace $elasticsearchPassword
                    $elasticsearchPassword = $(-Join (@('0'..'9';'A'..'Z';'a'..'z';'!';'@';'#') | Get-Random -Count 32))
                    $env = $env.Replace('$elasticsearchPassword', $elasticsearchPassword) 
                    
                    # Replace $kibanaPassword
                    $kibanaPassword = $(-Join (@('0'..'9';'A'..'Z';'a'..'z';'!';'@';'#') | Get-Random -Count 32))
                    $env = $env.Replace('$kibanaPassword', $kibanaPassword)
                
                    # Replace $kibanaEncryptionKey
                    $kibanaEncryptionKey = $(-Join (@('0'..'9';'A'..'Z';'a'..'z';'!';'@';'#') | Get-Random -Count 32))
                    $env = $env.Replace('$kibanaEncryptionKey', $kibanaEncryptionKey)
                
                    $env | Out-File .\docker\.env
                
                    Write-Host "New file has been created (.env) and is ready for use." -ForegroundColor Green
                    Write-Host "The following credentials will be used for setup and access to your Elastic stack so keep it close." -ForegroundColor Blue
                    Write-Host "Username : elastic`nPassword : $elasticsearchPassword"
                    Pause
                    } else {
                    Write-Debug "Did not choose to use docker so ignoring docker setup."
                    }
                } else {
                    Write-Debug "Docker .env file already exists with password skipping to next section."
                }
                
                # 2. Check to see if docker compose has been executed.
                if (Invoke-CheckForDockerInUse -eq "False") {
                    # Choose to start docker.
                    $startStack = Read-Host "Would you like to start up the Elastic stack with docker? `
                1. Yes, please run the docker commands to start the Elastic stack for me (Recommended) `
                2. No thanks, I will get my cluster up and running without your help and then continue the process `
                Please Choose (1 or 2)"
                
                    if ($startStack -eq "1") {
                        Invoke-StartDocker
                    } elseif ($startStack -eq "2") {
                        Write-Debug "Skipping to next part of the process."
                    } else {
                        Write-Debug "Not a valid option. Exiting."
                        exit
                    }
                } elseif (Invoke-CheckForDockerInUse -eq "True") {
                    Write-Host "Docker found to be running. Would you like to stop and then start Docker?"
                    $restartDocker = Read-Host "1. Yes, please restart Docker`n2. No, please leave it running.`nPlease Choose (1 or 2)"
                    if ($restartDocker -eq 1) {
                        Write-Host "Stopping current docker instances by bringing them down with docker compose down."
                        Invoke-StopDocker
                        Write-Host "Starting docker containers back upw tih docker compose up &"
                        Invoke-StartDocker
                    } else {
                        Write-Debug "Continuing with current docker instance running."
                    }
                } else {
                    Write-Host "Something is amiss, couldn't check to see if Docker was in use or not. Exiting." -ForegroundColor Yellow
                    exit
                }
                
                
                # Configure Elasticsearch credentials for creating the Elasticsearch ingest pipelines and importing saved objects into Kibana.
                # Force usage of elastic user by trying genereated creds first, then manual credential harvest
                if ($elasticsearchPassword) {
                    Write-Host "Elastic credentials detected! Going to use those for the setup process." -ForegroundColor Blue
                    $elasticsearchPasswordSecure = ConvertTo-SecureString -String "$elasticsearchPassword" -AsPlainText -Force
                    $elasticCreds = New-Object System.Management.Automation.PSCredential -ArgumentList "elastic", $elasticsearchPasswordSecure
                } else {
                    Write-Host "No generated credentials were found! Going to need the password for the elastic user." -ForegroundColor Yellow
                    # When no passwords were generated, then prompt for credentials
                    $elasticCreds = Get-Credential elastic
                }
                
                # Set passwords via automated configuration or manual input
                # Base64 Encoded elastic:secure_password for Kibana auth
                $elasticCredsBase64 = [convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($($elasticCreds.UserName+":"+$($elasticCreds.Password | ConvertFrom-SecureString -AsPlainText)).ToString()))
                $kibanaAuth = "Basic $elasticCredsBase64"
                
                # Extract custom settings from configuration.json
                $configurationSettings = Get-Content ./configuration.json | ConvertFrom-Json
                
                $elasticsearchURL = $configurationSettings.elasticsearchURL
                $elasticsearchAPIKey = $configurationSettings.elasticsearchAPIKey
                $kibanaURL = $configurationSettings.kibanaURL
                $tag = $configurationSettings.tag
                $initializationComplete = $configurationSettings.initializedElasticStack
                     
                # 3. Check to see if Elasticsearch is available for use.
                Invoke-CheckForElasticsearchStatus
                
                # Create API Key if not found in the config.
                if ("" -eq $elasticsearchAPIKey){
                    Write-Host "No API key found, going to generate a key for the helium indices nows."
                    #POST _security/api_key
                    $apiKey = Get-Content ./setup/api_key_creation.json
                
                    # API Key URL
                    $apiKeyCreationIndexURL = $elasticsearchURL+"/_security/api_key"
                    try {
                    $apiKey = Invoke-RestMethod -Method POST -Uri $apiKeyCreationIndexURL -body $apiKey -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck
                    
                    # Store API key in Elastic
                    $configurationSettings.elasticsearchAPIKey = $apiKey.encoded
                
                    $configurationSettings | Convertto-JSON | Out-File ./configuration.json -Force
                    } catch {
                    Write-Host "Couldn't bootstrap helium index, likely because it already exists. Check kibana to see if the helium index exists."
                    Write-Debug "$_"
                    }
                }
                
                # Static and Constant core variables needed for initialization and usage of this product. 
                # Please don't modify unless you know what you are doing.
                $indexName = "helium-enriched"
                $baseIndexName = "helium"
                $pipelineName = "Helium_Enrichment"
                
                
                # Bootstrap helium index
                Write-Host "Bootstrapping helium index in preparation for data ingest." -ForegroundColor Blue
                $bootstrapIndexURL = $elasticsearchURL+"/helium"
                try {
                    Invoke-RestMethod -Method PUT -Uri $bootstrapIndexURL -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck
                } catch {
                    Write-Host "Couldn't bootstrap helium index, likely because it already exists. Check kibana to see if the helium index exists." -ForegroundColor Yellow
                    Write-Debug "$_"
                }
                
                # The final step is to import the Visualizations and Dashboards
                Write-Host "Last step! Importing saved visualizations and dashboard objects to visualize the data." -ForegroundColor DarkMagenta
                Import-IndexPattern "./setup/dashboard_objects_helium.ndjson"
                
                $configurationSettings.initializedElasticStack = "true"
                $configurationSettings | Convertto-JSON | Out-File ./configuration.json -Force
                
                Write-Host "But first, please navigate to your Kibana dashboard to make sure you have some data.`nCopy and Paste the URL below to navigate to the dashboard that was created (ctrl-click might not work):" -ForegroundColor Yellow
                Write-Host $kibanaUrl'/app/dashboards#/view/c61c6ad0-13cc-11ec-b374-9dc91dfe0453?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-4y,to:now))' -ForegroundColor DarkCyan
                Write-Host "Username : elastic`nPassword : $elasticsearchPassword"

                $finished = $true
                break
            }
            '5' {
                # 5. Import Objects and Index Documents for Elastic Stack
                Write-Host "Option not available, yet."

                $finished = $true
                break
            }
            '6' {
                # 6. Reset Elastic Stack
                Write-Host "Option not available, yet."

                $finished = $true
                break
            }
            '7' {
                # 7. Check for Requirements
                Write-Host "Option not available, yet."
                # Check for running Elastic Stack
                # Check for running CTFd

                $finished = $true
                break
            }
            '8' {
                # Deploy all from scratch!
                Write-Host "Option not available, yet."

                $finished = $true
                break
            }
            {"q","Q"} {
                Write-Host "You selected quit, exiting." -ForegroundColor Yellow

                $finished = $true
                break
            }
            default {
                Write-Host "Invalid choice. Please select a valid option."
                $finished = $true
                break
            }
        }
    }
}

End {
    Write-Host "This is the end. Thanks for using this script!" -ForegroundColor Blue
    $finished = $null
}


<# TESTING
#$ctfd_username = "admin"
#$ctfd_password = ""
#$ctfd_email = "admin@fake.domain"
#$ctfd_email = Read-Host "Enter email address used for CTFd account."
$ctfd_basic_creds = Get-Credential
# Create Basic Auth object (Not used)
$auth_object = [PSCustomObject]@{
    name = $ctfd_basic_creds.UserName
    #email = $ctfd_email
    password = (New-Object PSCredential 0, $ctfd_basic_creds.Password).GetNetworkCredential().Password
    #type = "user"
    #verified = $False
    #hidden = $False
    #banned = $False
    #fields = @()
} | ConvertTo-Json -Compress

# Import challenges
$challenges_object
$current_challenge = $challenges_object.results[9] | ConvertTo-Json -Compress -Depth 10
$current_challenge_object = $challenges_object.results[9]
$dynamic_challenge_details = $dynamic_challenges_object.results | Where-Object {$_.id -eq $challenges_object.results[9].id}
$dynamic_challenge_details.PSObject.Members | Where-Object {$_.MemberType -eq "NoteProperty"} | ForEach-Object {
    $current_challenge_object | Add-Member -NotePropertyName $_.Name -NotePropertyValue $_.Value
    $current_challenge = $current_challenge_object | ConvertTo-Json -Compress -Depth 10
}
try{
    $test = Invoke-RestMethod -Method POST "$ctfd_url_api/challenges" -ContentType "application/json" -Headers $ctfd_auth -Body $current_challenge

}catch{
    $_.Exception
}
# TESTING#>