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

    # Extract custom settings from configuration.json
    $configurationSettings = Get-Content ./configuration.json | ConvertFrom-Json
    
    if($null -eq $Elasticsearch_URL){$Elasticsearch_URL = $configurationSettings.Elasticsearch_URL}
    if($null -eq $Kibana_URL){ $Kibana_URL= $configurationSettings.Kibana_URL}

    # Elasticsearch Variables
    $ingestIndexURL = $Elasticsearch_URL+"/logs-kibana-ctf/_doc"
    $indexTemplateURL = $Elasticsearch_URL+"/_index_template/logs-kibana-ctf"
    $ctfUserRoleURL = $Elasticsearch_URL+"/_security/role/Kibana CTF"
    $ctfUserCreateURL = $Elasticsearch_URL+"/_security/user/kibana-ctf"
    $indexTemplate = Get-Content ./setup/Elastic/index_template.json
    $ctfUserRole = Get-Content ./setup/Elastic/kibana_ctf_role.json
    $ctfUserCreate = Get-Content ./setup/Elastic/kibana_ctf_user.json

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
            $validate = Invoke-RestMethod -Method GET -Uri "$CTFd_URL_API/pages" -ContentType "application/json" -Headers $ctfd_auth
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

    function Invoke-Import-CTFd-Challenge {
        param(
            $challenge_file_path
        )
        $ctfd_challenge = Get-Content $challenge_file_path | ConvertFrom-Json -Depth 10
        # Set connection info
        $ctfd_challenge.connection_info = $ctfd_challenge.connection_info.Replace("http://127.0.0.1:5601",$Kibana_URL)

        Write-Host "Importing challenge: $($ctfd_challenge.name)"
        $current_challenge = $ctfd_challenge | ConvertTo-Json -Depth 10
        try{
            $import_challenge = Invoke-RestMethod -Method POST "$CTFd_URL_API/challenges" -ContentType "application/json" -Headers $ctfd_auth -Body $current_challenge
            Write-Host "Imported challenge $($ctfd_challenge.name) - $($import_challenge.success)"
        }catch{
            Write-Host "Could not import challenge: $($ctfd_challenge.name) - $($ctfd_challenge.id)"
            $_.Exception
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

            Write-Host "Importing flags for Challenge ID: $($ctfd_flag.challenge_id)"
            try{
                $import_flag = Invoke-RestMethod -Method POST "$CTFd_URL_API/flags" -ContentType "application/json" -Headers $ctfd_auth -Body $current_flag
                Write-Host "Imported flag $($_.id) - $($import_flag.success)"
            }catch{
                Write-Host "Could not import flag: $($current_challenge.name) - $($_.id)"
                $_.Exception
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

        Write-Host "Importing hint for Challenge ID: $($ctfd_hint.challenge_id)"
        try{
            $import_hints = Invoke-RestMethod -Method POST "$CTFd_URL_API/hints" -ContentType "application/json" -Headers $ctfd_auth -Body $current_hint
            Write-Host "Imported hint $($_.id) - $($import_hints.success)"
        }catch{
            Write-Host "Could not import hint: $($_.id) for challenge id: $($ctfd_hint.challenge_id)"
            $_.Exception
        }
    }

    # Elastic Stack Setup Functions
    function Invoke-CheckForEnv {
        # Check for existing .env file for setup
        # Get Elasticsearch password from .env file
        if (Test-Path .\setup\Elastic\docker_elastic_stack\.env) {
            Write-Host "Docker .env file found! Which likely means you have configured docker for use. Going to extract password to perform initialization."
            $env = Get-Content .\setup\Elastic\docker_elastic_stack\.env
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
        Write-Debug "Using the URL: $healthAPI"
        # Keep checking for a healthy cluster that can be used for the initialization process!
        do {
            try {
                Write-Debug "Checking to see if the cluster is accessible. Please wait."
                $status = Invoke-RestMethod -Method Get -Uri $healthAPI -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck  
            } catch {
                Write-Debug "Waiting for healthy cluster for 5 seconds. Then checking again."
                $_.Exception
                $status
                Start-Sleep -Seconds 5
            }
        } until ("yellow" -eq $status.status -or "green" -eq $status.status)
    
        if ("yellow" -eq $status.status -or "green" -eq $status.status) {
        Write-Host "Elastic cluster is $($status.status), continuing through the setup process." -ForegroundColor Green
        Start-Sleep -Seconds 2
        }
    }

    function Invoke-CheckForInUsePorts {
        $ports = @("9200", "5601")
        Write-Host "Checking for Elasticsearch (9200) and Kibana (5601) ports being in use before starting docker."
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
        Set-Location .\setup\Elastic\docker_elastic_stack
        try {
            $composeVersion = docker compose version
            if($composeVersion){
                Write-Debug '"docker compose detected"'
                $checkInUsePorts = Invoke-CheckForInUsePorts
                if($checkInUsePorts){
                    Write-Host "Ports detected already in use. Make sure these ports are available before continuing. Exiting."
                    exit
                }else{
                    docker compose up -d
                }
                Write-Host "Elastic Stack containers started, navigate to $Kibana_URL to ensure it started okay.`nNote: It could a few minutes to get the Elastic stack running so be patient.)" -ForegroundColor Green
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
        Set-Location ..\..\..\
    }
    
    function Invoke-StopDocker {
        Write-Debug "Shutting down docker containers for the Elastic stack."
        Set-Location .\setup\Elastic\docker_elastic_stack
        try { 
            docker compose down
        } catch {
            Write-Host "Failed to use docker compose down, so trying docker-compose down."
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
            #"imageUrl" = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAD4AAABACAYAAABC6cT1AAAGf0lEQVRoQ+3abYydRRUH8N882xYo0IqagEVjokQJKAiKBjXExC9G/aCkGowCIghCkRcrVSSKIu/FEiqgGL6gBIlAYrAqUTH6hZgQFVEMKlQFfItWoQWhZe8z5uzMLdvbfbkLxb13d+fbvfe588x/zpn/+Z9zJpmnI81T3BaAzzfLL1h8weLzZAcWXH2eGHo7zAWLL1h8nuzAjFw9G1N6Kzq8HnuM36MR8iibF3Fv4q+7cv8yDV6K13bYq2furSP8Ag8ncr/vnSnwRViJT2GfCV7yL1yHGxLb+l3EdM9lluNEnIC9xz+f2ZL4Er6Z2DrdXN3fZwp8CU7OfDHxggle8lTLbQ1nJ/7Z7yKmey5zYGZt4h2IzR8/trRc2PDlxJPTzfVcgJ+CC0wMPOa9F6cm7up3EVM9V9386MxliVdM8GwAv6hh/awCz/w7lY25OtF5ruBz4ZLP42NYNrDAFbC3YPWuILnMAfgq3oaRQQYea/stViV+sgssvjKzLvGySeaaNVfP4d7Btokgvxj/bblgpueuF1hmWcyTCmfE3J3M1lTcv0vMswM88zR+jpw4osu6me8kzkpsfLZWzxyRuabO22buxxOJ12FxnXfWgEe83pB5sOE47BsLymzscOoi7nw2JJfZreUjiUsTyzKPZm5NvBDvSuw268AzNzV8H5/Am+qCnsAXgpgSW2Zq9cyKlksbPlTd+te4quWNieMHBfiNDdciYnwsdI/MaOaWhnMTf54J8CqNj8x8JXFIZltYu+HqlmNT8YSBsHgAPw/vxvlVV4du/s0oaxbxg0TbL/jMni0nNcVjQq7+HZfgtpbzBg342TgQ63AkmsymxBW4IjE6A+D7Vzd/fyWxIM/VuCe+HzTgZ2Jpy/kNJ2FJLmLm24mPJ/42A+Bvrxt4SISwlhsaPodH26LZB8rVA3inwwebsrixJCZzX+KMxI/7AV61eVh3DV6Mx3EOvh4kN6jAg8nfUCXm4d1wE66OyxNPTQc+s3/o/MoXizL3JE5O3F3P/uBZPPF4Zr+Wi5uSO48ZPRdyCwn7YB/A35m5KhWNHox4fcNnIs0ddOCRSBxf8+cQG+Huf0l8NJVYP+nI7NXy2ar4QqIGm69JfKPOE2w/mBavCzwM11R2D+ChsUO7hyUfmwx55qDM1xJvqZ7y08TpifuGBfjeURVJnNIVGpkNiXNS0ds7jcySDitDCCWW56LJ10fRo8sNA+3qXUSZD2CtQlZh9T+1rB7h9oliembflnMbzqgSNZKbKGHdPm7OwXb1CvQ1metSETMpszmzvikCJNh/h5E5PHNl4qga/+/cxqrdeWDYgIe7X5L4cGJPJX2940lOX8pD41FnFnc4riluvQKbK0dcHJFi2IBHNTQSlguru4d2/wPOTNzRA3x5y+U1E1uqWDkETOT026XuUJzx6u7ReLhSYenQ7uHua0fKZmwfmcPqsQjxE5WVONcRxn7X89zgn/EKPMRMxOVQXmP18Mx3q3b/Y/0cQE/IhFtHESMsHFlZ1Ml3CH3DZPHImY+pxcKumNmYirtvqMBfhMuU6s3iqOQkTsMPe1tCQwO8Ajs0lxr7W+vnp1MJc9EgCNd/cy6x+9D4veXmprj5wxMw/3C4egW6zzgZOlYZzfwo3F2J7ael0pJamvlPKgWNKFft1AAcKotXoFEbD7kaoSoQPVKB35+5KHF0lai/rJo+up87jWEE/qqqwY+qrL21LWLm95lPJ16ppKw31XC3PXYPJauPEx7B6BHCgrSizRs18qiaRp8tlN3ueCTYPHH9RNaunjI8Z7wLYpT3jZSCYXQ8e9vTsRE/q+no3XMKeObgGtaintbb/AvXj4JDkNw/5hrwYPfIvlZFUbLn7G5q+eQIN09Vnho6cqvnM/Lt99RixH49wO8K0ZL41WTWHoQzvsNVkOheZqKhEGpsp3SzB+BBtZAYve7uOR9tuTaaB6l0XScdYfEQPpkTUyHEGP+XqyDBzu+NBCITUjNWHynkrbWKOuWFn1xKzqsyx0bdvS78odp0+N503Zao0uCsWuSIDku8/7EO60b41vN5+Ses9BKlTdvd8bhp9EBvJjWJAIn/vxwHe6b3tSk6JFPV4nq85oAOrx555v/x/rh3E6Lo+bnuNS4uB4Cuq0ZfvO8X1rM6q/+vnjLVqZq7v83onttc2oYF4HPJmv1gWbB4P7s0l55ZsPhcsmY/WBYs3s8uzaVn5q3F/wf70mRuBCtbjQAAAABJRU5ErkJggg=="
            "initials" = "KC"
            "description" = "This is the Kibana CTF Space! Let's go!!!"
            "disabledFeatures"=  @("enterpriseSearch","logs","infrastructure","apm","inventory","uptime","observabilityCasesV2","slo","siem","securitySolutionCasesV2","dev_tools","advancedSettings","filesManagement","filesSharedImage","savedObjectsManagement","savedObjectsTagging","osquery","actions","generalCasesV2","guidedOnboardingFeature","rulesSettings","maintenanceWindow","stackAlerts","fleetv2","fleet","dataQuality","monitoring","canvas","maps","ml","dashboard")
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

        if($result.errors -or $null -eq $result){
            Write-Host "There was an error trying to import the Kibana CTF Space." -ForegroundColor Yellow
            $result.errors
        }else{
            Write-Host "Created Kibana CTF Space!" -ForegroundColor Green
        }
    }

    function Invoke-Create-Kibana-CTF-User-Role {
        try {
            Write-Host "Creating role that will be applied to the kibana-ctf user during the user creation process following this step."
            $result = Invoke-RestMethod -Method PUT -Uri $ctfUserRoleURL -Body $ctfUserRole -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck
            Write-Host "Created CTF User Role: $($result.role.created)"
        } catch {
            Write-Host "Couldn't create role for CTF user. Check Kibana to see if the Kibana CTF role already exists." -ForegroundColor Yellow
            Write-Host "$_"
        }
    }

    function Invoke-Create-Kibana-CTF-User {
        try {
            Write-Host "Creating user that should be used to compete in the CTF with the Kibana CTF role mapping."
            $result = Invoke-RestMethod -Method PUT -Uri $ctfUserCreateURL -Body $ctfUserCreate -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck
            Write-Host "Created kibana-ctf user: $($result.created)"
            Write-Host "Credentials for the Kibana CTF user are:`nusername: kibana-ctf`npassword: kibana-ctf--please-change-me" -ForegroundColor Green
            Write-Host "If you wish to create more users, use the elastic account that the setup used before and create and number users you wish. `nJust make sure to add the Kibana CTF role to their account." -ForegroundColor Yellow
            Write-Host "Test user credentials by navigating to $Kibana_URL/s/kibana-ctf/app/home#/ and logging in with the kibana-ctf user." -ForegroundColor Yellow
        } catch {
            Write-Host "Couldn't create kibana-ctf user. Check Kibana to see if the user already exists." -ForegroundColor Yellow
            Write-Host "$_"
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
                Write-Host "Couldn't ingest CTF data. Check Kibana to see if the ctf data already exists, if it does, this is okay." -ForegroundColor Yellow
                Write-Debug "$_"
            }
        }else{
            try {
                $result = Invoke-RestMethod -Method POST -Uri $ingestIndexURL -Body $documentToIngest -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck
            } catch {
                Write-Host "Couldn't ingest CTF data. Check Kibana to see if the ctf data already exists, if it does, this is okay." -ForegroundColor Yellow
                Write-Debug "$_"
            }
        }

        return $result
    }

    function Invoke-Create-Index-Template {
        try {
            Write-Host "Creating Index Template for challenges then setup will be complete."
            $result = Invoke-RestMethod -Method PUT -Uri $indexTemplateURL -Body $indexTemplate -ContentType "application/json" -Credential $elasticCreds -AllowUnencryptedAuthentication -SkipCertificateCheck
            Write-Host "Created Index Template: $($result.acknowledged)"
        } catch {
            Write-Host "Couldn't create Index Template for ctf data. Check Kibana to see if the Index Template already exists." -ForegroundColor Yellow
            Write-Host "$_"
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
    
    $option1 = "1. Deploy CTFd"
    $option2 = "2. Deploy Elastic Stack"
    $option3 = "3. Import Flags (CTFd) + Challenges (Elastic Stack)"
    $option4 = "4. Delete CTFd"
    $option5 = "5. Delete Elastic Stack"
    $option6 = "6. Check for Requirements"
    $option7 = "7. Deploy everything from scratch (Recommended - Performs Options 1, 2 & 3 in sequence)"

    $challenge_option0 = "0. All Challenges (Recommended)"
    $challenge_option1 = "1. Discover Challenges Only"
    $challenge_option2 = "2. ES|QL Challenge Only"

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

        Write-Host $quit
    }

    function Show-CTF-Challenges-Menu {
        Write-Host "Which Kibana CTF Challenge Categories would you like to import?`nNote: This will import CTFd challenges and required Elastic resources." -ForegroundColor Yellow
        Write-Host $challenge_option0
        Write-Host $challenge_option1
        Write-Host $challenge_option2

        Write-Host $quit
    }

    function Invoke-CTFd-Deploy {
        # 1. Deploy CTFd

        # Check to see if CTFd has been deployed, and if not, ask to deploy.
        try{
            $pathForCTFd = Get-Item ../CTFd -ErrorAction Ignore
        }catch{
            Write-Host "CTFd path does not exist."
        }
        if($null -ne ($pathForCTFd)){
            $runCTFd = Read-host "CTFd directory detected! Would you like to run CTFd via docker? (Y/n)"
            if($runCTFd -match "y" -or $runCTFd -eq ""){
                Set-Location ../CTFd
                Write-Host "Bringing CTFd up! (Use docker compose down anytime from the CTFd directory to stop the container)" -ForegroundColor Green
                docker compose up -d
                Set-Location ../kibana-ctf/
                Write-Host "CTFd downloaded and began the process to bring it up. Navigate to $CTFd_URL to continue the setup process.`nNote: It could take a few minutes for the container to come up." -ForegroundColor Green
            }else{
                Write-Host "You said no, you do not wish to run CTFd, exiting." -ForegroundColor Yellow
            }
        }else{
            $runCTFd = Read-host "CTFd directory not detected, would you like to download and run CTFd via docker? (Y/n)"
            if($runCTFd -match "y" -or  $runCTFd -eq ""){
                Set-Location ../
                git clone https://github.com/CTFd/CTFd.git
                Set-Location ./CTFd/
                Write-Host "Bringing CTFd up! (Use docker compose down anytime from the CTFd directory to stop the container)" -ForegroundColor Green
                docker compose up -d
                Set-Location ../kibana-ctf/
                Write-Host "CTFd downloaded and began the process to bring it up. Navigate to $CTFd_URL to continue the setup process.`nNote: It could take a few minutes for the container to come up." -ForegroundColor Green
                Write-Host "Refer to ReadMe `"How to get started`" for next steps. (https://github.com/nicpenning/kibana-ctf?tab=readme-ov-file#how-to-get-started)"
                Write-Host "Once finished from the steps provided, run the script again and run option 2. to begin the setup for the Elastic Stack instance."
                Pause
            }else{
                Write-Host "You said no, you do not wish to deploy and run CTFd, exiting." -ForegroundColor Yellow
            }
        }
    }

    function Invoke-Elastic-Stack-Deploy {
        # 2. Deploy Elastic Stack
        
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
                $env = Get-Content .\setup\Elastic\docker_elastic_stack\.env_template
                
                # Replace $elasticsearchPassword
                $elasticsearchPassword = $(-Join (@('0'..'9';'A'..'Z';'a'..'z';'!';'@';'#') | Get-Random -Count 32))
                $env = $env.Replace('$elasticsearchPassword', $elasticsearchPassword) 
                
                # Replace $kibanaPassword
                $kibanaPassword = $(-Join (@('0'..'9';'A'..'Z';'a'..'z';'!';'@';'#') | Get-Random -Count 32))
                $env = $env.Replace('$kibanaPassword', $kibanaPassword)
            
                # Replace $kibanaEncryptionKey
                $kibanaEncryptionKey = $(-Join (@('0'..'9';'A'..'Z';'a'..'z';'!';'@';'#') | Get-Random -Count 32))
                $env = $env.Replace('$kibanaEncryptionKey', $kibanaEncryptionKey)
            
                $env | Out-File .\setup\Elastic\docker_elastic_stack\.env
            
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

        # 3. Check to see if Elasticsearch is available for use.
        Invoke-CheckForElasticsearchStatus
        
        $configurationSettings.initializedElasticStack = "true"
        $configurationSettings | Convertto-JSON | Out-File ./configuration.json -Force
        
        Write-Host "But first, please navigate to your Kibana instance to make sure you can log in.`nCopy and Paste the URL below to navigate to Kibana (ctrl-click might not work):" -ForegroundColor Yellow
        Write-Host "Kibana instance up and runnin here --> $Kibana_URL" -ForegroundColor DarkCyan
        Write-Host "Username : elastic`nPassword : $elasticsearchPassword"
        Write-Host "Proceed once you have confirmed you can log in to Kibana with the elastic user." -ForegroundColor Yellow
        Pause

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

        # Setup up Auth header
        $ctfd_auth = Get-CTFd-Admin-Token

        # Extract custom settings from configuration.json if it exists
        $configurationSettings = Get-Content ./configuration.json | ConvertFrom-Json
        if("" -ne $configurationSettings.Elasticsearch_URL){
            $Elasticsearch_URL = $configurationSettings.Elasticsearch_URL
            Write-Host "Elasticsearch URL detected: $Elasticsearch_URL" -ForegroundColor Green
        }
        if("" -ne $configurationSettings.Kibana_URL){
            $Kibana_URL = $configurationSettings.Kibana_URL
            Write-Host "Kibana URL detected: $Kibana_URL" -ForegroundColor Green
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
        Write-Host "Going to need the password for the elastic user. Checking for generated creds now." -ForegroundColor Yellow
        $elasticCredsCheck = Invoke-CheckForEnv
        # Set passwords via automated configuration or manual input
        # Base64 Encoded elastic:secure_password for Kibana auth
        if($($elasticCredsCheck)[0] -eq "True"){
            $elasticPass = ConvertTo-SecureString -String $($($elasticCredsCheck)[1]) -AsPlainText -Force
            $elasticCreds = New-Object System.Management.Automation.PSCredential("elastic", $elasticPass)
        }else{
            $elasticCreds = Get-Credential elastic
        }
        $elasticCredsBase64 = [convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($($elasticCreds.UserName+":"+$($elasticCreds.Password | ConvertFrom-SecureString -AsPlainText)).ToString()))

        $kibanaAuth = "Basic $elasticCredsBase64"
                
        # Check to see if Elasticsearch is available for use.
        Invoke-CheckForElasticsearchStatus

        # Ingesting Dummy Documents
        Write-Host "Ingesting documents for challenges" -ForegroundColor Blue
        $fakeCount = 0
        Write-Host "Ingesting 2.5K documents, please wait. This could take a few minutes."
        do{
            $dummyDocument = Invoke-Generate-FakeEvent
            $ingestDocs = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $dummyDocument
            $fakeCount++
            if((500, 1000, 1500, 2000) -contains $fakeCount){
                Write-Host "Total documents ingested: $fakeCount"
            }
        }while($fakeCount -lt 2500)

        # Import Kibana CTF Dashboard
        Write-Host "Importing Kibana CTF Dashboard" -ForegroundColor Blue
        Import-SavedObject "./setup/Elastic/kibana_dashboard.ndjson"

        # Challenges Discover - Import
        if((0, 1) -contains $CTF_Options_Selected){
            # Import Discover Challenges for CTFd
            Invoke-Import-CTFd-Challenge './challenges/Discover/1/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/Discover/2/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/Discover/4/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/Discover/3/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/Discover/5/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/Discover/7/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/Discover/6/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/Discover/8/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/Discover/9/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/Discover/10/ctfd_challenge.json'

            # Dynamically Generate Flags for Discover Challenges
            . ./challenges/Discover/8/dynamic_flag.ps1; dynamic_flag

            # Import Discover Challenge Flags for CTFd
            Invoke-Import-CTFd-Flag './challenges/Discover/1/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/Discover/2/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/Discover/3/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/Discover/4/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/Discover/5/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/Discover/6/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/Discover/7/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/Discover/8/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/Discover/9/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/Discover/10/ctfd_flag.json'

            # Import Discover Challenge Hints for CTFd
            Invoke-Import-CTFd-Hint './challenges/Discover/1/ctfd_hint.json'
            Invoke-Import-CTFd-Hint './challenges/Discover/7/ctfd_hint.json'
            Invoke-Import-CTFd-Hint './challenges/Discover/10/ctfd_hint.json'

            # Import Discover Challenges for Elastic
            . ./challenges/Discover/5/elastic_import_script.ps1; challenge
            . ./challenges/Discover/6/elastic_import_script.ps1; challenge
            . ./challenges/Discover/9/elastic_import_script.ps1; challenge
            . ./challenges/Discover/10/elastic_import_script.ps1; challenge

            Import-SavedObject "./challenges/Discover/1/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/Discover/2/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/Discover/3/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/Discover/5/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/Discover/8/elastic_saved_objects.ndjson"
        }
        
        # Challenges ES|QL - Import
        if((0, 2) -contains $CTF_Options_Selected){
            # Import ES|QL Challenges for CTFd
            Invoke-Import-CTFd-Challenge './challenges/ES_QL/2/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/ES_QL/1/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/ES_QL/3/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/ES_QL/4/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/ES_QL/5/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/ES_QL/6/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/ES_QL/7/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/ES_QL/8/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/ES_QL/9/ctfd_challenge.json'
            Invoke-Import-CTFd-Challenge './challenges/ES_QL/10/ctfd_challenge.json'

            # Import ES|QL Challenge Flags for CTFd
            Invoke-Import-CTFd-Flag './challenges/ES_QL/1/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/ES_QL/2/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/ES_QL/3/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/ES_QL/4/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/ES_QL/5/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/ES_QL/6/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/ES_QL/7/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/ES_QL/8/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/ES_QL/9/ctfd_flag.json'
            Invoke-Import-CTFd-Flag './challenges/ES_QL/10/ctfd_flag.json'

            # Import ES|QL Challenge Hints for CTFd
            Invoke-Import-CTFd-Hint './challenges/ES_QL/7/ctfd_hint.json'
            Invoke-Import-CTFd-Hint './challenges/ES_QL/8/ctfd_hint.json'
            Invoke-Import-CTFd-Hint './challenges/ES_QL/9/ctfd_hint.json'
            Invoke-Import-CTFd-Hint './challenges/ES_QL/10/ctfd_hint.json'

            # Import ES|QL Challenges for Elastic
            . ./challenges/ES_QL/2/elastic_import_script.ps1; challenge
            . ./challenges/ES_QL/6/elastic_import_script.ps1; challenge
            . ./challenges/ES_QL/8/elastic_import_script.ps1; challenge
            . ./challenges/ES_QL/9/elastic_import_script.ps1; challenge
            . ./challenges/ES_QL/10/elastic_import_script.ps1; challenge

            Import-SavedObject "./challenges/ES_QL/1/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/ES_QL/2/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/ES_QL/3/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/ES_QL/4/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/ES_QL/5/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/ES_QL/6/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/ES_QL/7/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/ES_QL/8/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/ES_QL/9/elastic_saved_objects.ndjson"
            Import-SavedObject "./challenges/ES_QL/10/elastic_saved_objects.ndjson"

        }

        #Challenges Dashboards - Import
        if((0, 3) -contains $CTF_Options_Selected){
            # Import Dashboard Challenges for CTFd
            Invoke-Import-CTFd-Challenge './challenges/Dashboards/1/ctfd_challenge.json'

            # Dynamically Generate Flags for Dashboard Challenges
            # . ./challenges/Dashboards/X/dynamic_flag.ps1; dynamic_flag

            # Import Dashboards Challenge Flags for CTFd
            # Invoke-Import-CTFd-Flag './challenges/Dashboards/1/ctfd_flag.json'

            # Import Dashboards Challenge Hints for CTFd
            # Invoke-Import-CTFd-Hint './challenges/Dashboards/X/ctfd_hint.json'

            # Import Dashboards Challenges for Elastic
            # . ./challenges/Dashboards/1/elastic_import_script.ps1; challenge

            Import-SavedObject "./challenges/Dashboards/1/elastic_saved_objects.ndjson"
        }

        # Retrieve challenges from challenges.json file and convert it into an object
        $pages_object = Get-Content './setup/CTFd/pages.json' | ConvertFrom-Json -Depth 10
        $config_object = Get-Content './setup/CTFd/config.json' | ConvertFrom-Json -Depth 10

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

        # Import Logo
        Write-Host "Importing logo for home page"
        Pause
        $form = @{
            "page_id" = 1
            "type" = "page"
            "file" = Get-Item -Path "images/DALLE_Capture_The_Flag_logo.webp"
            "location" = "9e66f558e02ce69471d071f5d9a049c0/DALLE_Capture_The_Flag_logo.webp"
        }
        $response = Invoke-RestMethod -Method POST -Uri "$CTFd_URL_API/files" -Headers $ctfd_auth -Form $form
        Write-Host "Imported $filePath`: $($response.success)"
    }

    function Invoke-Remove-CTFd {
        $continue = Read-Host "This action is destructive and will remove all CTFd resources such as the containers which in turn will lose all progress, users, flags, etc. Please backup your CTF using the UI if possible (https://docs.ctfd.io/docs/exports/ctfd-exports). If you wish to continue please type in: `nDELETE-CTFd-Instance"
        if($continue -ne "DELETE-CTFd-Instance"){
            Write-Host "Proper response was not entered, exiting."
            $finished = $true
            break
        }
        Write-Host "Deleting all CTFd containers and data now using: docker compose down --volumes --rmi all --remove-orphans" -ForegroundColor Yellow

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
                $_.Exception
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
        Write-Host "Deleting all Elastic stack data now..." -ForegroundColor Yellow
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
                Write-Host "Checking for correct versions of PowerShell and that Docker/Docker Compose exists"

                # Check for PowerShell
                if ($PSVersionTable.PSVersion.Major -lt 7 -or ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -lt 4)) {
                    Write-Host "This script requires PowerShell 7.4 or newer. Current version: $($PSVersionTable.PSVersion)" -ForegroundColor "Yellow"
                }else{
                    Write-Host "PowerShell requirement met. This script requires PowerShell 7.4 or newer. Current version: $($PSVersionTable.PSVersion)" -ForegroundColor "Green"
                }

                # Check for Docker
                if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
                    Write-Host "Docker is not installed or not in PATH." -ForegroundColor "Yellow"
                }else{
                    Write-Host "Docker requirement met. This script requires docker and was found in PATH." -ForegroundColor "Green"
                }

                # Check for Docker Compose
                $composeVersion = docker compose version
                if($composeVersion){
                    Write-Host "Docker Compose requirement met. $composeVersion detected" -ForegroundColor "Green"
                }else{
                    Write-Host "Docker Compose not detected, will now check for docker-compose" -ForegroundColor "Yellow"
                }

                # Check for running Elastic Stack (Future use case if needed)
                # Check for running CTFd (Future use case if needed)

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
