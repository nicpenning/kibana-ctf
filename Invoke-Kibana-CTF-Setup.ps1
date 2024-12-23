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

.EXAMPLE
   .\Invoke-Kibana-CTF-Setup.ps1 -Elasticsearch_URL "http://127.0.0.1:9200" -Kibana_URL "https://127.0.0.1:5601" -CTFd_URL "http://127.0.0.1:8000"
#>

Param (

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

    $option1 = "1. Deploy CTFd"
    $option2 = "2. Import CTFd Challenges (All or Specfic Challenges)"
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
    $ctfd_token = Get-CTFd-Creds
    $ctfd_auth = @{"Authorization" = "Token $ctfd_token"}

    # Elastic Stack Variables
    $elasticserach_url = "https://127.0.0.1:9200"
    $kibana_url = "https://127.0.0.1:5601"
}

Process {

    while ($true -ne $finished) {
        # Show Menu if script was not provided the choice on execution using the Option_Selected variable
        if ($null -eq $Option_Selected) {
            Show-Menu
            $Option_Selected = Read-Host "Enter your choice"
        }

        switch ($Option_Selected) {
            '1' {
                 # Options
                # 1. Deploy CTFd
                # git clone https://github.com/CTFd/CTFd.git
                # cd CTFd
                # docker compose up
            }
            '2' {
                # 2. Import CTFd Challenges (All or Specfic Challenges)

                # Retrieve challenges from challenges.json file and convert it into an object
                $challenges_object = Get-Content './CTFd_Events/JSON Configuration Files/challenges.json' | ConvertFrom-Json -Depth 10
                $dynamic_challenges_object = Get-Content './CTFd_Events/JSON Configuration Files/dynamic_challenge.json' | ConvertFrom-Json -Depth 10

                # Import Challenges 1 by 1
                Write-Host "Importing $($challenges_object.results.count) challenges"
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
            }
            '3' {
                # 3. Reset CTFd

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
            }
            '4' {
                # 4. Deploy Elastic Stack
            }
            '5' {
                # 5. Import Objects and Index Documents for Elastic Stack
            }
            '6' {
                # 6. Reset Elastic Stack
            }
            '7' {
                # 7. Check for Requirements
                # Check for running Elastic Stack
                # Check for running CTFd
            }
            '8' {
                # Deploy all from scratch!
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