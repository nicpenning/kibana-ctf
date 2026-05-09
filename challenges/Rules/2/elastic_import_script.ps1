# Advanced Elastic Stack Import Script for Challenge: High Quality Rules Only - No Exceptions!
# This script will help you import the necessary resources into Elastic Stack for the challenge.
# Make sure to customize the script as needed before running.
function challenge {
    # Create an exception for the calc.exe detection rule in Elastic Stack using the API

    # Check if the exception list already exists and delete it if it does
    $listIdToDelete = "d735da52-0640-42a2-b11f-9fa111772d03"
    try {
        $findResponse = Invoke-RestMethod -Method GET -Uri "$Kibana_URL/s/kibana-ctf/api/exception_lists/_find?list_id=$listIdToDelete" -Headers @{"kbn-xsrf"="true"; "Authorization"="$kibanaAuth"} -AllowUnencryptedAuthentication -SkipCertificateCheck
        if ($findResponse.data.Count -gt 0) {
            $existingListId = $findResponse.data[0].id
            Invoke-RestMethod -Method DELETE -Uri "$Kibana_URL/s/kibana-ctf/api/exception_lists&list_id=$existingListId" -Headers @{"kbn-xsrf"="true"; "Authorization"="$kibanaAuth"} -AllowUnencryptedAuthentication -SkipCertificateCheck
            Write-Host "Deleted existing exception list with ID: $existingListId"
        }
    } catch {
        Write-Host "No existing exception list found or error during check/delete: $($_.Exception.Message)"
    }

    # Import the exception rule
    $exceptionRuleFilePath = "./challenges/Rules/2/elastic_exception_rule.ndjson"
    $importExceptionRuleResponse = Invoke-RestMethod -Method POST -Uri "$Kibana_URL/s/kibana-ctf/api/exception_lists" -Headers @{"kbn-xsrf"="true"; "Authorization"="$kibanaAuth"} -Form @{file = Get-Item $exceptionRuleFilePath} -AllowUnencryptedAuthentication -SkipCertificateCheck
    # Need to make the exception work
    return Write-Debug "✅ elastic_import_script.ps1 executed"
}
