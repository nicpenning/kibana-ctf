# Advanced Elastic Stack Import Script for Challenge: High Quality Rules Only - No Exceptions!
function challenge {
    # Create an exception for the calc.exe detection rule in Elastic Stack using the API
    # Requires overwrite_exceptions=true parameter to be set in the import API call

    # Import the calc.exe detection rule with the exception

    $ruleFilePath = "./challenges/Rules/2/elastic_rule_with_exceptions.ndjson"
    $importRuleResponse = Invoke-RestMethod -Method POST -Uri "$Kibana_URL/s/kibana-ctf/api/detection_engine/rules/_import?overwrite=true&overwrite_exceptions=true" -Headers @{"kbn-xsrf"="true"; "Authorization"="$kibanaAuth"} -Form @{file = Get-Item $ruleFilePath} -AllowUnencryptedAuthentication -SkipCertificateCheck

    return Write-Debug "✅ elastic_import_script.ps1 executed"
}
