# Advanced Elastic Stack Import Script for Challenge: My First Rule
# This script will help you import the necessary resources into Elastic Stack for the challenge.
# Make sure to customize the script as needed before running.
function challenge {
    # Create suspicious events and document for rules

    # Import the calc.exe detection rule and execute it to create the alert

    $ruleFilePath = "./challenges/Rules/1/elastic_rule.ndjson"
    $importRuleResponse = Invoke-RestMethod -Method POST -Uri "$Kibana_URL/s/kibana-ctf/api/detection_engine/rules/_import" -Headers @{"kbn-xsrf"="true"; "Authorization"="$kibanaAuth"} -Form $ruleFilePath -ContentType "multipart/form-data" -AllowUnencryptedAuthentication -SkipCertificateCheck

    return Write-Debug "✅ elastic_import_script.ps1 executed"
}
