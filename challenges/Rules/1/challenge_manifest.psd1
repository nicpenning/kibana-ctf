@{
    Name = "My First Rule"
    Category = "Rules"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "elastic_import_script.ps1"
        "elastic_rule.ndjson"
    )
    Resources = @{
        KibanaVersion = "^9.5.4"
        LicenseRequired = "basic"
    }
}
