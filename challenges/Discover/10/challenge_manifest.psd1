@{
    Name = "Data is more than what meets the eye"
    Category = "(re)Discover"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "ctfd_hint.json"
        "elastic_import_script.ps1"
    )
    Resources = @{
        KibanaVersion = "^8.17.0"
    }
}