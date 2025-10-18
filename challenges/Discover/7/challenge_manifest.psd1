@{
    Name = "Future"
    Category = "(re)Discover"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "elastic_import_script.ps1"
    )
    Resources = @{
        KibanaVersion = "^8.17.0"
    }
}