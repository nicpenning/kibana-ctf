@{
    Name = "Advanced Query"
    Category = "(re)Discover"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "elastic_saved_objects.ndjson"
        "elastic_import_script.ps1"
    )
    Resources = @{
        KibanaVersion = "^8.17.0"
    }
}