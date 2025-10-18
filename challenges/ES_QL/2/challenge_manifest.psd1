@{
    Name = "Strange Activity"
    Category = "ES|QL != SQL"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "elastic_import_script.ps1"
        "elastic_saved_objects.ndjson"
    )
    Resources = @{
        KibanaVersion = "^8.17.0"
    }
}