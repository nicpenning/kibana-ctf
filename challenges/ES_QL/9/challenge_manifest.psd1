@{
    Name = "Array Unleashed"
    Category = "ES|QL != SQL"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "ctfd_hint.txt"
        "elastic_import_script.ps1"
        "elastic_saved_objects.ndjson"
    )
    Resources = @{
        KibanaVersion = "^9.1.0"
    }
}