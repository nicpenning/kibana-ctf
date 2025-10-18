@{
    Name = "Zippidy Do Da"
    Category = "ES|QL != SQL"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "ctfd_hint.json"
        "elastic_saved_objects.ndjson"
    )
    Resources = @{
        KibanaVersion = "^8.17.0"
    }
}