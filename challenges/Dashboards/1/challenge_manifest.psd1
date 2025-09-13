@{
    Name = "Dashboard Challenge 1"
    Category = "Visualization Sensation"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "ctfd_hint.json"
        "elastic_saved_objects.ndjson"
    )
    Resources = @{
        KibanaVersion = "^9.1.0"
    }
}