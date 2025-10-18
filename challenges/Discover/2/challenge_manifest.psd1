@{
    Name = "I like a good query."
    Category = "(re)Discover"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "elastic_saved_objects.ndjson"
    )
    Resources = @{
        KibanaVersion = "^8.17.0"
    }
}