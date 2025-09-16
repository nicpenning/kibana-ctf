@{
    Name = "Ahh, that is quite the (Data) View [Bonus]"
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