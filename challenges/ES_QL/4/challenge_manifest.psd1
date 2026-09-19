@{
    Name = "ES|QL + Lens"
    Category = "ES|QL != SQL"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "elastic_saved_objects.ndjson"
    )
    Resources = @{
        KibanaVersion = "^9.5.3"
        LicenseRequired = "basic"
    }
}