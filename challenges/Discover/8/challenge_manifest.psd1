@{
    Name = "⚠️ 🕰️ ⛏️"
    Category = "(re)Discover"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "dynamic_flag.ps1"
        "elastic_saved_objects.ndjson"
    )
    Resources = @{
        KibanaVersion = "^9.5.4"
        LicenseRequired = "basic"
    }
}