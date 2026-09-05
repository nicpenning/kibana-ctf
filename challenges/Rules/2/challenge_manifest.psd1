@{
    Name = "High Quality Rules Only - No Exceptions!"
    Category = "Rules"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
    )
    Resources = @{
        KibanaVersion = "^9.5.3"
    }
}
