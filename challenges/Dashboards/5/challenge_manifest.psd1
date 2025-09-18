@{
    Name = "sudo rm -rf /"
    Category = "Visualization Sensation"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
    )
    Resources = @{
        KibanaVersion = "^9.1.0"
    }
}