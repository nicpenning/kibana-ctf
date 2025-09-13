All Discover challenges live in this directory.

Template for manifest files that contain useful information about the challenge such as name, category, and version of Kibana required to perform the challenge. These are not functional yet so are informational only at this point.

```
@{
    Name = "Title of the Challenge in CTFd"
    Category = "Category of challenge (Dashboards, Discover, ES_QL, etc)"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        "ctfd_hint.json"
        "elastic_saved_objects.ndjson"
        "other_file_needed_to_setup_challenge_in_elastic_or_ctfd.ps1"
    )
    Resources = @{
        KibanaVersion = "^8.17.0"
    }
}
```