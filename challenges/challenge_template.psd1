@{
    Name = $Challenge_Name
    Category = $Challenge_Category
    RequiredFiles = @(
        $ctfd_challenge_json
        $ctfd_flag_json
        $ctfd_hint_json
        $elastic_saved_objects_ndjson
        $dynamic_flag_ps1
        $elastic_import_script_ps1
    )
    Resources = @{
        KibanaVersion = $Challenge_Required_Kibana_Version
    }
}