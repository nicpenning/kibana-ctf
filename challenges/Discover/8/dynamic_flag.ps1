function dynamic_flag {
    $flag_file_path = './challenges/Discover/8/ctfd_flag.json'
    $saved_object_file_path = './challenges/Discover/8/elastic_saved_objects.ndjson'
    $ctfd_flag = Get-Content $flag_file_path | ConvertFrom-Json -Depth 10
    $saved_object = Get-Content $saved_object_file_path | ConvertFrom-Json -Depth 10

    # Adjust dynamic incident challenge
    if ($ctfd_flag.content -match 'dynamic_days'){
        Write-Debug "Incident Challenge detected, updating dynamic challenge answer."
        # Calculate a random date between now and 90 days ago.
        $random_date = (Get-Date).AddDays(-(Get-Random -Minimum 0 -Maximum 91))
        $days = ((Get-Date) - $random_date).Days
        $ctfd_flag.content = $ctfd_flag.content -replace 'dynamic_days', "$($days-1)|$days|$($days+1)"
        $saved_object.attributes.'timepicker:quickRanges' = $saved_object.attributes.'timepicker:quickRanges' -replace 'dynamic_days', "$days"
    }
    # Create new flag file with new dynamic date
    $ctfd_flag | ConvertTo-Json -Depth 10 | Out-File -FilePath $flag_file_path
    $saved_object | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $saved_object_file_path

    return Write-Debug "✅ elastic_import_script.ps1 executed"
}