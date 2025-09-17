function dynamic_flag {
    $flag_file_path = './challenges/Discover/8/ctfd_flag.json'
    $ctfd_flag = Get-Content $flag_file_path | ConvertFrom-Json -Depth 10

    # Adjust dynamic incident challenge
    if ($ctfd_flag.content -match '38'){
        Write-Host "Incident Challenge detected, updating dynamic challenge answer."
        $days = $($($(Get-date)-$(Get-Date 2024-11-12T07:43:13.373Z)).Days)
        $ctfd_flag.content = $ctfd_flag.content -replace '38', "$($days-1)|$days|$($days+1)"
    }
    # Create new flag file with new dynamic date
    $ctfd_flag | ConvertTo-Json -Depth 10 | Out-File -FilePath $flag_file_path
    return Write-Debug "✅ elastic_import_script.ps1 executed"
}