function challenge {
    # Create a massive array of 100 random secrets, with the flag broken up
    $random = New-Object System.Random
    $words = @(
        "banana","orange","tomato","potato","carrot","pepper","grapes","apples","peachy","plumage","dragon","silver","bronze","platinum","emerald","sapphire","topaz","pearly","ambery","onyxes","corals","ivorys","tealish","cyanide","magenta","maroon","navyblue","olives","limeade","aquafer","fuchsia","indigos","violet","crimson","scarlet","turquoise","peachy","apricot","cherry","berrys","melon","lemony","grapey","figs","dates","kiwis","pearls","mangos","papaya","guavas","coconut","pineapple","starfruit","dragonfruit","whiskey","victor","uniform","tangoed","sierra","romeos","quebec","papaed","oscar","november","juliet","hotel","foxtrot","charlie","bravo","alpha"
    )
    $flagParts = @("{c","t","f","_","m","v","_","e","x","p","a","n","d","_","i","s","_","c","o","o","l","}")
    $secrets = @()
    $flagIndexes = @(3,7,12,18,21,25,31,38,44,49,51,57,63,69,72,75,81,87,90,92,96,99)
    $flagIdx = 0
    for ($i=0; $i -lt 100; $i++) {
        if ($flagIndexes -contains $i) {
            $secrets += $flagParts[$flagIdx]
            $flagIdx++
        } else {
            $secrets += $words[$random.Next(0, $words.Count)]
        }
    }
    $expandMe = [PSCustomObject]@{
        '@timestamp' = ($(Get-Date -AsUTC).AddHours(-2)).ToString("o")
        user = @{ name = "ctf_player"}
        secrets = $secrets
        message = "Some secrets are best kept in arrays!"
    } | ConvertTo-Json
    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $expandMe

    return Write-Debug "✅ elastic_import_script.ps1 executed"
}