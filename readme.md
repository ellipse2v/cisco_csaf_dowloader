# Cisco CSAF Downloader

This Python script downloads Cisco Common Security Advisory Framework (CSAF) files using the Cisco OpenVuln API.

## Requirements

- Python 3.6 or later
- `requests` library

## Installation

1.  Clone the repository or download the script.
2.  Install the required library:

    ```bash
    pip install requests
    ```

3.  Create a `credentials.json` file in the same directory as the script. This file should contain your Cisco API client ID and secret: https://developer.cisco.com/docs/psirt/introduction/

    ```json
    {
      "CLIENT_ID": "your_client_id",
      "CLIENT_SECRET": "your_client_secret"
    }
    ```

## Usage

```bash
python cisco_csaf_dl.py [--path <download_path>] [--token <auth_token>] [--mode <all|dates>] [--days <number_of_days>]
```

### Command Line Arguments

- `--path`: Directory path where downloaded CSAF files will be saved (default: "downloaded_csaf")
- `--token`: Bearer authorization token. If not provided, the script will attempt to generate one using the credentials in `credentials.json`
- `--mode`: Download mode (choices: "all" or "dates")
  - `all`: Download all available advisories
  - `dates`: Download advisories published within a specific date range
- `--days`: Number of days to look back when using the `dates` mode (default: 2)

## Rate Limiting

The script implements rate limiting according to Cisco API restrictions:
- 5 calls per second
- 30 calls per minute
- 5000 calls per day

## Features

- Automatic token generation using client credentials
- Token refresh on authentication failure
- JSON output for each advisory
- Error handling and retry mechanism
- Rate limiting to comply with API usage policies

## Examples

Download all advisories:
```bash
python cisco_csaf_dl.py
```

Download advisories from the last 7 days:
```bash
python cisco_csaf_dl.py --mode dates --days 7
```

Specify a custom download directory:
```bash
python cisco_csaf_dl.py --path /path/to/save/advisories
```

Use a pre-existing authorization token:
```bash
python cisco_csaf_dl.py --token your_auth_token
```

## Output

The script creates individual JSON files for each advisory, named with the advisory ID. All files are saved in the specified download directory.

## License

Copyright 2025 ellipse2v

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
