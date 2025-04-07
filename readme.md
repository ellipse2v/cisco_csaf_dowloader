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
python script_name.py [--path <download_path>] [--token <auth_token>] [--mode <all|dates>] [--days <number_of_days>]
