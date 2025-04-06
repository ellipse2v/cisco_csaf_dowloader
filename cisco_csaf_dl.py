# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 
import requests
import json
import os
import argparse
import time
from datetime import datetime, timedelta

token_url = "https://id.cisco.com/oauth2/default/v1/token"
CISCO_API_BASE_URL = "https://apix.cisco.com/security/advisories/v2/all"

class RateLimiter:
    """
    Implements rate limiting for API calls.
    
    Enforces:
    - 5 calls per second
    - 30 calls per minute
    - 5000 calls per day
    """
    def __init__(self):
        self.second_timestamp = datetime.now()
        self.second_counter = 0
        
        self.minute_timestamp = datetime.now()
        self.minute_counter = 0
        
        self.day_timestamp = datetime.now()
        self.day_counter = 0
        
        # Limits
        self.SECOND_LIMIT = 5
        self.MINUTE_LIMIT = 30
        self.DAY_LIMIT = 5000

    def wait_if_needed(self):
        """Check all limits and wait if necessary before allowing next API call"""
        current_time = datetime.now()
        
        # Reset counters if time periods have elapsed
        if (current_time - self.second_timestamp).total_seconds() >= 1:
            self.second_counter = 0
            self.second_timestamp = current_time
            
        if (current_time - self.minute_timestamp).total_seconds() >= 60:
            self.minute_counter = 0
            self.minute_timestamp = current_time
            
        if (current_time - self.day_timestamp).total_seconds() >= 86400:  # 24 hours in seconds
            self.day_counter = 0
            self.day_timestamp = current_time
        
        # Check second limit
        if self.second_counter >= self.SECOND_LIMIT:
            sleep_time = 1 - (current_time - self.second_timestamp).total_seconds()
            if sleep_time > 0:
                print(f"Rate limit approaching: Waiting {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
                # Reset after waiting
                self.second_counter = 0
                self.second_timestamp = datetime.now()
                
        # Check minute limit
        if self.minute_counter >= self.MINUTE_LIMIT:
            sleep_time = 60 - (current_time - self.minute_timestamp).total_seconds()
            if sleep_time > 0:
                print(f"Minute rate limit reached: Waiting {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
                # Reset after waiting
                self.minute_counter = 0
                self.minute_timestamp = datetime.now()
                
        # Check day limit
        if self.day_counter >= self.DAY_LIMIT:
            sleep_time = 86400 - (current_time - self.day_timestamp).total_seconds()
            if sleep_time > 0:
                print(f"Daily rate limit reached: Waiting {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
                # Reset after waiting
                self.day_counter = 0
                self.day_timestamp = datetime.now()
    
    def increment(self):
        """Increment all counters after an API call"""
        self.second_counter += 1
        self.minute_counter += 1
        self.day_counter += 1

def get_new_token():
    """
    Generate a new access token using the client credentials flow.
    
    Returns:
        str: The new access token if successful, None otherwise.
    """
    try:
        # Load credentials from json file
        if not os.path.exists("credentials.json"):
            print("Error: credentials.json file not found")
            return None
            
        with open("credentials.json", "r") as f:
            credentials = json.load(f)
            
        if "CLIENT_ID" not in credentials or "CLIENT_SECRET" not in credentials:
            print("Error: CLIENT_ID or CLIENT_SECRET not found in credentials.json")
            return None
            
        client_id = credentials["CLIENT_ID"]
        client_secret = credentials["CLIENT_SECRET"]
        
        # Prepare token request
        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        # Make token request
        print("Requesting new access token...")
        response = requests.post(token_url, data=payload, headers=headers)
        response.raise_for_status()
        
        token_data = response.json()
        if "access_token" in token_data:
            print("Successfully obtained new access token")
            return token_data["access_token"]
        else:
            print("Error: access_token not found in response")
            print(f"Response: {token_data}")
            return None
            
    except Exception as e:
        print(f"Error generating new token: {e}")
        return None

def process_advisories(advisories, save_path):
    """
    Process and save advisories to disk.
    
    Args:
        advisories (list): List of advisory dictionaries.
        save_path (str): Directory path where files will be saved.
    """
    if not advisories:
        print("No advisories found in the response")
        return
        
    print(f"Processing {len(advisories)} advisories")
    
    for advisory in advisories:
        if isinstance(advisory, dict) and "advisoryId" in advisory:
            advisory_id = advisory["advisoryId"]
            filename = os.path.join(save_path, f"{advisory_id}.json")
            
            # Save the advisory content directly
            with open(filename, "w", encoding="utf-8") as file:
                json.dump(advisory, file, indent=2)
            print(f"Saved advisory: {filename}")
        else:
            print(f"Skipping advisory with missing ID: {advisory}")

def download_csaf(save_path, auth_token, rate_limiter, mode="all", days=2):
    """
    Downloads Cisco CSAF files using the OpenVuln API.

    Args:
        save_path (str): Directory path where CSAF files will be saved.
        auth_token (str): Bearer authorization token.
        rate_limiter (RateLimiter): Rate limiter object to enforce API limits.
        mode (str): Download mode ("all" or "dates").
        days (int): Number of days to look back in 'dates' mode.
        
    Returns:
        bool: True if successful, False otherwise.
    """

    if not os.path.exists(save_path):
        os.makedirs(save_path)

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {auth_token}"
    }

    try:
        if mode == "all":
            url = CISCO_API_BASE_URL
        elif mode == "dates":
            start_date = datetime.now() - timedelta(days=days)
            end_date = datetime.now()
            url = f"{CISCO_API_BASE_URL}/lastpublished?startDate={start_date.strftime('%Y-%m-%d')}&endDate={end_date.strftime('%Y-%m-%d')}"
        else:
            print("Invalid mode. Use 'all' or 'dates'.")
            return False
            
        # Make the API request
        rate_limiter.wait_if_needed()
        print(f"Requesting advisories from: {url}")
        response = requests.get(url, headers=headers)
        rate_limiter.increment()
        
        # Check for 403 Forbidden (token expired or invalid)
        if response.status_code == 403:
            print("Error 403 Forbidden: Token may be expired or invalid")
            return False
            
        response.raise_for_status()
        response_data = response.json()
        
        # Debug output to help understand API response structure
        print(f"Response type: {type(response_data)}")
        
        # Handle nested structure with advisories key
        if isinstance(response_data, dict) and "advisories" in response_data:
            advisories = response_data["advisories"]
            process_advisories(advisories, save_path)
            
        # Handle direct list of advisories
        elif isinstance(response_data, list):
            process_advisories(response_data, save_path)
            
        else:
            print(f"Unexpected response format: {type(response_data)}")
            print(json.dumps(response_data, indent=2)[:500] + "...")
            
        return True

    except requests.exceptions.RequestException as e:
        print(f"Error retrieving CSAF list: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        # Print more debug info
        import traceback
        traceback.print_exc()
        return False

def main():
    """
    Main function to handle command line arguments and start the download process.
    """
    parser = argparse.ArgumentParser(description="Download Cisco CSAF files.")
    parser.add_argument("--path", default="downloaded_csaf", help="Path to save downloaded files.")
    parser.add_argument("--token", help="Bearer authorization token. If not provided, will attempt to generate one using credentials.json.")
    parser.add_argument("--mode", choices=["all", "dates"], default="all", help="Download mode (all or dates).")
    parser.add_argument("--days", type=int, default=2, help="Number of days to look back in 'dates' mode.")
    args = parser.parse_args()

    # Get token - either from command line or generate new one
    auth_token = args.token
    if not auth_token:
        print("No token provided, attempting to generate one from credentials.json")
        auth_token = get_new_token()
        if not auth_token:
            print("Failed to obtain token. Exiting.")
            return

    # Initialize rate limiter
    rate_limiter = RateLimiter()

    # First attempt
    success = download_csaf(
        save_path=args.path,
        auth_token=auth_token,
        rate_limiter=rate_limiter,
        mode=args.mode,
        days=args.days,
    )
    
    # If first attempt fails, try with a new token
    if not success:
        print("Initial download attempt failed. Attempting to refresh token and retry...")
        new_token = get_new_token()
        if new_token:
            print("Retrying download with new token...")
            download_csaf(
                save_path=args.path,
                auth_token=new_token,
                rate_limiter=rate_limiter,
                mode=args.mode,
                days=args.days,
            )
        else:
            print("Failed to obtain new token. Cannot retry download.")

if __name__ == "__main__":
    main()