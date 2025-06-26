import requests
import pandas as pd
import re
import base64
import urllib.parse
from config import VT_API_KEY, SHODAN_API_KEY, URLSCAN_API_KEY

def identify_indicator_type(indicator):
    """
    Identify if the indicator is an IP, domain, URL, or file hash
    Returns: "ip", "domain", "url", or "hash"
    """
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    url_pattern = r"^https?://"
    md5_pattern = r"^[a-fA-F0-9]{32}$"
    sha1_pattern = r"^[a-fA-F0-9]{40}$"
    sha256_pattern = r"^[a-fA-F0-9]{64}$"

    if re.match(ip_pattern, indicator):
        return "ip"
    elif re.match(url_pattern, indicator):
        return "url"
    elif re.match(md5_pattern, indicator) or re.match(sha1_pattern, indicator) or re.match(sha256_pattern, indicator):
        return "hash"
    else:
        return "domain"

def get_virustotal_data(indicator):
    """Get data from VirusTotal API based on indicator type."""
    indicator_type = identify_indicator_type(indicator)
    headers = {"x-apikey": VT_API_KEY}

    try:
        if indicator_type == "ip":
            api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        elif indicator_type == "url":
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip('=')
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif indicator_type == "domain":
            api_url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
        elif indicator_type == "hash":
            api_url = f"https://www.virustotal.com/api/v3/files/{indicator}"
        else:
            return {"indicator": indicator, "type": "unknown", "error": "Unknown indicator type"}

        response = requests.get(api_url, headers=headers)
        response.raise_for_status()

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

        result = {
            "indicator": indicator,
            "type": indicator_type,
        }

        if "last_analysis_stats" in attributes:
            result["last_analysis_stats"] = attributes["last_analysis_stats"]
        else:
            result["last_analysis_stats"] = {}

        if indicator_type == "hash":
            result["meaningful_name"] = attributes.get("meaningful_name", "")
            result["type_description"] = attributes.get("type_description", "")
            result["size"] = attributes.get("size", "")

        if indicator_type == "ip":
            result["as_owner"] = attributes.get("as_owner")
            result["country"] = attributes.get("country")

        if indicator_type == "domain":
            result["registrar"] = attributes.get("registrar")
            result["creation_date"] = attributes.get("creation_date")
            result["categories"] = attributes.get("categories")

        if indicator_type == "url":
            result["content_length"] = attributes.get("last_http_response_content_length")
            result["http_code"] = attributes.get("last_http_response_code")
            result["categories"] = attributes.get("categories")

        return result

    except requests.exceptions.HTTPError as e:
        error_message = f"Error: {e}"
        if response.status_code == 401:
            error_message = "Authentication error: Please check your API key"
        elif response.status_code == 404:
            error_message = f"Not found: The indicator '{indicator}' could not be found in VirusTotal"
        return {"indicator": indicator, "type": indicator_type, "error": error_message}
    except Exception as e:
        return {"indicator": indicator, "type": indicator_type, "error": str(e)}

def read_inputs(filename):
    try:
        with open(filename, "r") as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"Error: Input file '{filename}' not found")
        return []

def save_to_csv(data, filename):
    if not data:
        print("No data to save")
        return

    processed_data = []
    for item in data:
        processed_item = item.copy()

        if "last_analysis_stats" in processed_item and isinstance(processed_item["last_analysis_stats"], dict):
            for key, value in processed_item["last_analysis_stats"].items():
                processed_item[f"detection_{key}"] = value

        if "last_analysis_stats" in processed_item:
            processed_item["last_analysis_stats_raw"] = str(processed_item["last_analysis_stats"])
            del processed_item["last_analysis_stats"]

        processed_data.append(processed_item)

    df = pd.DataFrame(processed_data)

    if 'detection_malicious' in df.columns and 'detection_undetected' in df.columns:
        df['detection_ratio'] = df['detection_malicious'] / (df['detection_malicious'] + df['detection_undetected'])

    df.to_csv(filename, index=False)
    print(f"Saved output to {filename}")

def main():
    if not VT_API_KEY:
        print("Error: VirusTotal API key is missing or empty in config.py")
        return

    indicators = read_inputs("sample_input.txt")
    if not indicators:
        print("No indicators found to process")
        return

    print(f"Processing {len(indicators)} indicators...")

    processed = 0
    total = len(indicators)
    enriched_data = []

    for indicator in indicators:
        processed += 1
        print(f"Progress: {processed}/{total} ({processed/total*100:.1f}%)", end="\r")
        vt_result = get_virustotal_data(indicator)
        enriched_data.append(vt_result)

    print()
    save_to_csv(enriched_data, "output.csv")
    print("Processing complete!")

if __name__ == "__main__":
    main()
