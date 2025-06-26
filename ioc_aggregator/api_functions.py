import requests
import ipwhois
import whois
import shodan
import re

# 🔑 Set your API keys directly here
VT_API_KEY = "742"
SHODAN_API_KEY = "khsoa1"
URLSCAN_API_KEY = "1397ahfklh"


def detect_ioc_type(ioc):
    if re.match(r"^(http|https)://", ioc):
        return "URL"
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "IP"
    elif re.match(r"^[a-fA-F0-9]{32}$", ioc) or re.match(r"^[a-fA-F0-9]{40}$", ioc) or re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "Hash"
    elif re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", ioc):
        return "Domain"
    else:
        return "Unknown"


def enrich_ip(ioc):
    try:
        obj = ipwhois.IPWhois(ioc)
        rdap = obj.lookup_rdap()

        shodan_api = shodan.Shodan(SHODAN_API_KEY)
        try:
            shodan_info = shodan_api.host(ioc)
            org = shodan_info.get("org", "")
            open_ports = shodan_info.get("ports", [])
        except Exception:
            org = "N/A"
            open_ports = []

        return {
            "IOC": ioc,
            "Type": "IP",
            "Country": rdap.get("network", {}).get("country", ""),
            "AS Owner": rdap.get("network", {}).get("name", ""),
            "Malicious": 0,
            "Registrar": "",
            "Org": org,
            "Open Ports": ','.join(map(str, open_ports)),
            "Error": ""
        }
    except Exception as e:
        return {"IOC": ioc, "Type": "IP", "Malicious": "", "Error": str(e)}


def enrich_domain(ioc):
    try:
        w = whois.whois(ioc)
        return {
            "IOC": ioc,
            "Type": "Domain",
            "Country": w.get("country", ""),
            "AS Owner": "",
            "Malicious": 0,
            "Registrar": w.get("registrar", ""),
            "Error": ""
        }
    except Exception as e:
        return {"IOC": ioc, "Type": "Domain", "Malicious": "", "Error": str(e)}


def enrich_url(ioc):
    headers = {"API-Key": URLSCAN_API_KEY}
    data = {"url": ioc, "visibility": "public"}
    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
        if response.status_code == 200:
            scan_result = response.json()
            return {
                "IOC": ioc,
                "Type": "URL",
                "Malicious": 0,  # urlscan doesn't return malicious flag directly
                "Error": ""
            }
        else:
            return {"IOC": ioc, "Type": "URL", "Malicious": "", "Error": f"Scan failed: {response.status_code}"}
    except Exception as e:
        return {"IOC": ioc, "Type": "URL", "Malicious": "", "Error": str(e)}


def enrich_hash(ioc):
    url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "IOC": ioc,
                "Type": "Hash",
                "Malicious": stats.get("malicious", 0),
                "Error": ""
            }
        elif response.status_code == 404:
            return {"IOC": ioc, "Type": "Hash", "Malicious": 0, "Error": "Hash not found in VirusTotal"}
        else:
            return {"IOC": ioc, "Type": "Hash", "Malicious": "", "Error": response.text}
    except Exception as e:
        return {"IOC": ioc, "Type": "Hash", "Malicious": "", "Error": str(e)}


def enrich_ioc(ioc):
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == "IP":
        return enrich_ip(ioc)
    elif ioc_type == "Domain":
        return enrich_domain(ioc)
    elif ioc_type == "URL":
        return enrich_url(ioc)
    elif ioc_type == "Hash":
        return enrich_hash(ioc)
    else:
        return {"IOC": ioc, "Type": "Unknown", "Malicious": "", "Error": "Unsupported IOC type"}


if __name__ == "__main__":
    iocs = [
        "https://example.com",                        # URL
        "8.8.8.8",                                    # IP
        "google.com",                                 # Domain
        "44d88612fea8a8f36de82e1278abb02f"            # MD5 hash (EICAR)
    ]

    for ioc in iocs:
        result = enrich_ioc(ioc)
        print(result)
