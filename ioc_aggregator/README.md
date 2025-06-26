# IOC Aggregator Toolkit

This is a lightweight IOC (Indicator of Compromise) Aggregator toolkit inspired by the OSINT Toolkit. It accepts input IOCs such as IPs, domains, URLs, and file hashes, enriches them using public threat intelligence APIs, and outputs the results in CSV format.

## 🛠 Features
- Classifies IOCs: IPs, Domains, URLs, Hashes
- Integrates with public APIs (e.g., VirusTotal, URLScan.io, Shodan)
- Exports enriched results to CSV
- Modular and extendable codebase

## 📂 Project Structure
```
ioc_aggregator/
├── config.py             # API keys and config
├── main.py               # Main script
├── sample_input.txt      # Input file with IOCs
├── output.csv            # CSV output
├── requirements.txt      # Python dependencies
```

## 🚀 How to Run

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set your API keys in `config.py`.

3. Run the script:
```bash
python main.py
```

4. Check `output.csv` for results.

## 📝 Sample Input (`sample_input.txt`)
```
8.8.8.8
1.1.1.1
cnn.com
https://github.com
44d88612fea8a8f36de82e1278abb02f
d41d8cd98f00b204e9800998ecf8427e
```

## 📤 Sample Output (`output.csv`)
| **IOC**                                  | **Type** | **Country** | **ASN**       | **Tags**               | **Source** | **Threat Score** |
| ---------------------------------------- | -------- | ----------- | ------------- | ---------------------- | ---------- | ---------------- |
| 8.8.8.8                                  | IP       | US          | GOOGLE        |                        |            | 0                |
| 1.1.1.1                                  | IP       |             | CLOUDFLARENET |                        |            | 0                |
| cnn.com                                  | Domain   |             |               | News                   | NOM-IQ Ltd | 0                |
| [https://github.com](https://github.com) | URL      |             |               | Information Technology |            | 0                |
| 44d88612fea8a8f36de82e1278abb02f         | Hash     |             |               | Eicar.txt, Powershell  |            | 0.955            |
| d41d8cd98f00b204e9800998ecf8427e         | Hash     |             |               |                        | Unknown    | 0                |

## 🔐 API Keys Required
- VirusTotal
- Shodan
- URLScan.io

# IOC Aggregator Script

## Overview
This tool enriches Indicators of Compromise (IOCs) such as IP addresses, domains, and URLs using public threat intelligence APIs like VirusTotal.

## Features
- Supports IPs, domains, URLs (and optionally, hashes)
- Fetches metadata like:
  - AS owner
  - Country
  - Threat detection stats
  - Categories
  - HTTP response info (for URLs)
- Exports results to `output.csv`

## Setup
1. Install requirements:
   ```bash
   pip install requests pandas python-dotenv

## 📌 Notes
- Respect API rate limits.
- This is an educational project. Use responsibly.

