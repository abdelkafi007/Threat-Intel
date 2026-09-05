# Threat Intel Triage CLI 

A fast, automated command-line tool built for SOC analysts. Instead of manually copying and pasting IPs, Domains, or Hashes into different browser tabs, this tool queries threat intelligence feeds asynchronously and outputs a clean, color-coded verdict table right in your terminal.

## What it does
- Automatically figures out if your input is an IPv4, Domain, MD5, or SHA256.
- Queries **VirusTotal** (for everything) and **AbuseIPDB** (for IPs) at the exact same time.
- Uses a scoring engine to label the indicator as CRITICAL MALICIOUS, WARNING SUSPICIOUS, or SAFE HARMLESS based on vendor detections and abuse confidence scores.

## Setup

1. **Clone the repo and set up your environment**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -r requirement.txt
  ```

2. **Add your API keys**
  Create a `.env` file in the main folder and add your free API keys:
  ```env
  VT_API_KEY=your_virustotal_key
  ABUSEIPDB_API_KEY=your_abuseipdb_key
  ```

3. **Run a scan!**
  You can pass as many IPs, domains, or hashes as you want.
  ```bash
  python3 -m src.cli 8.8.8.8 google.com 44d88612fea8a8f36de82e1278abb02f
  ```

## Built With
- **Python 3**
- **httpx & asyncio:** For lightning-fast, simultaneous API queries.
- **Typer & Rich:** For the CLI interface, loading spinners, and colored tables.
