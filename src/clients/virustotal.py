import os
import httpx
from dotenv import load_dotenv
import asyncio

# This automatically finds your .env file and loads the variables
load_dotenv()

# Grab the key securely
VT_API_KEY = os.getenv("VT_API_KEY")

async def check_ip(ip_address: str):
    # This is the specific URL for VirusTotal IP lookups
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    
    
    # VirusTotal requires your API key in the headers
    headers = {
        "x-apikey": VT_API_KEY
    }

    # How to make an async GET request:
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        
        # Convert the response to a JSON dictionary and return it
        return response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]

async def check_domain(domain: str):
    # This is the specific URL for VirusTotal domain lookups
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    
    
    # VirusTotal requires your API key in the headers
    headers = {
        "x-apikey": VT_API_KEY
    }

    # How to make an async GET request:
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        
        # Convert the response to a JSON dictionary and return it
        return response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]

async def check_hash(hash: str):
    # This is the specific URL for VirusTotal hash lookups
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    
    
    # VirusTotal requires your API key in the headers
    headers = {
        "x-apikey": VT_API_KEY
    }

    # How to make an async GET request:
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        
        # Convert the response to a JSON dictionary and return it
        return response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]

