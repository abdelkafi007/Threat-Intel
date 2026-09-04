import os
import httpx
from dotenv import load_dotenv
import asyncio

# This automatically finds your .env file and loads the variables
load_dotenv()

# Grab the key securely
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

async def check_ip(ip_address: str):
    # This is the specific URL for AbuseIPDB IP lookups
    url = f"https://api.abuseipdb.com/api/v2/check/"
    
    # AbuseIPDB requires your API key in the headers
    headers = {
        "accept": "application/json",
        "key": ABUSEIPDB_API_KEY
        
    }
    querystring = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    # How to make an async GET request:
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, params=querystring)
        
        # Convert the response to a JSON dictionary and return it
        return response.json()["data"]["abuseConfidenceScore"]

