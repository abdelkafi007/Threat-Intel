import os
import httpx
from dotenv import load_dotenv
import asyncio

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

async def check_ip(ip_address: str):
    url = f"https://api.abuseipdb.com/api/v2/check/"
    
    headers = {
        "accept": "application/json",
        "key": ABUSEIPDB_API_KEY
        
    }
    querystring = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, params=querystring)
        
        return response.json()["data"]["abuseConfidenceScore"]

