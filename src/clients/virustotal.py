import os
import httpx
from dotenv import load_dotenv
import asyncio

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

async def check_ip(ip_address: str):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    
    
    headers = {
        "x-apikey": VT_API_KEY
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        
        return response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]

async def check_domain(domain: str):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    
    
    headers = {
        "x-apikey": VT_API_KEY
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        
        return response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]

async def check_hash(hash: str):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    
    
    headers = {
        "x-apikey": VT_API_KEY
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        
        return response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]

