from src.clients.virustotal import check_ip as vt_check_ip
from src.clients.virustotal import check_domain as vt_check_domain
from src.clients.virustotal import check_hash as vt_check_hash
from src.clients.abuseIPDB import check_ip as abuse_check
from src.parsers.ioc_parser import parse_ioc, Types


async def analyze_ioc(ioc: str):
    if parse_ioc(ioc) == Types.IPV4:
        vt_report = await vt_check_ip(ioc)
        abuse_report = await abuse_check(ioc)
    elif parse_ioc(ioc) == Types.DOMAIN:
        vt_report = await vt_check_domain(ioc)
        abuse_report = 0  
    elif parse_ioc(ioc) in [Types.SHA256, Types.MD5]:
        vt_report = await vt_check_hash(ioc)
        abuse_report = 0  
    else:
        return "invalid ioc"
    
    vt_malicious_count = vt_report
    abuse_score = abuse_report
    
    if vt_malicious_count >= 3 or abuse_score > 75:
        return {"verdict": "MALICIOUS", "vt_score": vt_malicious_count, "abuse_score": abuse_score}
    elif vt_malicious_count > 0 or abuse_score > 0:
        return {"verdict": "SUSPICIOUS", "vt_score": vt_malicious_count, "abuse_score": abuse_score}
    else:
        return {"verdict": "HARMLESS", "vt_score": vt_malicious_count, "abuse_score": abuse_score}

