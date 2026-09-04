from enum import Enum
import re
import ipaddress


class Types(Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    SHA256 = "sha256"
    MD5 = "md5"
    UNKNOWN = "unknown"



def parse_ioc(value: str):
    value = value.strip()

    try:
        ipaddress.IPv4Address(value)
        return Types.IPV4
    except ValueError:
        pass

    if len(value) == 32 and re.match(r"^[0-9a-fA-F]+$", value):
        return Types.MD5
    elif len(value) == 64 and re.match(r"^[0-9a-fA-F]+$", value):
        return Types.SHA256
    elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
        return Types.DOMAIN
    else:
        return Types.UNKNOWN

