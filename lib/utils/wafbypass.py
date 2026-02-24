#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

WAF Bypass Level Handler

This module provides automatic tamper script selection based on the
--waf-bypass level option. Higher levels apply more aggressive evasion
techniques.

Levels:
    1 - Basic: Standard encoding and case manipulation
    2 - Moderate: + Oversized requests, header manipulation
    3 - Aggressive: + Chunked encoding, parameter pollution
    4 - Advanced: + Content-Type confusion, Unicode normalization
    5 - Maximum: All techniques combined including HTTP smuggling

Reference:
    * https://www.blackhillsinfosec.com/bypassing-wafs-using-oversized-requests/
    * https://www.imperva.com/blog/smuggling-requests-with-chunked-extensions-a-new-http-desync-trick/
    * https://medium.com/@gasmask/bypassing-wafs-in-2025-new-techniques-and-evasion-tactics
"""

from lib.core.data import conf
from lib.core.data import logger

# Tamper scripts organized by bypass level
WAF_BYPASS_TAMPERS = {
    1: [
        # Basic encoding and obfuscation
        "randomcase",
        "space2comment",
        "between",
    ],
    2: [
        # + Oversized requests and header manipulation
        "oversizedrequest",
        "xforwardedfor",
        "randomcomments",
        "charencode",
        "scientificnotation",  # e notation bypass (ptswarm technique)
        "tabsandlinefeeds",    # HackenProof technique
        "methodoverride",      # HTTP method override (PUT, PATCH, DELETE)
    ],
    3: [
        # + Chunked encoding and parameter pollution
        "parampollutionfull",
        "space2morecomment",
        "apostrophemask",
        "equaltolike",
        "junkchars",           # HackenProof technique
        "linebreaks",          # HackenProof technique (CR/LF)
    ],
    4: [
        # + Content-Type confusion and Unicode
        "contenttypeconfusion",
        "unicodenormalize",
        "multipartboundary",
        "charunicodeencode",
        "tokenbreaker",        # HackenProof technique
        "doubleencode",        # Double URL encoding bypass
    ],
    5: [
        # + HTTP smuggling and advanced techniques
        "chunkextensionsmuggle",
        "slowrequest",
        "base64encode",
        "percentage",
    ],
}

# Recommended combinations for specific WAFs
WAF_SPECIFIC_TAMPERS = {
    "cloudflare": [
        "oversizedrequest",
        "xforwardedfor",
        "randomcase",
        "space2comment",
        "charunicodeencode",
    ],
    "aws": [
        "oversizedrequest",
        "contenttypeconfusion",
        "randomcase",
        "between",
    ],
    "modsecurity": [
        "space2comment",
        "randomcase",
        "charencode",
        "versionedmorekeywords",
        "chunkextensionsmuggle",
    ],
    "imperva": [
        "xforwardedfor",
        "randomcase",
        "space2morecomment",
        "unicodenormalize",
    ],
    "akamai": [
        "oversizedrequest",
        "xforwardedfor",
        "randomcase",
        "apostrophemask",
    ],
    "f5": [
        "contenttypeconfusion",
        "parampollutionfull",
        "randomcase",
        "space2comment",
    ],
    "fortinet": [
        "oversizedrequest",  # 64MB limit - very high
        "randomcase",
        "charencode",
    ],
    "sucuri": [
        "oversizedrequest",  # 1.25MB limit
        "xforwardedfor",
        "randomcase",
    ],
    "google": [
        "oversizedrequest",  # 8KB limit
        "contenttypeconfusion",
        "randomcase",
    ],
    "azure": [
        "oversizedrequest",  # 128KB for Front Door
        "xforwardedfor",
        "randomcase",
    ],
}


def getWafBypassTampers(level):
    """
    Returns the list of tamper scripts to use for the given WAF bypass level
    
    Args:
        level: Integer from 1-5 indicating bypass aggressiveness
        
    Returns:
        List of tamper script names to apply
    """
    
    if not level or level < 1:
        return []
    
    # Cap at level 5
    level = min(level, 5)
    
    # Accumulate tampers from level 1 up to the specified level
    tampers = []
    for lvl in range(1, level + 1):
        tampers.extend(WAF_BYPASS_TAMPERS.get(lvl, []))
    
    # Remove duplicates while preserving order
    seen = set()
    unique_tampers = []
    for t in tampers:
        if t not in seen:
            seen.add(t)
            unique_tampers.append(t)
    
    return unique_tampers


def getWafSpecificTampers(waf_name):
    """
    Returns recommended tamper scripts for a specific WAF
    
    Args:
        waf_name: Name of the WAF (e.g., "cloudflare", "aws", "modsecurity")
        
    Returns:
        List of tamper script names optimized for that WAF
    """
    
    waf_name = waf_name.lower().strip()
    
    # Try exact match first
    if waf_name in WAF_SPECIFIC_TAMPERS:
        return WAF_SPECIFIC_TAMPERS[waf_name]
    
    # Try partial match
    for waf, tampers in WAF_SPECIFIC_TAMPERS.items():
        if waf in waf_name or waf_name in waf:
            return tampers
    
    # Default to level 3 tampers if WAF not recognized
    return getWafBypassTampers(3)


def applyWafBypassLevel():
    """
    Applies the WAF bypass tamper scripts based on conf.wafBypassLevel
    This should be called during option initialization
    """
    
    level = conf.get("wafBypassLevel")
    
    if not level:
        return
    
    tampers = getWafBypassTampers(level)
    
    if not tampers:
        return
    
    # Get existing tampers
    existing = conf.get("tamper") or ""
    if existing:
        existing_list = [t.strip() for t in existing.split(',')]
    else:
        existing_list = []
    
    # Merge with WAF bypass tampers (WAF bypass tampers go first)
    all_tampers = tampers + [t for t in existing_list if t not in tampers]
    
    # Update conf
    conf.tamper = ','.join(all_tampers)
    
    infoMsg = "WAF bypass level %d: applying tamper scripts: %s" % (level, ', '.join(tampers))
    logger.info(infoMsg)


def printWafBypassHelp():
    """
    Prints help information about WAF bypass levels
    """
    
    help_text = """
WAF Bypass Levels:
==================

Level 1 (Basic):
    Tampers: randomcase, space2comment, between
    Target: Basic WAFs with simple pattern matching

Level 2 (Moderate):
    Tampers: + oversizedrequest, xforwardedfor, randomcomments, charencode
    Target: Cloudflare (free), AWS WAF, Google Cloud Armor

Level 3 (Aggressive):
    Tampers: + parampollutionfull, space2morecomment, apostrophemask, equaltolike
    Target: ModSecurity, Imperva, most commercial WAFs

Level 4 (Advanced):
    Tampers: + contenttypeconfusion, unicodenormalize, multipartboundary, charunicodeencode
    Target: WAFs with ML-based detection, behavioral analysis

Level 5 (Maximum):
    Tampers: + chunkextensionsmuggle, slowrequest, base64encode, percentage
    Target: All WAFs, includes HTTP smuggling techniques

Usage:
    sqlmap -u "http://target.com/?id=1" --waf-bypass=3

WAF-Specific Recommendations:
    Cloudflare: --waf-bypass=2 (8KB body limit bypass)
    AWS WAF:    --waf-bypass=2 (8KB body limit bypass)
    ModSecurity: --waf-bypass=3 (chunked + obfuscation)
    Imperva:    --waf-bypass=4 (Unicode + headers)
    Akamai:     --waf-bypass=3 (oversized + headers)
"""
    
    return help_text
