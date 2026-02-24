#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

WAF Bypass Handler - Smart WAF Detection Based

This module provides automatic tamper script selection based on the
detected WAF. It uses sqlmap's identYwaf detection (kb.identifiedWafs)
to select optimal tamper scripts (2-4 max) for each specific WAF.

Usage:
    --waf-bypass=auto     Auto-detect WAF and apply specific tampers
    --waf-bypass=cloudflare   Force Cloudflare-specific tampers
    --waf-bypass=modsecurity  Force ModSecurity-specific tampers
    etc.

Reference:
    * https://www.blackhillsinfosec.com/bypassing-wafs-using-oversized-requests/
    * https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/
"""

from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger

# Maximum number of tampers to apply (to avoid sqlmap warning)
MAX_TAMPERS = 4

# WAF-specific tamper configurations
# Each WAF has optimized tampers based on known bypass techniques
WAF_TAMPERS = {
    # Cloud WAFs
    "cloudflare": {
        "tampers": ["oversizedrequest", "randomcase", "space2comment"],
        "notes": "8KB body limit bypass, basic obfuscation"
    },
    "aws": {
        "tampers": ["oversizedrequest", "randomcase", "between"],
        "notes": "8KB body limit, AWS WAF rule bypass"
    },
    "awswaf": {
        "tampers": ["oversizedrequest", "randomcase", "between"],
        "notes": "Same as AWS"
    },
    "google": {
        "tampers": ["oversizedrequest", "randomcase", "charencode"],
        "notes": "8KB limit, Google Cloud Armor"
    },
    "googlecloudarmor": {
        "tampers": ["oversizedrequest", "randomcase", "charencode"],
        "notes": "Same as Google"
    },
    "azure": {
        "tampers": ["oversizedrequest", "xforwardedfor", "randomcase"],
        "notes": "128KB Front Door limit"
    },
    "azurewaf": {
        "tampers": ["oversizedrequest", "xforwardedfor", "randomcase"],
        "notes": "Same as Azure"
    },
    "akamai": {
        "tampers": ["oversizedrequest", "xforwardedfor", "apostrophemask"],
        "notes": "Header manipulation + encoding"
    },
    
    # Commercial WAFs
    "modsecurity": {
        "tampers": ["space2comment", "randomcase", "versionedmorekeywords"],
        "notes": "Comment-based bypass, MySQL version comments"
    },
    "owasp": {
        "tampers": ["space2comment", "randomcase", "versionedmorekeywords"],
        "notes": "Same as ModSecurity (OWASP CRS)"
    },
    "imperva": {
        "tampers": ["xforwardedfor", "unicodenormalize", "space2morecomment"],
        "notes": "Header spoofing + Unicode bypass"
    },
    "incapsula": {
        "tampers": ["xforwardedfor", "unicodenormalize", "space2morecomment"],
        "notes": "Same as Imperva"
    },
    "f5": {
        "tampers": ["parampollutionfull", "randomcase", "space2comment"],
        "notes": "Parameter pollution effective"
    },
    "bigip": {
        "tampers": ["parampollutionfull", "randomcase", "space2comment"],
        "notes": "Same as F5"
    },
    "fortinet": {
        "tampers": ["oversizedrequest", "randomcase", "charencode"],
        "notes": "64MB limit - very high, use encoding"
    },
    "fortigate": {
        "tampers": ["oversizedrequest", "randomcase", "charencode"],
        "notes": "Same as Fortinet"
    },
    "sucuri": {
        "tampers": ["oversizedrequest", "xforwardedfor", "randomcase"],
        "notes": "1.25MB limit, header manipulation"
    },
    "barracuda": {
        "tampers": ["space2comment", "randomcase", "between"],
        "notes": "Comment-based bypass"
    },
    "citrix": {
        "tampers": ["xforwardedfor", "randomcase", "charencode"],
        "notes": "NetScaler WAF"
    },
    "netscaler": {
        "tampers": ["xforwardedfor", "randomcase", "charencode"],
        "notes": "Same as Citrix"
    },
    
    # Open source / Other
    "wordfence": {
        "tampers": ["randomcase", "space2comment", "between"],
        "notes": "WordPress WAF"
    },
    "comodo": {
        "tampers": ["randomcase", "charencode", "space2comment"],
        "notes": "Basic encoding bypass"
    },
    "wallarm": {
        "tampers": ["unicodenormalize", "randomcase", "doubleencode"],
        "notes": "ML-based, use Unicode tricks"
    },
    "reblaze": {
        "tampers": ["xforwardedfor", "randomcase", "space2comment"],
        "notes": "Header manipulation"
    },
    "radware": {
        "tampers": ["oversizedrequest", "randomcase", "charencode"],
        "notes": "AppWall bypass"
    },
    "sophos": {
        "tampers": ["randomcase", "space2comment", "between"],
        "notes": "Basic obfuscation"
    },
    "paloalto": {
        "tampers": ["randomcase", "charencode", "space2morecomment"],
        "notes": "PAN-OS WAF"
    },
    
    # Generic / Unknown WAF
    "generic": {
        "tampers": ["randomcase", "space2comment", "between"],
        "notes": "Generic bypass for unknown WAFs"
    },
}

# Aliases for WAF names (identYwaf may use different names)
WAF_ALIASES = {
    "cloudflare inc.": "cloudflare",
    "amazon web services": "aws",
    "amazon": "aws",
    "microsoft azure": "azure",
    "google cloud": "google",
    "mod_security": "modsecurity",
    "modsec": "modsecurity",
    "imperva incapsula": "imperva",
    "f5 networks": "f5",
    "f5 big-ip": "bigip",
    "fortinet fortigate": "fortinet",
    "citrix netscaler": "citrix",
    "palo alto": "paloalto",
}


def normalizeWafName(waf_name):
    """
    Normalizes WAF name to match our configuration keys
    """
    if not waf_name:
        return "generic"
    
    waf_lower = waf_name.lower().strip()
    
    # Check aliases first
    for alias, normalized in WAF_ALIASES.items():
        if alias in waf_lower or waf_lower in alias:
            return normalized
    
    # Check direct match
    for waf_key in WAF_TAMPERS.keys():
        if waf_key in waf_lower or waf_lower in waf_key:
            return waf_key
    
    return "generic"


def getWafTampers(waf_name):
    """
    Returns the optimal tamper scripts for a specific WAF
    
    Args:
        waf_name: Name of the WAF (from identYwaf or user input)
        
    Returns:
        List of tamper script names (max MAX_TAMPERS)
    """
    normalized = normalizeWafName(waf_name)
    
    if normalized in WAF_TAMPERS:
        tampers = WAF_TAMPERS[normalized]["tampers"][:MAX_TAMPERS]
        return tampers
    
    # Default to generic
    return WAF_TAMPERS["generic"]["tampers"][:MAX_TAMPERS]


def getDetectedWafTampers():
    """
    Returns tampers based on WAFs detected by identYwaf (kb.identifiedWafs)
    
    If multiple WAFs detected, combines unique tampers up to MAX_TAMPERS
    """
    detected_wafs = getattr(kb, 'identifiedWafs', set())
    
    if not detected_wafs:
        return []
    
    all_tampers = []
    
    for waf in detected_wafs:
        tampers = getWafTampers(waf)
        for t in tampers:
            if t not in all_tampers:
                all_tampers.append(t)
                if len(all_tampers) >= MAX_TAMPERS:
                    break
        if len(all_tampers) >= MAX_TAMPERS:
            break
    
    return all_tampers


def applyWafBypassLevel():
    """
    Applies WAF bypass tamper scripts based on conf.wafBypassLevel
    
    Values:
        - "auto" or 0: Use detected WAF (kb.identifiedWafs)
        - WAF name (string): Use specific WAF tampers
        - Integer 1-5: Legacy mode (not recommended)
    """
    
    level = conf.get("wafBypassLevel")
    
    if not level:
        return
    
    tampers = []
    waf_info = ""
    
    # Handle different input types
    if isinstance(level, str):
        level_lower = level.lower().strip()
        
        if level_lower == "auto":
            # Auto-detect from kb.identifiedWafs
            tampers = getDetectedWafTampers()
            if tampers:
                detected = list(getattr(kb, 'identifiedWafs', set()))
                waf_info = "detected WAF(s): %s" % ', '.join(detected[:3])
            else:
                # No WAF detected yet, use generic
                tampers = WAF_TAMPERS["generic"]["tampers"][:MAX_TAMPERS]
                waf_info = "no WAF detected, using generic"
        else:
            # Specific WAF name provided
            tampers = getWafTampers(level_lower)
            waf_info = "WAF: %s" % normalizeWafName(level_lower)
    
    elif isinstance(level, int):
        if level == 0:
            # Same as "auto"
            tampers = getDetectedWafTampers()
            if not tampers:
                tampers = WAF_TAMPERS["generic"]["tampers"][:MAX_TAMPERS]
            waf_info = "auto mode"
        else:
            # Legacy numeric level - map to generic with increasing tampers
            # Level 1-2: basic, Level 3-4: moderate, Level 5: aggressive
            if level <= 2:
                tampers = ["randomcase", "space2comment", "between"]
            elif level <= 4:
                tampers = ["randomcase", "space2comment", "oversizedrequest", "xforwardedfor"]
            else:
                tampers = ["randomcase", "space2comment", "oversizedrequest", "unicodenormalize"]
            waf_info = "legacy level %d" % level
    
    if not tampers:
        return
    
    # Get existing tampers
    existing = conf.get("tamper") or ""
    if existing:
        existing_list = [t.strip() for t in existing.split(',') if t.strip()]
    else:
        existing_list = []
    
    # Merge: WAF bypass tampers first, then existing (avoid duplicates)
    all_tampers = tampers + [t for t in existing_list if t not in tampers]
    
    # Update conf
    conf.tamper = ','.join(all_tampers)
    
    infoMsg = "WAF bypass (%s): applying %d tampers: %s" % (
        waf_info, len(tampers), ', '.join(tampers)
    )
    logger.info(infoMsg)


def printWafBypassHelp():
    """
    Prints help information about WAF bypass options
    """
    
    help_text = """
WAF Bypass Options:
===================

Usage:
    --waf-bypass=auto           Auto-detect WAF and apply optimal tampers
    --waf-bypass=cloudflare     Apply Cloudflare-specific tampers
    --waf-bypass=modsecurity    Apply ModSecurity-specific tampers
    --waf-bypass=aws            Apply AWS WAF-specific tampers
    etc.

Supported WAFs:
"""
    
    for waf, config in sorted(WAF_TAMPERS.items()):
        if waf != "generic":
            help_text += "    %-20s %s\n" % (waf, config["notes"])
    
    help_text += """
Examples:
    # Auto-detect WAF and apply bypass
    sqlmap -u "http://target.com/?id=1" --waf-bypass=auto

    # Force Cloudflare bypass (8KB body limit)
    sqlmap -u "http://target.com/?id=1" --waf-bypass=cloudflare

    # Force ModSecurity bypass
    sqlmap -u "http://target.com/?id=1" --waf-bypass=modsecurity

Notes:
    - Maximum %d tampers are applied to avoid conflicts
    - Use 'auto' to let sqlmap detect the WAF first
    - Combine with --chunked for additional evasion
""" % MAX_TAMPERS
    
    return help_text


def listSupportedWafs():
    """
    Returns list of supported WAF names
    """
    return sorted([w for w in WAF_TAMPERS.keys() if w != "generic"])
