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
to select optimal tamper scripts for each specific WAF.

IMPORTANT: Tampers are applied AFTER WAF detection (checkWaf()) to ensure
we know which WAF we're dealing with before selecting bypass techniques.

Usage:
    --waf-bypass=auto         Auto-detect WAF and apply specific tampers
    --waf-bypass=cloudflare   Force Cloudflare-specific tampers
    --waf-bypass=modsecurity  Force ModSecurity-specific tampers
    etc.

Reference:
    * https://github.com/Ekultek/WhatWaf
    * https://www.blackhillsinfosec.com/bypassing-wafs-using-oversized-requests/
    * https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/
"""

from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.settings import UNICODE_ENCODING

# Maximum number of tampers to apply (to avoid sqlmap warning)
MAX_TAMPERS = 4

# =============================================================================
# WAF-SPECIFIC TAMPER CONFIGURATIONS
# Based on tested combinations and WhatWaf research
# =============================================================================

WAF_TAMPERS = {
    # =========================================================================
    # CLOUD WAFs
    # =========================================================================
    
    "cloudflare": {
        # --tamper=space2comment,between,randomcase,charencode
        # --tamper=space2comment,randomcase,apostrophemask
        "tampers": ["space2comment", "between", "randomcase", "charencode"],
        "notes": "8KB body limit. Effective: space2comment, between, randomcase, charencode",
        "detection": ["cf-ray", "__cfduid", "cloudflare"],
    },
    
    "aws": {
        # Similar to Cloudflare, 8KB limit
        "tampers": ["space2comment", "between", "randomcase", "charencode"],
        "notes": "8KB body limit. Similar techniques to Cloudflare.",
        "detection": ["x-amz-id", "x-amz-request-id", "aws"],
    },
    
    "akamai": {
        # --tamper=space2comment,between,randomcase,charencode
        # --tamper=charunicodeencode,space2comment,randomcase
        # --tamper=space2plus,space2comment,randomcase
        "tampers": ["charunicodeencode", "space2comment", "randomcase", "space2plus"],
        "notes": "Unicode encoding effective. Also: space2plus, charencode",
        "detection": ["akamai", "ghost", "kona", "ak_bmsc"],
    },
    
    "sucuri": {
        # --tamper=space2comment,between,randomcase,charencode
        # --tamper=space2plus,space2comment,randomcase
        "tampers": ["space2comment", "between", "randomcase", "charencode"],
        "notes": "1.25MB limit. Similar to Cloudflare techniques.",
        "detection": ["sucuri", "cloudproxy", "x-sucuri"],
    },
    
    "stackpath": {
        # --tamper=space2plus,space2comment,randomcase
        "tampers": ["space2plus", "space2comment", "randomcase"],
        "notes": "space2plus effective.",
        "detection": ["stackpath"],
    },
    
    "azure": {
        # --tamper=charunicodeencode,space2comment,randomcase
        "tampers": ["charunicodeencode", "space2comment", "randomcase"],
        "notes": "128KB limit. Unicode encoding effective.",
        "detection": ["azure", "front door", "microsoft"],
    },
    
    "google": {
        "tampers": ["space2comment", "between", "randomcase", "charencode"],
        "notes": "8KB limit. Similar to Cloudflare.",
        "detection": ["google", "gfe", "cloud armor"],
    },
    
    # =========================================================================
    # MODSECURITY VARIANTS
    # =========================================================================
    
    "modsecurity": {
        # --tamper=between,randomcase,space2comment
        # --tamper=modsecurityversioned,space2comment
        # --tamper=between,space2comment,modsecurityzeroversioned
        "tampers": ["between", "randomcase", "space2comment", "modsecurityversioned"],
        "notes": "Version comments /*!50000*/ very effective. Also: modsecurityzeroversioned",
        "detection": ["mod_security", "modsecurity", "owasp"],
    },
    
    "comodo": {
        # --tamper=modsecurityversioned,space2comment
        # --tamper=between,space2comment,modsecurityzeroversioned
        "tampers": ["modsecurityversioned", "space2comment", "between", "modsecurityzeroversioned"],
        "notes": "ModSecurity-based. Version comments effective.",
        "detection": ["comodo", "protected by comodo"],
    },
    
    # =========================================================================
    # IMPERVA / INCAPSULA
    # =========================================================================
    
    "imperva": {
        # --tamper=space2comment,space2morehash
        # --tamper=space2comment,between,percentage
        # --tamper=space2comment,randomcase,apostrophemask
        "tampers": ["space2comment", "space2morehash", "between", "percentage"],
        "notes": "space2morehash, percentage effective. Also: apostrophemask",
        "detection": ["incapsula", "imperva", "incap_ses", "visid_incap"],
    },
    
    "incapsula": {
        "tampers": ["space2comment", "space2morehash", "between", "percentage"],
        "notes": "Same as Imperva.",
        "detection": ["incapsula", "incap_ses", "visid_incap"],
    },
    
    # =========================================================================
    # F5 / BIG-IP
    # =========================================================================
    
    "f5": {
        # --tamper=between,randomcase,space2comment
        # --tamper=charencode,randomcase,space2comment
        # --tamper=space2comment,between,randomcase,equaltolike
        "tampers": ["between", "randomcase", "space2comment", "equaltolike"],
        "notes": "between, equaltolike effective. Also: charencode",
        "detection": ["f5", "big-ip", "bigip", "asm", "ts="],
    },
    
    "bigip": {
        "tampers": ["between", "randomcase", "space2comment", "equaltolike"],
        "notes": "Same as F5.",
        "detection": ["big-ip", "bigip", "bigipserver"],
    },
    
    # =========================================================================
    # OTHER COMMERCIAL WAFs
    # =========================================================================
    
    "barracuda": {
        # --tamper=space2comment,between,percentage
        "tampers": ["space2comment", "between", "percentage", "randomcase"],
        "notes": "percentage effective.",
        "detection": ["barracuda", "barra_counter_session"],
    },
    
    "citrix": {
        # --tamper=space2comment,between,randomcase,equaltolike
        "tampers": ["space2comment", "between", "randomcase", "equaltolike"],
        "notes": "NetScaler. equaltolike effective.",
        "detection": ["citrix", "netscaler", "ns_af"],
    },
    
    "radware": {
        # --tamper=charencode,randomcase,space2comment
        # --tamper=charunicodeencode,space2comment,randomcase
        "tampers": ["charencode", "randomcase", "space2comment", "charunicodeencode"],
        "notes": "Encoding techniques effective.",
        "detection": ["radware", "appwall", "x-sl-compstate"],
    },
    
    "fortinet": {
        # --tamper=space2comment,randomcase,overlongutf8
        "tampers": ["space2comment", "randomcase", "overlongutf8"],
        "notes": "FortiWeb. overlongutf8 effective for legacy rules.",
        "detection": ["fortigate", "fortinet", "fortiweb", "fortiwafsid"],
    },
    
    "bluecoat": {
        # --tamper=space2comment,between,randomcase,bluecoat
        "tampers": ["space2comment", "between", "randomcase", "bluecoat"],
        "notes": "Symantec WAF. Specific bluecoat tamper available.",
        "detection": ["bluecoat", "symantec"],
    },
    
    "paloalto": {
        "tampers": ["space2comment", "randomcase", "charencode"],
        "notes": "PAN-OS URL Filtering.",
        "detection": ["palo alto", "pan-os"],
    },
    
    # =========================================================================
    # PHP / CMS WAFs
    # =========================================================================
    
    "wordfence": {
        # --tamper=space2comment,randomcase,unmagicquotes
        "tampers": ["space2comment", "randomcase", "unmagicquotes"],
        "notes": "WordPress WAF. unmagicquotes for magic_quotes bypass.",
        "detection": ["wordfence", "wfwaf"],
    },
    
    "litespeed": {
        # --tamper=space2comment,randomcase,unmagicquotes
        "tampers": ["space2comment", "randomcase", "unmagicquotes"],
        "notes": "LiteSpeed WAF. Similar to PHP WAFs.",
        "detection": ["litespeed"],
    },
    
    "php": {
        # --tamper=space2comment,randomcase,unmagicquotes
        "tampers": ["space2comment", "randomcase", "unmagicquotes"],
        "notes": "Generic PHP WAF. unmagicquotes effective.",
        "detection": ["php"],
    },
    
    # =========================================================================
    # OTHER WAFs
    # =========================================================================
    
    "wallarm": {
        "tampers": ["charunicodeencode", "space2comment", "randomcase"],
        "notes": "ML-based WAF. Unicode encoding effective.",
        "detection": ["wallarm", "nginx-wallarm"],
    },
    
    "naxsi": {
        "tampers": ["space2comment", "randomcase", "charencode"],
        "notes": "Nginx Anti-XSS & SQL Injection.",
        "detection": ["naxsi", "naxsi_sig"],
    },
    
    "webknight": {
        "tampers": ["space2comment", "randomcase", "charencode"],
        "notes": "AQTRONIX WebKnight.",
        "detection": ["webknight", "aqtronix"],
    },
    
    "dotdefender": {
        "tampers": ["space2comment", "randomcase", "charencode"],
        "notes": "dotDefender WAF.",
        "detection": ["dotdefender", "applicure"],
    },
    
    # =========================================================================
    # CHINESE WAFs
    # =========================================================================
    
    "360": {
        "tampers": ["charencode", "randomcase", "space2comment"],
        "notes": "360 WAF (Chinese).",
        "detection": ["360", "wzws-waf-cgi"],
    },
    
    "aliyundun": {
        "tampers": ["charencode", "randomcase", "charunicodeencode"],
        "notes": "Alibaba Cloud WAF.",
        "detection": ["aliyundun", "aliyun", "errors.aliyun.com"],
    },
    
    "baidu": {
        "tampers": ["charencode", "randomcase", "space2comment"],
        "notes": "Baidu Yunjiasu WAF.",
        "detection": ["yunjiasu", "baidu"],
    },
    
    "safedog": {
        "tampers": ["charencode", "randomcase", "space2comment"],
        "notes": "SafeDog WAF (Chinese).",
        "detection": ["safedog", "safe dog"],
    },
    
    # =========================================================================
    # GENERIC / FALLBACK
    # =========================================================================
    
    "generic": {
        "tampers": ["space2comment", "randomcase", "between"],
        "notes": "Generic bypass for unknown WAFs.",
        "detection": [],
    },
}

# =============================================================================
# ALIASES - Map various WAF names to our standard keys
# =============================================================================

WAF_ALIASES = {
    # Cloudflare
    "cloudflare inc.": "cloudflare",
    "cloudflare waf": "cloudflare",
    
    # AWS
    "amazon web services": "aws",
    "amazon": "aws",
    "aws waf": "aws",
    "awswaf": "aws",
    "cloudfront": "aws",
    
    # Azure
    "microsoft azure": "azure",
    "azure waf": "azure",
    "azure front door": "azure",
    
    # Google
    "google cloud": "google",
    "google cloud armor": "google",
    "gcp": "google",
    
    # ModSecurity
    "mod_security": "modsecurity",
    "modsec": "modsecurity",
    "owasp": "modsecurity",
    "owasp crs": "modsecurity",
    "owasp modsecurity": "modsecurity",
    
    # Imperva
    "imperva incapsula": "imperva",
    "imperva waf": "imperva",
    "imperva securesphere": "imperva",
    "securesphere": "imperva",
    
    # F5
    "f5 networks": "f5",
    "f5 big-ip": "f5",
    "f5 asm": "f5",
    "application security manager": "f5",
    
    # Fortinet
    "fortinet fortigate": "fortinet",
    "fortiweb": "fortinet",
    "fortigate": "fortinet",
    
    # Citrix
    "citrix netscaler": "citrix",
    "netscaler": "citrix",
    "netscaler appfirewall": "citrix",
    
    # Symantec
    "symantec": "bluecoat",
    "symantec waf": "bluecoat",
    
    # Palo Alto
    "palo alto": "paloalto",
    "pan-os": "paloalto",
    
    # Akamai
    "akamai ghost": "akamai",
    "akamai kona": "akamai",
    "kona": "akamai",
    
    # Chinese
    "alibaba": "aliyundun",
    "alibaba cloud": "aliyundun",
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
    
    # Check direct match in WAF_TAMPERS
    for waf_key in WAF_TAMPERS.keys():
        if waf_key in waf_lower or waf_lower in waf_key:
            return waf_key
    
    # Check detection keywords
    for waf_key, config in WAF_TAMPERS.items():
        for keyword in config.get("detection", []):
            if keyword.lower() in waf_lower:
                return waf_key
    
    return "generic"


def getWafTampers(waf_name):
    """
    Returns the optimal tamper scripts for a specific WAF
    """
    normalized = normalizeWafName(waf_name)
    
    if normalized in WAF_TAMPERS:
        return WAF_TAMPERS[normalized]["tampers"][:MAX_TAMPERS]
    
    return WAF_TAMPERS["generic"]["tampers"][:MAX_TAMPERS]


def getWafInfo(waf_name):
    """
    Returns information about bypass techniques for a WAF
    """
    normalized = normalizeWafName(waf_name)
    
    if normalized in WAF_TAMPERS:
        return WAF_TAMPERS[normalized]
    
    return WAF_TAMPERS["generic"]


def getDetectedWafTampers():
    """
    Returns tampers based on WAFs detected by identYwaf (kb.identifiedWafs)
    """
    detected_wafs = getattr(kb, 'identifiedWafs', set())
    
    if not detected_wafs:
        return [], []
    
    all_tampers = []
    detected_names = []
    
    for waf in detected_wafs:
        normalized = normalizeWafName(waf)
        if normalized not in detected_names:
            detected_names.append(normalized)
        
        tampers = getWafTampers(waf)
        for t in tampers:
            if t not in all_tampers:
                all_tampers.append(t)
                if len(all_tampers) >= MAX_TAMPERS:
                    break
        if len(all_tampers) >= MAX_TAMPERS:
            break
    
    return all_tampers, detected_names


def applyWafBypassAfterDetection():
    """
    Applies WAF bypass tampers AFTER WAF detection (called from controller.py)
    
    This is the main function that should be called after checkWaf() completes.
    It checks kb.identifiedWafs and applies the appropriate tampers.
    """
    
    level = conf.get("wafBypassLevel")
    
    if not level:
        return
    
    # Convert to string if needed
    if isinstance(level, int):
        level = str(level)
    
    level_lower = level.lower().strip()
    
    tampers = []
    waf_info = ""
    
    if level_lower == "auto" or level_lower == "0":
        # Auto mode - use detected WAFs
        tampers, detected_names = getDetectedWafTampers()
        
        if tampers and detected_names:
            waf_info = "detected %s" % ', '.join(detected_names[:2])
            
            # Log the specific techniques being used
            for waf_name in detected_names[:1]:
                info = getWafInfo(waf_name)
                if info.get("notes"):
                    logger.info("WAF bypass technique: %s" % info["notes"][:60])
        else:
            # No WAF detected, use generic
            tampers = WAF_TAMPERS["generic"]["tampers"][:MAX_TAMPERS]
            waf_info = "no WAF identified, using generic"
    else:
        # Specific WAF name provided by user
        normalized = normalizeWafName(level_lower)
        tampers = getWafTampers(level_lower)
        info = getWafInfo(level_lower)
        waf_info = normalized
        
        if info.get("notes"):
            logger.info("WAF bypass technique: %s" % info["notes"][:60])
    
    if not tampers:
        return
    
    # Get existing tampers
    existing = conf.get("tamper") or ""
    if existing:
        existing_list = [t.strip() for t in existing.split(',') if t.strip()]
    else:
        existing_list = []
    
    # Check if tampers are already applied
    if all(t in existing_list for t in tampers):
        return
    
    # Merge: WAF bypass tampers first, then existing (avoid duplicates)
    all_tampers = tampers + [t for t in existing_list if t not in tampers]
    
    # Update conf
    conf.tamper = ','.join(all_tampers)
    
    # Reload tamper functions
    _reloadTamperFunctions()
    
    infoMsg = "WAF bypass (%s): applying tampers: %s" % (waf_info, ', '.join(tampers))
    logger.info(infoMsg)


def _reloadTamperFunctions():
    """
    Reloads tamper functions after updating conf.tamper
    This is needed because tampers are loaded during initialization
    """
    try:
        from lib.core.option import _setTamperingFunctions
        _setTamperingFunctions()
    except Exception as ex:
        logger.debug("Could not reload tamper functions: %s" % str(ex))


def applyWafBypassLevel():
    """
    Initial WAF bypass setup (called during option initialization)
    
    For 'auto' mode: NO tampers are applied here. Tampers will be applied
    dynamically in lib/request/basic.py when identYwaf detects the WAF.
    
    For specific WAF names (e.g., --waf-bypass=cloudflare): tampers are
    applied immediately since we know which WAF to target.
    """
    
    level = conf.get("wafBypassLevel")
    
    if not level:
        return
    
    # Convert to string if needed
    if isinstance(level, int):
        level = str(level)
        conf.wafBypassLevel = level
    
    level_lower = level.lower().strip()
    
    # For auto mode, just log - tampers will be applied dynamically when WAF is detected
    if level_lower == "auto" or level_lower == "0":
        logger.info("WAF bypass mode: auto (tampers will be applied when WAF is detected)")
        return
    
    # For specific WAF, apply tampers now
    normalized = normalizeWafName(level_lower)
    tampers = getWafTampers(level_lower)
    
    if not tampers:
        return
    
    # Get existing tampers
    existing = conf.get("tamper") or ""
    if existing:
        existing_list = [t.strip() for t in existing.split(',') if t.strip()]
    else:
        existing_list = []
    
    # Merge tampers
    all_tampers = tampers + [t for t in existing_list if t not in tampers]
    conf.tamper = ','.join(all_tampers)
    
    info = getWafInfo(level_lower)
    infoMsg = "WAF bypass (%s): %s" % (normalized, ', '.join(tampers))
    logger.info(infoMsg)
    
    if info.get("notes"):
        logger.info("Technique: %s" % info["notes"][:60])


def printWafBypassHelp():
    """
    Prints help information about WAF bypass options
    """
    
    help_text = """
WAF Bypass Options (--waf-bypass):
==================================

Usage:
    --waf-bypass=auto           Auto-detect WAF and apply optimal tampers
    --waf-bypass=cloudflare     Apply Cloudflare-specific tampers
    --waf-bypass=modsecurity    Apply ModSecurity-specific tampers
    etc.

Tested Combinations:
"""
    
    tested = [
        ("ModSecurity", "between,randomcase,space2comment"),
        ("Cloudflare/Akamai/Sucuri", "space2comment,between,randomcase,charencode"),
        ("Imperva", "space2comment,space2morehash,between,percentage"),
        ("F5 ASM", "between,randomcase,space2comment,equaltolike"),
        ("PHP WAFs/Wordfence", "space2comment,randomcase,unmagicquotes"),
        ("FortiWeb", "space2comment,randomcase,overlongutf8"),
        ("Azure/Radware", "charunicodeencode,space2comment,randomcase"),
    ]
    
    for waf, tampers in tested:
        help_text += "    %-25s %s\n" % (waf + ":", tampers)
    
    help_text += """
Examples:
    # Auto-detect WAF (recommended)
    sqlmap -u "http://target.com/?id=1" --waf-bypass=auto

    # Force specific WAF bypass
    sqlmap -u "http://target.com/?id=1" --waf-bypass=cloudflare
    sqlmap -u "http://target.com/?id=1" --waf-bypass=modsecurity

Notes:
    - 'auto' mode waits for WAF detection before applying tampers
    - Maximum %d tampers are applied to avoid conflicts
    - Combine with --chunked for additional evasion
""" % MAX_TAMPERS
    
    return help_text


def listSupportedWafs():
    """
    Returns list of supported WAF names
    """
    return sorted([w for w in WAF_TAMPERS.keys() if w != "generic"])
