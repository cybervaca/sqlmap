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

# Maximum number of tampers to apply (to avoid sqlmap warning)
MAX_TAMPERS = 4

# =============================================================================
# WAF-SPECIFIC TAMPER CONFIGURATIONS
# Based on WhatWaf research and known bypass techniques
# =============================================================================

WAF_TAMPERS = {
    # =========================================================================
    # CLOUD WAFs
    # =========================================================================
    
    "cloudflare": {
        "tampers": ["oversizedrequest", "randomcase", "space2comment"],
        "notes": "8KB body limit bypass. CF-RAY header detection.",
        "detection": ["cf-ray", "__cfduid", "cloudflare"],
        "techniques": "Oversized request (>8KB) bypasses inspection entirely"
    },
    
    "aws": {
        "tampers": ["oversizedrequest", "randomcase", "between"],
        "notes": "8KB body limit. x-amz-id header detection.",
        "detection": ["x-amz-id", "x-amz-request-id", "aws"],
        "techniques": "Body size limit + basic obfuscation"
    },
    
    "cloudfront": {
        "tampers": ["oversizedrequest", "randomcase", "charencode"],
        "notes": "Amazon CloudFront CDN with WAF",
        "detection": ["cloudfront", "x-amz-cf-id"],
        "techniques": "Similar to AWS WAF"
    },
    
    "google": {
        "tampers": ["oversizedrequest", "randomcase", "charencode"],
        "notes": "8KB limit. Google Cloud Armor.",
        "detection": ["google", "gfe", "cloud armor"],
        "techniques": "Oversized + encoding"
    },
    
    "azure": {
        "tampers": ["oversizedrequest", "xforwardedfor", "randomcase"],
        "notes": "128KB Front Door limit. Azure WAF.",
        "detection": ["azure", "front door", "microsoft"],
        "techniques": "Larger body limit, header manipulation"
    },
    
    "akamai": {
        "tampers": ["oversizedrequest", "xforwardedfor", "apostrophemask", "randomcase"],
        "notes": "Akamai Ghost/Kona. Header manipulation effective.",
        "detection": ["akamai", "ghost", "kona", "ak_bmsc"],
        "techniques": "Header spoofing + apostrophe encoding"
    },
    
    # =========================================================================
    # COMMERCIAL WAFs
    # =========================================================================
    
    "modsecurity": {
        "tampers": ["space2comment", "versionedmorekeywords", "randomcase"],
        "notes": "OWASP CRS. MySQL version comments effective.",
        "detection": ["mod_security", "modsecurity", "owasp"],
        "techniques": "/*!50000 version comments bypass many rules"
    },
    
    "imperva": {
        "tampers": ["xforwardedfor", "unicodenormalize", "space2morecomment", "randomcase"],
        "notes": "Incapsula. Unicode + header manipulation.",
        "detection": ["incapsula", "imperva", "incap_ses", "visid_incap"],
        "techniques": "Unicode normalization bypass + IP spoofing"
    },
    
    "incapsula": {
        "tampers": ["xforwardedfor", "unicodenormalize", "space2morecomment", "randomcase"],
        "notes": "Same as Imperva (Incapsula is Imperva product)",
        "detection": ["incapsula", "incap_ses", "visid_incap"],
        "techniques": "Unicode + headers"
    },
    
    "f5": {
        "tampers": ["parampollutionfull", "randomcase", "space2comment", "between"],
        "notes": "BIG-IP ASM. Parameter pollution effective.",
        "detection": ["f5", "big-ip", "bigip", "asm", "ts="],
        "techniques": "HPP confuses F5 parameter parsing"
    },
    
    "bigip": {
        "tampers": ["parampollutionfull", "randomcase", "space2comment", "between"],
        "notes": "F5 BIG-IP Application Security Manager",
        "detection": ["big-ip", "bigip", "bigipserver"],
        "techniques": "Same as F5"
    },
    
    "fortinet": {
        "tampers": ["oversizedrequest", "randomcase", "charencode"],
        "notes": "FortiWeb. 64MB limit - very high, use encoding.",
        "detection": ["fortigate", "fortinet", "fortiweb", "fortiwafsid"],
        "techniques": "Large body limit, encoding bypass"
    },
    
    "sucuri": {
        "tampers": ["oversizedrequest", "xforwardedfor", "randomcase"],
        "notes": "Sucuri CloudProxy. 1.25MB limit.",
        "detection": ["sucuri", "cloudproxy", "x-sucuri"],
        "techniques": "Oversized + header manipulation"
    },
    
    "barracuda": {
        "tampers": ["space2comment", "randomcase", "between", "charencode"],
        "notes": "Barracuda WAF. Comment-based bypass.",
        "detection": ["barracuda", "barra_counter_session"],
        "techniques": "SQL comments + encoding"
    },
    
    "citrix": {
        "tampers": ["xforwardedfor", "randomcase", "charencode", "space2comment"],
        "notes": "NetScaler AppFirewall.",
        "detection": ["citrix", "netscaler", "ns_af"],
        "techniques": "Header manipulation + encoding"
    },
    
    "radware": {
        "tampers": ["oversizedrequest", "randomcase", "charencode", "xforwardedfor"],
        "notes": "AppWall WAF.",
        "detection": ["radware", "appwall", "x-sl-compstate"],
        "techniques": "Oversized + encoding"
    },
    
    "paloalto": {
        "tampers": ["randomcase", "charencode", "space2morecomment"],
        "notes": "PAN-OS URL Filtering.",
        "detection": ["palo alto", "pan-os"],
        "techniques": "Encoding + comments"
    },
    
    # =========================================================================
    # OPEN SOURCE / CMS WAFs
    # =========================================================================
    
    "wordfence": {
        "tampers": ["randomcase", "space2comment", "between"],
        "notes": "WordPress WAF plugin.",
        "detection": ["wordfence", "wfwaf"],
        "techniques": "Basic obfuscation usually sufficient"
    },
    
    "comodo": {
        "tampers": ["randomcase", "charencode", "space2comment"],
        "notes": "Comodo WAF.",
        "detection": ["comodo", "protected by comodo"],
        "techniques": "Encoding + case randomization"
    },
    
    "wallarm": {
        "tampers": ["unicodenormalize", "randomcase", "doubleencode"],
        "notes": "ML-based WAF. Unicode tricks effective.",
        "detection": ["wallarm", "nginx-wallarm"],
        "techniques": "Unicode + double encoding for ML bypass"
    },
    
    "reblaze": {
        "tampers": ["xforwardedfor", "randomcase", "space2comment"],
        "notes": "Reblaze WAF.",
        "detection": ["reblaze", "rbzid"],
        "techniques": "Header manipulation"
    },
    
    "sophos": {
        "tampers": ["randomcase", "space2comment", "between"],
        "notes": "Sophos UTM WAF.",
        "detection": ["sophos"],
        "techniques": "Basic obfuscation"
    },
    
    # =========================================================================
    # CHINESE WAFs
    # =========================================================================
    
    "360": {
        "tampers": ["charencode", "randomcase", "space2comment"],
        "notes": "360 WAF (Chinese).",
        "detection": ["360", "wzws-waf-cgi"],
        "techniques": "Encoding bypass"
    },
    
    "aliyundun": {
        "tampers": ["charencode", "randomcase", "unicodenormalize"],
        "notes": "Alibaba Cloud WAF.",
        "detection": ["aliyundun", "aliyun", "errors.aliyun.com"],
        "techniques": "Unicode + encoding"
    },
    
    "baidu": {
        "tampers": ["charencode", "randomcase", "space2comment"],
        "notes": "Baidu Yunjiasu WAF.",
        "detection": ["yunjiasu", "baidu"],
        "techniques": "Encoding bypass"
    },
    
    "tencent": {
        "tampers": ["charencode", "randomcase", "unicodenormalize"],
        "notes": "Tencent Cloud WAF.",
        "detection": ["tencent", "waf.tencent"],
        "techniques": "Unicode + encoding"
    },
    
    "safedog": {
        "tampers": ["charencode", "randomcase", "space2morecomment"],
        "notes": "SafeDog WAF (Chinese).",
        "detection": ["safedog", "safe dog"],
        "techniques": "Encoding + comments"
    },
    
    "yundun": {
        "tampers": ["charencode", "randomcase", "space2comment"],
        "notes": "Yundun WAF.",
        "detection": ["yundun"],
        "techniques": "Encoding bypass"
    },
    
    # =========================================================================
    # OTHER WAFs
    # =========================================================================
    
    "dotdefender": {
        "tampers": ["randomcase", "space2comment", "charencode"],
        "notes": "dotDefender WAF.",
        "detection": ["dotdefender", "applicure"],
        "techniques": "Basic obfuscation"
    },
    
    "webknight": {
        "tampers": ["randomcase", "charencode", "space2comment"],
        "notes": "AQTRONIX WebKnight.",
        "detection": ["webknight", "aqtronix"],
        "techniques": "Encoding + case"
    },
    
    "naxsi": {
        "tampers": ["space2comment", "randomcase", "charencode"],
        "notes": "Nginx Anti-XSS & SQL Injection.",
        "detection": ["naxsi", "naxsi_sig"],
        "techniques": "Comment-based bypass"
    },
    
    "armor": {
        "tampers": ["xforwardedfor", "randomcase", "space2comment"],
        "notes": "Armor Defense (uses Imperva).",
        "detection": ["armor"],
        "techniques": "Header manipulation"
    },
    
    "airlock": {
        "tampers": ["randomcase", "charencode", "space2comment"],
        "notes": "Phion/Ergon Airlock.",
        "detection": ["airlock", "al_sess", "al_lb"],
        "techniques": "Encoding bypass"
    },
    
    "sitelock": {
        "tampers": ["randomcase", "space2comment", "between"],
        "notes": "SiteLock TrueShield.",
        "detection": ["sitelock", "trueshield"],
        "techniques": "Basic obfuscation"
    },
    
    # =========================================================================
    # GENERIC / FALLBACK
    # =========================================================================
    
    "generic": {
        "tampers": ["randomcase", "space2comment", "between"],
        "notes": "Generic bypass for unknown WAFs.",
        "detection": [],
        "techniques": "Basic obfuscation as fallback"
    },
}

# =============================================================================
# ALIASES - Map various WAF names to our standard keys
# =============================================================================

WAF_ALIASES = {
    # Cloudflare variants
    "cloudflare inc.": "cloudflare",
    "cloudflare waf": "cloudflare",
    
    # AWS variants
    "amazon web services": "aws",
    "amazon": "aws",
    "aws waf": "aws",
    "awswaf": "aws",
    
    # Azure variants
    "microsoft azure": "azure",
    "azure waf": "azure",
    "azurewaf": "azure",
    "azure front door": "azure",
    
    # Google variants
    "google cloud": "google",
    "google cloud armor": "google",
    "googlecloudarmor": "google",
    "gcp": "google",
    
    # ModSecurity variants
    "mod_security": "modsecurity",
    "modsec": "modsecurity",
    "owasp": "modsecurity",
    "owasp crs": "modsecurity",
    "owasp modsecurity": "modsecurity",
    
    # Imperva variants
    "imperva incapsula": "imperva",
    "imperva waf": "imperva",
    
    # F5 variants
    "f5 networks": "f5",
    "f5 big-ip": "f5",
    "f5 asm": "f5",
    "application security manager": "f5",
    
    # Fortinet variants
    "fortinet fortigate": "fortinet",
    "fortiweb": "fortinet",
    "fortigate": "fortinet",
    
    # Citrix variants
    "citrix netscaler": "citrix",
    "netscaler": "citrix",
    "netscaler appfirewall": "citrix",
    
    # Palo Alto variants
    "palo alto": "paloalto",
    "pan-os": "paloalto",
    
    # Akamai variants
    "akamai ghost": "akamai",
    "akamai kona": "akamai",
    "kona": "akamai",
    
    # Chinese WAFs
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
    
    If multiple WAFs detected, combines unique tampers up to MAX_TAMPERS
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
            tampers, detected_names = getDetectedWafTampers()
            if tampers:
                waf_info = "detected: %s" % ', '.join(detected_names[:2])
            else:
                # No WAF detected yet, use generic
                tampers = WAF_TAMPERS["generic"]["tampers"][:MAX_TAMPERS]
                waf_info = "no WAF detected, using generic"
        else:
            # Specific WAF name provided
            normalized = normalizeWafName(level_lower)
            tampers = getWafTampers(level_lower)
            info = getWafInfo(level_lower)
            waf_info = "%s (%s)" % (normalized, info.get("notes", "")[:40])
    
    elif isinstance(level, int):
        if level == 0:
            # Same as "auto"
            tampers, detected_names = getDetectedWafTampers()
            if not tampers:
                tampers = WAF_TAMPERS["generic"]["tampers"][:MAX_TAMPERS]
            waf_info = "auto mode"
        else:
            # Legacy numeric level - map to increasing aggressiveness
            if level <= 2:
                tampers = ["randomcase", "space2comment", "between"]
            elif level <= 4:
                tampers = ["randomcase", "space2comment", "oversizedrequest", "xforwardedfor"]
            else:
                tampers = ["randomcase", "oversizedrequest", "unicodenormalize", "doubleencode"]
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
    
    infoMsg = "WAF bypass (%s): %s" % (waf_info, ', '.join(tampers))
    logger.info(infoMsg)


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
    --waf-bypass=aws            Apply AWS WAF-specific tampers
    etc.

Supported WAFs and Techniques:
"""
    
    categories = {
        "Cloud WAFs": ["cloudflare", "aws", "google", "azure", "akamai"],
        "Commercial": ["modsecurity", "imperva", "f5", "fortinet", "sucuri", "barracuda", "citrix"],
        "Other": ["wordfence", "wallarm", "radware", "sophos", "paloalto"],
    }
    
    for category, wafs in categories.items():
        help_text += "\n%s:\n" % category
        for waf in wafs:
            if waf in WAF_TAMPERS:
                config = WAF_TAMPERS[waf]
                tampers = ', '.join(config["tampers"][:3])
                help_text += "    %-15s %s\n" % (waf, tampers)
    
    help_text += """
Examples:
    # Auto-detect WAF and apply bypass
    sqlmap -u "http://target.com/?id=1" --waf-bypass=auto

    # Force Cloudflare bypass (8KB body limit)
    sqlmap -u "http://target.com/?id=1" --waf-bypass=cloudflare

    # Force ModSecurity bypass (version comments)
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


def getWafBypassStats():
    """
    Returns statistics about WAF bypass configurations
    """
    return {
        "total_wafs": len(WAF_TAMPERS) - 1,  # Exclude generic
        "max_tampers": MAX_TAMPERS,
        "categories": {
            "cloud": len([w for w in ["cloudflare", "aws", "google", "azure", "akamai", "cloudfront"] if w in WAF_TAMPERS]),
            "commercial": len([w for w in ["modsecurity", "imperva", "f5", "fortinet", "sucuri", "barracuda", "citrix", "radware", "paloalto"] if w in WAF_TAMPERS]),
            "other": len(WAF_TAMPERS) - 1 - 6 - 9,
        }
    }
