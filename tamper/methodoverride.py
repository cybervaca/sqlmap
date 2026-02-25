#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_

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
    Uses HTTP method override headers to bypass WAF inspection

    Requirement:
        * Target must support method override headers
        * Works with frameworks like Rails, Laravel, Express, etc.

    Tested against:
        * ModSecurity CRS
        * Cloudflare WAF
        * AWS WAF
        * WAFs that only inspect GET/POST

    Notes:
        * Many WAFs only deeply inspect GET and POST requests
        * Using PUT, PATCH, DELETE or method override headers can bypass inspection
        * Some frameworks accept X-HTTP-Method-Override to change the actual method
        * This tamper adds headers to signal method override

    Reference:
        * https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/
        * OWASP Testing Guide

    >>> tamper('1 AND 1=1')
    '1 AND 1=1'
    """

    headers = kwargs.get("headers", {})
    
    # HTTP Method Override headers
    # These tell the backend to treat the request as a different method
    override_methods = ["PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]
    selected_method = random.choice(override_methods)
    
    # Standard method override headers used by various frameworks
    headers["X-HTTP-Method-Override"] = selected_method
    headers["X-HTTP-Method"] = selected_method
    headers["X-Method-Override"] = selected_method
    
    # .NET specific
    headers["X-HTTP-Method-Override"] = selected_method
    
    # Rails specific
    headers["_method"] = selected_method.lower()
    
    # Some frameworks use these
    headers["X-Original-HTTP-Method"] = "POST"
    headers["X-Requested-With"] = "XMLHttpRequest"
    
    return payload


def tamper_put(payload, **kwargs):
    """
    Specifically sets PUT method override
    Useful when WAF ignores PUT requests
    """
    
    headers = kwargs.get("headers", {})
    
    headers["X-HTTP-Method-Override"] = "PUT"
    headers["X-HTTP-Method"] = "PUT"
    headers["X-Method-Override"] = "PUT"
    
    return payload


def tamper_patch(payload, **kwargs):
    """
    Specifically sets PATCH method override
    """
    
    headers = kwargs.get("headers", {})
    
    headers["X-HTTP-Method-Override"] = "PATCH"
    headers["X-HTTP-Method"] = "PATCH"
    headers["X-Method-Override"] = "PATCH"
    
    return payload


def tamper_delete(payload, **kwargs):
    """
    Specifically sets DELETE method override
    """
    
    headers = kwargs.get("headers", {})
    
    headers["X-HTTP-Method-Override"] = "DELETE"
    headers["X-HTTP-Method"] = "DELETE"
    headers["X-Method-Override"] = "DELETE"
    
    return payload


def tamper_content_type_method(payload, **kwargs):
    """
    Combines method override with Content-Type manipulation
    Some WAFs check method + content-type combinations
    """
    
    headers = kwargs.get("headers", {})
    
    # Use PUT with unusual content type
    headers["X-HTTP-Method-Override"] = "PUT"
    headers["Content-Type"] = "application/merge-patch+json"
    
    return payload


def tamper_graphql_method(payload, **kwargs):
    """
    Uses GraphQL-style headers that some WAFs whitelist
    """
    
    headers = kwargs.get("headers", {})
    
    headers["X-HTTP-Method-Override"] = "POST"
    headers["Content-Type"] = "application/graphql"
    headers["X-GraphQL-Operation-Name"] = "query"
    
    return payload


def tamper_websocket_upgrade(payload, **kwargs):
    """
    Adds WebSocket upgrade headers
    Some WAFs don't inspect WebSocket upgrade requests
    """
    
    headers = kwargs.get("headers", {})
    
    headers["Upgrade"] = "websocket"
    headers["Connection"] = "Upgrade"
    headers["Sec-WebSocket-Version"] = "13"
    headers["Sec-WebSocket-Key"] = "dGhlIHNhbXBsZSBub25jZQ=="
    
    return payload
