#!/usr/bin/env python

# Author: CyberVaca , Luis Vacas de Santos
# Twitter: https://twitter.com/CyberVaca_

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import random
import time

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Marks the request for slow/delayed transmission to evade timing-based WAF detection

    Requirement:
        * Custom request handler support (sets headers for delayed transmission)

    Tested against:
        * WAFs with timing-based anomaly detection
        * Rate-limiting WAFs
        * Behavioral analysis WAFs

    Notes:
        * Many WAFs use timing patterns to detect automated attacks
        * By sending requests slowly (byte-by-byte or chunk-by-chunk with delays),
          the request may appear more like legitimate human traffic
        * This tamper sets markers that can be used by custom request handlers
          to implement slow transmission
        * Combine with --delay for additional evasion
        * "Low and slow" attacks are harder to detect

    Reference:
        * https://medium.com/@gasmask/bypassing-wafs-in-2025-new-techniques-and-evasion-tactics
        * Slowloris attack concept applied to WAF evasion

    >>> tamper('1 AND 1=1')
    '1 AND 1=1'
    """

    headers = kwargs.get("headers", {})
    
    # Set markers for slow request transmission
    # These can be read by custom request handlers
    
    # Delay between chunks/bytes in milliseconds
    delay_ms = random.randint(50, 200)
    headers["X-Slow-Request-Delay"] = str(delay_ms)
    
    # Chunk size for slow transmission (bytes)
    chunk_size = random.randint(1, 10)
    headers["X-Slow-Request-Chunk-Size"] = str(chunk_size)
    
    # Enable slow request mode
    headers["X-Slow-Request-Mode"] = "enabled"
    
    # Random jitter to make timing less predictable
    jitter_ms = random.randint(0, 50)
    headers["X-Slow-Request-Jitter"] = str(jitter_ms)
    
    return payload


def slow_send_data(data, sock, chunk_size=1, delay_ms=100, jitter_ms=50):
    """
    Helper function to send data slowly over a socket
    
    Args:
        data: The data to send
        sock: The socket object
        chunk_size: Number of bytes to send at a time
        delay_ms: Base delay between chunks in milliseconds
        jitter_ms: Random jitter to add to delay
        
    Returns:
        Total bytes sent
    """
    
    total_sent = 0
    data_bytes = data.encode() if isinstance(data, str) else data
    
    for i in range(0, len(data_bytes), chunk_size):
        chunk = data_bytes[i:i + chunk_size]
        sock.send(chunk)
        total_sent += len(chunk)
        
        # Add delay with jitter
        actual_delay = delay_ms + random.randint(0, jitter_ms)
        time.sleep(actual_delay / 1000.0)
    
    return total_sent


def create_slow_http_request(method, path, headers, body=None, chunk_size=1, delay_ms=100):
    """
    Creates an HTTP request formatted for slow transmission
    
    Args:
        method: HTTP method (GET, POST, etc.)
        path: Request path
        headers: Dictionary of headers
        body: Request body (optional)
        chunk_size: Bytes per chunk
        delay_ms: Delay between chunks
        
    Returns:
        List of (chunk, delay) tuples for slow transmission
    """
    
    # Build request line
    request_line = "%s %s HTTP/1.1\r\n" % (method, path)
    
    # Build headers
    header_lines = ""
    for name, value in headers.items():
        header_lines += "%s: %s\r\n" % (name, value)
    header_lines += "\r\n"
    
    # Combine request
    full_request = request_line + header_lines
    if body:
        full_request += body
    
    # Split into chunks with delays
    chunks = []
    for i in range(0, len(full_request), chunk_size):
        chunk = full_request[i:i + chunk_size]
        jitter = random.randint(0, delay_ms // 2)
        chunks.append((chunk, delay_ms + jitter))
    
    return chunks


class SlowRequestWrapper:
    """
    Wrapper class for implementing slow HTTP requests
    Can be used to wrap existing request mechanisms
    """
    
    def __init__(self, chunk_size=1, delay_ms=100, jitter_ms=50):
        self.chunk_size = chunk_size
        self.delay_ms = delay_ms
        self.jitter_ms = jitter_ms
    
    def send_slow(self, sock, data):
        """
        Send data slowly over the socket
        """
        return slow_send_data(
            data, 
            sock, 
            self.chunk_size, 
            self.delay_ms, 
            self.jitter_ms
        )
    
    def get_transmission_time(self, data_length):
        """
        Estimate total transmission time for given data length
        """
        num_chunks = (data_length + self.chunk_size - 1) // self.chunk_size
        avg_delay = self.delay_ms + (self.jitter_ms / 2)
        return num_chunks * avg_delay / 1000.0  # Return in seconds


def tamper_with_incomplete_headers(payload, **kwargs):
    """
    Sends headers slowly/incompletely to exploit WAF timeout behaviors
    Some WAFs may timeout waiting for complete headers and let the request through
    """
    
    headers = kwargs.get("headers", {})
    
    # Mark for incomplete header transmission
    headers["X-Incomplete-Headers-Mode"] = "enabled"
    
    # Time to wait before completing headers (ms)
    headers["X-Header-Completion-Delay"] = str(random.randint(5000, 15000))
    
    return payload
