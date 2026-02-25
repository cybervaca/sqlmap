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

    git clone https://github.com/cybervaca/sqlmap.git 

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

Smart WAF detection with optimized tamper selection (max 4 tampers per WAF):

    python sqlmap.py -r request.req --waf-bypass=auto
    python sqlmap.py -r request.req --waf-bypass=cloudflare

**Modes:**
- `auto` - Waits for WAF detection, then applies specific tampers dynamically
- `<waf_name>` - Applies tampers for that WAF immediately

**Supported WAFs (30+):**

| Category | WAF | Tampers |
|----------|-----|---------|
| **Cloud** | `cloudflare` | cloudflarebypas, space2comment, between, randomcase |
| | `aws` | space2comment, between, randomcase, charencode |
| | `akamai` | charunicodeencode, space2comment, randomcase, space2plus |
| | `azure` | charunicodeencode, space2comment, randomcase |
| | `google` | space2comment, between, randomcase, charencode |
| | `sucuri` | space2comment, between, randomcase, charencode |
| | `stackpath` | space2plus, space2comment, randomcase |
| **Commercial** | `modsecurity` | between, randomcase, space2comment, modsecurityversioned |
| | `imperva` | space2comment, space2morehash, between, percentage |
| | `f5` / `bigip` | between, randomcase, space2comment, equaltolike |
| | `fortinet` | space2comment, randomcase, overlongutf8 |
| | `barracuda` | space2comment, between, percentage, randomcase |
| | `citrix` | space2comment, between, randomcase, equaltolike |
| | `radware` | charencode, randomcase, space2comment, charunicodeencode |
| | `paloalto` | space2comment, randomcase, charencode |
| | `bluecoat` | space2comment, between, randomcase, bluecoat |
| **CMS/PHP** | `wordfence` | space2comment, randomcase, unmagicquotes |
| | `litespeed` | space2comment, randomcase, unmagicquotes |
| | `comodo` | modsecurityversioned, space2comment, between |
| **Other** | `wallarm` | charunicodeencode, space2comment, randomcase |
| | `naxsi` | space2comment, randomcase, charencode |
| | `webknight` | space2comment, randomcase, charencode |
| | `dotdefender` | space2comment, randomcase, charencode |
| **Chinese** | `360` | charencode, randomcase, space2comment |
| | `aliyundun` | charencode, randomcase, charunicodeencode |
| | `baidu` | charencode, randomcase, space2comment |
| | `safedog` | charencode, randomcase, space2comment |

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
| `tabsandlinefeeds` | Tabs (%09) instead of spaces for regex bypass |
| `methodoverride` | HTTP method override (PUT, PATCH, DELETE) bypass |
| `doubleencode` | Double URL encoding (%2520) to bypass normalization |

### Usage Examples

```bash
# Bypass Cloudflare/AWS (8KB body limit)
python sqlmap.py -r request.req --tamper=oversizedrequest

# HTTP smuggling with chunked encoding
python sqlmap.py -r request.req --chunked --tamper=chunkextensionsmuggle

# Unicode bypass for pattern-matching WAFs
python sqlmap.py -r request.req --tamper=unicodenormalize

# Scientific notation bypass (ptswarm technique)
python sqlmap.py -r request.req --tamper=scientificnotation

# Junk chars + line breaks for regex WAFs
python sqlmap.py -r request.req --tamper=junkchars,linebreaks

# Token breaker for WAF tokenizers
python sqlmap.py -r request.req --tamper=tokenbreaker

# Auto-detect WAF and apply specific tampers dynamically
python sqlmap.py -r request.req --waf-bypass=auto

# Force specific WAF bypass (applies tampers immediately)
python sqlmap.py -r request.req --waf-bypass=cloudflare
python sqlmap.py -r request.req --waf-bypass=modsecurity
python sqlmap.py -r request.req --waf-bypass=f5

# Combined with chunked encoding
python sqlmap.py -r request.req --waf-bypass=auto --chunked
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
