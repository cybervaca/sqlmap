# Changelog - WAF Bypass Enhancements

## Author: CyberVaca, Luis Vacas de Santos
## Twitter: https://twitter.com/CyberVaca_
## Date: 2026-02-24

---

## [1.0.0] - 2026-02-26 - CyberVaca mod

Primera versión del mod con numeración propia. Basado en sqlmap 1.10.2.17.

* Versión: CyberVaca mod. 1.0.0#dev
* Ver doc/CHANGELOG.md para resumen completo

---

## [2.7.0] - 2026-02-24 - Ghauri-like Oracle

### Ghauri-like Behavior for Oracle Time-based

Cuando sqlmap usa payloads de estilo Ghauri (Oracle + DBMS_PIPE.RECEIVE_MESSAGE), se comporta como Ghauri:

- **Prioridad Ghauri**: Si se detecta Oracle time-based con heavy query (bloqueado por F5 WAF en extracción), sqlmap cambia automáticamente al payload Ghauri `'||DBMS_PIPE.RECEIVE_MESSAGE(...)||'` para la extracción.
- **Formato de payload**: Usa `prefix='||` y `suffix=||'` igual que Ghauri.
- **Preservar valor original**: Con marcador custom (`login=aaaaa*`), el payload queda `aaaaa'||DBMS_PIPE.RECEIVE_MESSAGE(...)||'` en lugar de reemplazar todo el valor.
- **Fallback**: Si el payload Ghauri falla, vuelve automáticamente al heavy query de sqlmap.

**Archivos:**
- `lib/core/common.py` – initTechnique(): cambia a Ghauri cuando Oracle + time-based
- `lib/controller/checks.py` – origValue en boundPayload para custom marker; checkFalsePositives
- `lib/request/inject.py` – fallback Oracle en getValue()
- `data/xml/boundaries.xml` – boundary Ghauri (`'||`/`||'`) level=0
- `data/xml/payloads/time_blind.xml` – tests Ghauri level=0

---

## [2.6.0] - 2026-02-24

### Version Branding

- **CyberVaca mod. 1.0.0#dev** - Version string now displays in banner, `--version` and User-Agent

### Ghauri Payloads for All DBMS

**time_blind.xml - MySQL:**
- `(SELECT(0)FROM(SELECT(SLEEP([SLEEPTIME])))v)` - Pre-WHERE/string context, WAF bypass
- `if(now()=sysdate(),SLEEP([SLEEPTIME]),0)` - Alternate when IF/SLEEP filtered
- `(SELECT CASE WHEN(1=1) THEN SLEEP([SLEEPTIME]) ELSE 0 END)` - CASE variant

**time_blind.xml - Oracle:**
- `DBMS_LOCK.SLEEP([SLEEPTIME])` - String context (Ghauri style)
- `USER_LOCK.SLEEP([SLEEPTIME])` - Alternative when DBMS_LOCK unavailable

**stacked_queries.xml - MySQL:**
- `;(SELECT(1)FROM(SELECT(SLEEP([SLEEPTIME])))a)` - Ghauri stacked query style

### Technical

- PostgreSQL, MSSQL: Existing payloads cover Ghauri techniques
- Reference: https://github.com/r0oth3x49/ghauri

---

## [2.5.0] - 2026-02-25 - Oversizedrequest Configurable Size

### Enhancement

**oversizedrequest.py** - Configurable oversize parameter

- New option `--tamper-data=oversizedrequest.size=20M` to pass tamper parameters
- Fallback: `SQLMAP_OVERSIZEDREQUEST_SIZE` environment variable
- Supports suffixes: K (1024), M (1024²), G (1024³), case-insensitive
- Default: 8200 bytes. Max: 64MB
- Invalid values fall back to default with a warning

**Usage:**
```bash
# Default 8200 bytes (Cloudflare, AWS, Google Cloud Armor)
python sqlmap.py -r request.req --tamper=oversizedrequest

# Custom size via --tamper-data (preferred)
python sqlmap.py -r request.req --tamper=oversizedrequest --tamper-data=oversizedrequest.size=20M

# Or via environment variable
SQLMAP_OVERSIZEDREQUEST_SIZE=128K python sqlmap.py -r request.req --tamper=oversizedrequest
```

---

## [2.4.0] - 2026-02-25 - Oracle Ghauri Techniques

### New Tamper Scripts (based on Ghauri)

**oraclechr.py** - Converts string literals to CHR() concatenation
- `'test'` → `CHR(116)||CHR(101)||CHR(115)||CHR(116)`
- Effective against signature-based WAFs

**oraclectxsys.py** - Uses CTXSYS.DRITHSX.SN for boolean-based bypass
- Converts `THEN 1 ELSE 0 END` to `THEN NULL ELSE CTXSYS.DRITHSX.SN(1,0568) END`
- Uses Oracle error for true/false differentiation

**oraclebetween.py** - Oracle-specific BETWEEN for extraction
- Replaces `)>N` with `) NOT BETWEEN 0 AND N` for DUAL/SUBSTRC payloads
- When WAF blocks greater-than operator

### New Payloads

**time_blind.xml** - USER_LOCK.SLEEP for Oracle
- Alternative when DBMS_LOCK.SLEEP not available
- Ghauri technique for Oracle E-Business Suite

### WAF Mapping

- F5: Added oraclebetween to default tampers for Oracle+F5 scenarios

**Usage (Oracle + F5 WAF):**
```bash
sqlmap -r request.req --dbms=oracle --tamper=oraclebetween,oraclechr,oraclectxsys,between --dbs
```

**Reference:** https://github.com/r0oth3x49/ghauri

---

## [2.2.0] - 2026-02-24 - Oversized Request Fix

### Bug Fix

**oversizedrequest.py** - Fixed junk data placement

**Problem:**
- Junk was being prepended to the payload parameter, not the HTTP body
- WAF could still inspect the actual payload

**Solution:**
- Now uses `HINT.PREPEND` mechanism to add junk at the START of HTTP body
- WAF sees 8KB of junk first, potentially exceeding inspection limit
- Payload remains in its original position, unmodified

---

## [2.1.0] - 2026-02-24 - Cloudflare 403 Bypass

### New Tamper Script

**cloudflarebypas.py** - Bypasses Cloudflare 403 for time-based blind SQLi

**Technique:**
- Original payload blocked: `(select(0)from(select(sleep(10)))v)` → 403
- Bypass: Repeat payload with comments and escape sequences
- `payload/*'+payload+'\"+payload`

**How it works:**
- Comments `/*'` break WAF regex patterns
- Escaped quotes `\'` and `\"` confuse the parser
- Triple repetition makes the pattern unrecognizable

**Usage:**
```bash
sqlmap -r request.req --tamper=cloudflarebypas
# Or automatically with:
sqlmap -r request.req --waf-bypass=cloudflare
```

---

## [2.0.0] - 2026-02-24 - Smart WAF Detection

### Major Refactor

The `--waf-bypass` option now uses **smart WAF detection** instead of cumulative levels.

**Why this change:**
- Previous system loaded 16+ tampers at level 3 (sqlmap warning: "using too many tamper scripts")
- New system applies **maximum 4 tampers** optimized for each specific WAF
- Uses sqlmap's identYwaf detection (`kb.identifiedWafs`) for auto mode

### New Usage:
```bash
# Auto-detect WAF and apply optimal tampers (max 3-4)
sqlmap -r request.req --waf-bypass=auto

# Force specific WAF bypass
sqlmap -r request.req --waf-bypass=cloudflare
sqlmap -r request.req --waf-bypass=modsecurity
sqlmap -r request.req --waf-bypass=aws
```

### Supported WAFs:
| Category | WAFs |
|----------|------|
| Cloud | cloudflare, aws, google, azure, akamai |
| Commercial | modsecurity, imperva, f5, fortinet, sucuri, barracuda, citrix |
| Other | wordfence, comodo, wallarm, reblaze, radware, sophos, paloalto |

### Removed (non-SQLi):
- `pathobfuscation.py` - For LFI/Access Control, not SQLi
- `uninitializedvars.py` - For OS Command Injection, not SQLi

---

## [1.0.0] - 2026-02-24

### Added

#### New Tamper Scripts (7)

1. **oversizedrequest.py**
   - Bypasses WAF body size inspection limits by prepending large junk data
   - Targets: Cloudflare (~8KB), AWS WAF (8KB), Google Cloud Armor (8KB), Azure Front Door (128KB), Sucuri (1.25MB), Fortinet (64MB)
   - Reference: https://www.blackhillsinfosec.com/bypassing-wafs-using-oversized-requests/

2. **scientificnotation.py**
   - Uses scientific notation (e notation) to bypass WAF pattern matching
   - Converts `' OR '1'='1` to `' OR 1337.e('')='1` which bypasses most WAFs
   - Targets: Cloudflare, AWS WAF, ModSecurity CRS, Nginx WAF
   - Reference: @ptswarm technique, GoSecure MySQL scientific notation research

3. **chunkextensionsmuggle.py**
   - Exploits HTTP desync via malformed chunk extensions
   - Targets: Proxies with inconsistent chunk extension parsing
   - Reference: https://www.imperva.com/blog/smuggling-requests-with-chunked-extensions-a-new-http-desync-trick/

4. **parampollutionfull.py**
   - Advanced HTTP Parameter Pollution (HPP)
   - Includes variants for PHP, ASP.NET, and JSP backends
   - Targets: WAFs that only inspect first/last parameter occurrence

5. **contenttypeconfusion.py**
   - Manipulates Content-Type header to bypass WAF inspection
   - Includes EBCDIC charset confusion and null byte injection
   - Targets: WAFs with Content-Type specific rules

6. **unicodenormalize.py**
   - Converts SQL keywords to Unicode Fullwidth characters
   - Includes homoglyph and combining character variants
   - Targets: WAFs without Unicode normalization
   - Example: SELECT → ＳＥＬＥＣＴ

7. **multipartboundary.py**
   - Manipulates multipart/form-data boundaries
   - Techniques: long boundaries, special chars, nested multipart
   - Targets: WAFs with strict multipart parsing

8. **slowrequest.py**
   - Marks requests for slow/delayed transmission
   - "Low and slow" attack technique for timing-based evasion
   - Targets: WAFs with behavioral/timing analysis

9. **junkchars.py**
   - Adds junk characters (+-+-1-+-+, !#$%&) to confuse regex-based WAFs
   - Wraps SQL keywords with noise characters
   - Reference: HackenProof WAF Bypass Cheat Sheet

10. **linebreaks.py**
    - Uses CR/LF (%0D%0A) to break WAF regex patterns
    - Inserts line breaks before SQL keywords
    - Reference: HackenProof WAF Bypass Cheat Sheet

11. **tokenbreaker.py**
    - Uses token breaker techniques to confuse WAF tokenizers
    - Adds uncontexted brackets, semicolons to break parsing
    - Reference: HackenProof WAF Bypass Cheat Sheet

12. **tabsandlinefeeds.py**
    - Uses tabs (%09) and vertical tabs (%0B) instead of spaces
    - Breaks regex expecting whitespace characters
    - Reference: HackenProof WAF Bypass Cheat Sheet

13. **methodoverride.py**
    - Uses HTTP method override headers (X-HTTP-Method-Override, X-Method-Override)
    - Bypasses WAFs that only inspect GET/POST requests
    - Supports PUT, PATCH, DELETE method spoofing
    - Includes WebSocket upgrade header technique

14. **doubleencode.py**
    - Double URL encodes payload (%25XX format)
    - Bypasses WAFs that only decode once
    - Example: space -> %20 -> %2520
    - Includes triple encoding and mixed encoding variants

#### New CLI Option

- **--waf-bypass=LEVEL** (1-5)
  - Automatically applies tamper scripts based on aggressiveness level
  - Level 1: Basic encoding (randomcase, space2comment, between)
  - Level 2: + Oversized requests, header manipulation
  - Level 3: + Parameter pollution, advanced obfuscation
  - Level 4: + Content-Type confusion, Unicode normalization
  - Level 5: + HTTP smuggling, all techniques combined

#### New Utility Module

- **lib/utils/wafbypass.py**
  - Centralized WAF bypass level management
  - WAF-specific tamper recommendations (Cloudflare, AWS, ModSecurity, etc.)
  - Helper functions for automatic tamper selection

### Enhanced

#### tamper/xforwardedfor.py
- Added 30+ new evasion headers:
  - Cloudflare: CF-RAY, CF-IPCountry
  - Akamai: Akamai-Origin-Hop
  - AWS: X-Forwarded-Host, X-Forwarded-Proto
  - Internal bypass: X-Original-URL, X-Rewrite-URL
  - Method override: X-HTTP-Method-Override
  - Debug headers: X-Debug, X-Debug-Token
  - IPv6 support: X-Forwarded-For-IPv6

#### lib/core/common.py - chunkSplitPostData()
- Added `aggressive` mode with 1-3 byte chunks
- Added `use_extensions` for random chunk extensions
- New function: `chunkSplitPostDataAggressive()`
- New function: `chunkSplitPostDataDesync()` for HTTP smuggling

### Technical Details

#### Oversized Request Bypass
Many WAFs have body size limits for inspection:
```
Cloudflare (free): ~8KB
AWS WAF (ALB): 8KB
Google Cloud Armor: 8KB
Azure Front Door: 128KB
ModSecurity: Configurable (ProcessPartial)
Sucuri: 1.25MB
Fortinet: 64MB
```

Requests exceeding these limits may bypass inspection entirely.

#### HTTP Desync via Chunk Extensions
Exploits RFC 9112 Section 7.1.1 parsing differences:
- Bare semicolons without extension names
- Malformed extensions causing front-end/back-end disagreement
- Potential for request smuggling attacks

#### Unicode Normalization Bypass
WAFs often don't normalize Unicode before pattern matching:
- Fullwidth characters: U+FF00-U+FFEF
- Cyrillic homoglyphs
- Zero-width combining characters

### References

- Black Hills InfoSec - Oversized Request Bypass
- Imperva - HTTP Desync via Chunk Extensions
- Bypassing WAFs in 2025 - Modern Evasion Techniques
- Ghauri - Alternative SQLi tool techniques

---

## Usage Examples

```bash
# Basic WAF bypass (level 1)
python sqlmap.py -r request.req --waf-bypass=1

# Moderate bypass for Cloudflare/AWS (level 2)
python sqlmap.py -r request.req --waf-bypass=2

# Aggressive bypass (level 3)
python sqlmap.py -r request.req --waf-bypass=3

# Advanced bypass with Unicode (level 4)
python sqlmap.py -r request.req --waf-bypass=4

# Maximum evasion (level 5)
python sqlmap.py -r request.req --waf-bypass=5

# Individual tamper scripts
python sqlmap.py -r request.req --tamper=oversizedrequest
python sqlmap.py -r request.req --tamper=oversizedrequest,xforwardedfor,randomcase

# Combined with chunked encoding
python sqlmap.py -r request.req --chunked --tamper=chunkextensionsmuggle
```

---

## Files Changed

### New Files
- `tamper/oversizedrequest.py`
- `tamper/chunkextensionsmuggle.py`
- `tamper/parampollutionfull.py`
- `tamper/contenttypeconfusion.py`
- `tamper/unicodenormalize.py`
- `tamper/multipartboundary.py`
- `tamper/slowrequest.py`
- `lib/utils/wafbypass.py`
- `CHANGELOG_WAF_BYPASS.md`

### Modified Files
- `tamper/xforwardedfor.py`
- `lib/core/common.py`
- `lib/core/option.py`
- `lib/core/optiondict.py`
- `lib/parse/cmdline.py`
- `README.md`
