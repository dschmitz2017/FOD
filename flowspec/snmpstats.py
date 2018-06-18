# -*- coding: utf-8 -*- vim:fileencoding=utf-8:
# vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab

# Copyright (C) 2017 CESNET, a.l.e.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import logging
from pysnmp.hlapi.asyncore import *
from django.conf import settings
from datetime import datetime, timedelta
import json
import os

logger = logging.getLogger(__name__)
identoffset = len(settings.SNMP_CNTPACKETS) + 1

# Wait for responses or errors, submit GETNEXT requests for further OIDs
# noinspection PyUnusedLocal,PyUnusedLocal
def snmpCallback(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBindTable, cbCtx):
    (authData, transportTarget, results) = cbCtx

    # debug - which router replies:
    #print('%s via %s' % (authData, transportTarget))

    # CNTPACKETS and CNTBYTES are of the same length
    if errorIndication:
        logger.error('Bad errorIndication.')
        return 0
    elif errorStatus:
        logger.error('Bad errorStatus.')
        return 0
    for varBindRow in varBindTable:
        for name, val in varBindRow:
            name = str(name)
            if name.startswith(settings.SNMP_CNTPACKETS):
                counter = "packets"
            elif name.startswith(settings.SNMP_CNTBYTES):
                counter = "bytes"
            else:
                logger.info('Finished {}.'.format(transportTarget))
                return 0

            ident = name[identoffset:]
            ordvals = [int(i) for i in ident.split(".")]
            # the first byte is length of table name string
            len1 = ordvals[0] + 1
            tablename = "".join([chr(i) for i in ordvals[1:len1]])
            if tablename in settings.SNMP_RULESFILTER:
                # if the current route belongs to specified table from SNMP_RULESFILTER list,
                # take the route identifier
                len2 = ordvals[len1] + 1
                routename = "".join([chr(i) for i in ordvals[len1 + 1:len1 + len2]])

                # add value into dict
                if routename in results:
                    if counter in results[routename]:
                        results[routename][counter] = results[routename][counter] + int(val)
                    else:
                        results[routename][counter] = int(val)
                else:
                    results[routename] = {counter: int(val)}
                logger.debug("%s %s %s %s = %s" %(transportTarget, counter, tablename, routename, int(val)))

    return 1  # continue table retrieval


def get_snmp_stats():
    """Return dict() of the sum of counters (bytes, packets) from all selected routes, where
    route identifier is the key in dict.  The sum is counted over all routers.

    Example output with one rule: {'77.72.72.1,0/0,proto=1': {'bytes': 13892216, 'packets': 165387}}

    This function uses SNMP_IP list, SNMP_COMMUNITY, SNMP_CNTPACKETS and
    SNMP_RULESFILTER list, all defined in settings."""

    if not isinstance(settings.SNMP_IP, list):
        settings.SNMP_IP = [settings.SNMP_IP]

    results = {}
    targets = []
    # prepare cmdlist
    for ip in settings.SNMP_IP:
        # get values of counters using SNMP
        if isinstance(ip, dict):
            if "port" in ip:
                port = ip["port"]
            else:
                port = 161

            if "community" in ip:
                community = ip["community"]
            else:
                community = settings.SNMP_COMMUNITY
            ip = ip["ip"]
        elif isinstance(ip, str):
            port = 161
            community = settings.SNMP_COMMUNITY
        else:
            raise Exception("Bad configuration of SNMP, SNMP_IP should be a list of dict or a list of str.")

        targets.append((CommunityData(community), UdpTransportTarget((ip, port), timeout=15, retries=1),
                        (ObjectType(ObjectIdentity(settings.SNMP_CNTPACKETS)),
                         #ObjectType(ObjectIdentity(settings.SNMP_CNTBYTES))
                         )))

    snmpEngine = SnmpEngine()

    # Submit initial GETNEXT requests and wait for responses
    for authData, transportTarget, varBinds in targets:
        bulkCmd(snmpEngine, authData, transportTarget, ContextData(), 0, 50,
                *varBinds, **dict(cbFun=snmpCallback, cbCtx=(authData, transportTarget.transportAddr, results)))

    snmpEngine.transportDispatcher.runDispatcher()

    return results

def poll_snmp_statistics():
    logger.info("Polling SNMP statistics.")

    # load history
    history = {}
    try:
        with open(settings.SNMP_TEMP_FILE, "r") as f:
            history = json.load(f)
    except:
        logger.info("There is no file with SNMP historical data.")
        pass

    # get new data
    now = datetime.now()
    nowstr = now.isoformat()
    try:
      last_poll_no_time = history['_last_poll_no_time']
    except Exception as e:
      logger.info("got exception while trying to access history[_last_poll_time]: "+str(e))
      last_poll_no_time=None
      
    try:
        logger.info("snmpstats: nowstr="+str(nowstr)+", last_poll_no_time="+str(last_poll_no_time))
        newdata = get_snmp_stats()

        # update history
        samplecount = settings.SNMP_MAX_SAMPLECOUNT
        for rule in newdata:
            counter = {"ts": nowstr, "value": newdata[rule]}
            if rule in history:
                history[rule].insert(0, counter)
                history[rule] = history[rule][:samplecount]
            else:
                history[rule] = [counter]

        # check for old rules and remove them
        toremove = []
        for rule in history:
          if rule!='_last_poll_no_time':
            ts = datetime.strptime(history[rule][0]["ts"], '%Y-%m-%dT%H:%M:%S.%f')
            if (now - ts).total_seconds() >= settings.SNMP_REMOVE_RULES_AFTER:
                toremove.append(rule)
        for rule in toremove:
            history.pop(rule, None)

        # for now workaround for low-level rules (by match params, not FoD rule id) no longer have data, typically because of haveing been deactivated
        for rule in history:
          if rule!='_last_poll_no_time':
            ts = history[rule][0]["ts"]
            if ts!=nowstr and ts==last_poll_no_time:
              counter = {"ts": nowstr, "value": 0}
              history[rule].insert(0, counter)
              history[rule] = history[rule][:samplecount]

        history['_last_poll_no_time']=nowstr

        # store updated history
        tf = settings.SNMP_TEMP_FILE + "." + nowstr
        with open(tf, "w") as f:
            json.dump(history, f)
        os.rename(tf, settings.SNMP_TEMP_FILE)
        logger.info("Polling finished.")
    except Exception as e:
        logger.error(e)
        logger.error("Polling failed.")
    logger.info("Polling end: last_poll_no_time="+str(last_poll_no_time))

