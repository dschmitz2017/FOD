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

from pysnmp.hlapi import *
import json
from pysnmp.entity.rfc3413.oneliner import cmdgen
from django.conf import settings


def getSNMPData(ip, port, comm, obj):
    cmdGen = cmdgen.CommandGenerator()
    cmd = cmdGen.bulkCmd
    errorIndication, errorStatus, errorIndex, varBindTable = cmd(
        cmdgen.CommunityData(comm),
        cmdgen.UdpTransportTarget((ip, port)), 1, 10,
        obj
    )
    if errorIndication:
        print("error", str(errorIndication))
    else:
        if errorStatus:
            print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBindTable[-1][int(errorIndex)-1] or '?'
                )
            )
        else:
            vars = []
            for varBindTableRow in varBindTable:
                for name, val in varBindTableRow:
                    vars.append((name, val))
            return vars
    return []

def get_snmp_stats():
    """Return dict() of the sum of counters per each selected routes, where
    route identifier is the key in dict.  The sum is counted over all routers.

    This function uses SNMP_IP list, SNMP_COMMUNITY, SNMP_CNTPACKETS and
    SNMP_RULESFILTER list, all defined in settings."""
    results = {}
    identoffset = len(settings.SNMP_CNTPACKETS) + 1
    if not isinstance(settings.SNMP_IP, list):
        settings.SNMP_IP = [settings.SNMP_IP]

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

        data = getSNMPData(ip, port, community, settings.SNMP_CNTPACKETS)
        for name, val in data:
            # each oid contains encoded identifier of table and route
            ident = str(name)[identoffset:]
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
                    results[routename] = results[routename] + int(val)
                else:
                    results[routename] = int(val)
    return results

