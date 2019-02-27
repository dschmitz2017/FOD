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
import time

from flowspec.models import Route
from flowspec.models import Rule
from flowspec.junos import create_junos_name

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

def lock_history_file(wait=1):
    first=1
    success=0
    while first or wait:
      first=0
      try:
          dirname=settings.SNMP_TEMP_FILE+".lock"
          os.mkdir(dirname) # TODO use regular file than dir
          logger.info("lock_history_file(): creating lock dir succeeded")
          success=1
          return success
      except OSError, e:
          logger.error("lock_history_file(): creating lock dir "+str(dirname)+" failed: OSError: "+str(e))
          success=0
      except Exception as e:
          #logger.error("lock_history_file(): lock already exists")
          logger.error("lock_history_file(): creating lock dir "+str(dirname)+" failed: "+str(e))
          success=0
      if not success and wait:
        time.sleep(1)
    return success;

def unlock_history_file():
    try:
      dirname=settings.SNMP_TEMP_FILE+".lock"
      os.rmdir(dirname) # TODO use regular file than dir
      logger.info("unlock_history_file(): succeeded")
      return 1
    except Exception as e:
      logger.info("unlock_history_file(): failed "+str(e))
      return 0

def load_history():
    history = {}
    try:
        with open(settings.SNMP_TEMP_FILE, "r") as f:
            history = json.load(f)
        f.close()
    except:
        logger.info("There is no file with SNMP historical data.")
        pass
    return history

# TODO: need locking for ro access?
def get_last_msrm_delay_time():
  last_msrm_delay_time = ""
  try:
    history = load_history()
    last_msrm_delay_time = history['_last_msrm_delay_time']
  except Exception as e:
    logger.info("get_last_msrm_delay_time(): got exception: "+str(e))
  return last_msrm_delay_time

def save_history(history, nowstr):
  try:
    # store updated history
    tf = settings.SNMP_TEMP_FILE + "." + nowstr
    with open(tf, "w") as f:
      json.dump(history, f)
    os.rename(tf, settings.SNMP_TEMP_FILE)
  except:
    logger.info("save_history(): got exception: ", exc_info=True)

def helper_stats_store_parse_ts(ts_string):
  try:
    ts = datetime.strptime(ts_string, '%Y-%m-%dT%H:%M:%S.%f')
  except Exception as e:
    logger.info("helper_stats_store_parse_ts(): ts_string="+str(ts_string)+": got exception "+str(e))
    ts = None
  return ts

def helper_rule_ts_parse(ts_string):
  try:
    ts = datetime.strptime(ts_string, '%Y-%m-%d %H:%M:%S+00:00') # TODO TZ offset assumed to be 00:00
  except ValueError as e:
    #logger.info("helper_rule_ts_parse(): trying with milli seconds fmt")
    try:
      ts = datetime.strptime(ts_string, '%Y-%m-%d %H:%M:%S.%f+00:00') # TODO TZ offset assumed to be 00:00
    except Exception as e:
      logger.info("helper_rule_ts_parse(): ts_string="+str(ts_string)+": got exception "+str(type(e))+": "+str(e))
      ts = None
  except Exception as e:
    logger.info("helper_rule_ts_parse(): ts_string="+str(ts_string)+": got exception "+str(type(e))+": "+str(e))
    ts = None

  #logger.info("helper_rule_ts_parse(): => ts="+str(ts))
  return ts

def process_new_snmp_measurements__low_level(nowstr, samplecount, newdata, history):
        # proper update history
        for rule in newdata:
            counter = {"ts": nowstr, "value": newdata[rule]}
            if rule in history:
                history[rule].insert(0, counter)
                history[rule] = history[rule][:samplecount]
            else:
                history[rule] = [counter]

# can be used for low level and per rule data, but for per rule data it is not used at the moment
def postprocess_history__remove_old_rules(now, history, settings_SNMP_REMOVE_RULES_AFTER):
        # check for old rules and remove them
        toremove = []
        for rule in history:
          try:
            if len(rule)>0 and rule[0]!='_':
              #ts = datetime.strptime(history[rule][0]["ts"], '%Y-%m-%dT%H:%M:%S.%f')
              ts = helper_stats_store_parse_ts(history[rule][0]["ts"])
              if ts!=None and (now - ts).total_seconds() >= settings_SNMP_REMOVE_RULES_AFTER:
                  toremove.append(rule)
          except Exception as e:
            logger.info("postprocess_history__remove_old_rules(): old rules remove loop: rule="+str(rule)+" got exception "+str(e))
        for rule in toremove:
            history.pop(rule, None)

def postprocess_history_final_zero__low_level(nowstr, samplecount, last_poll_no_time, history, null_measurement):
          # for now workaround for low-level rules (by match params, not FoD rule id) no longer have data, typically because of haveing been deactivated
          for rule in history:
            if len(rule)>0 and rule[0]!='_':
              ts = history[rule][0]["ts"]
              if ts!=nowstr and ts==last_poll_no_time:
                counter = {"ts": nowstr, "value": null_measurement }
                history[rule].insert(0, counter)
                history[rule] = history[rule][:samplecount]

def process_history_get_new_value_of_rule(ruleobj, newdata, zero_measurement):
      #flowspec_params_str=create_junos_name(routeobj)
      #new_data_value = newdata[flowspec_params_str] # old case with single route = rule

      new_data_value_per_route__hash = {}
      new_data_value = zero_measurement.copy()
      #rule_routes = ruleobj.routes.all()
      rule_routes = ruleobj.get_routes_nondeleted
      for routeobj in rule_routes:
        flowspec_params_str=create_junos_name(routeobj)
        logger.info("process_history_get_new_value_of_rule(): rule_id="+str(ruleobj.id)+" routeobj="+str(routeobj)+" => flowspec_params_str="+str(flowspec_params_str))
        new_data_value_of_route = newdata[flowspec_params_str]
        new_data_value_per_route__hash[str(routeobj.id)]=new_data_value_of_route
        logger.info("process_history_get_new_value_of_rule(): rule_id="+str(ruleobj.id)+" routeobj="+str(routeobj)+" => new_data_value_of_route="+str(new_data_value_of_route))
        for key in new_data_value_of_route:
          if not key in new_data_value:
            new_data_value[key] = 0
          new_data_value[key] = new_data_value[key] + new_data_value_of_route[key]
      #logger.info("process_history_new_data_per_rule(): rule_id="+str(ruleobj.id)+" => new_data_value="+str(new_data_value))
      #logger.info("process_history_new_data_per_rule(): rule_id="+str(ruleobj.id)+" => new_data_value_per_route__hash="+str(new_data_value_per_route__hash))
      return (new_data_value, new_data_value_per_route__hash)

# is used for history_per_rule and history_per_route actually:
def process_history_calc_final_value_of_rule_or_route(is_rule_or_route, history_per_rule, rule_id, rule_status, rule_last_updated, counter, counter_is_null, counter_null, counter_zero, samplecount):
      if is_rule_or_route: # just used for debugging
        debug_str = "rule_id="+str(rule_id)
      else:
        debug_str = "route_id="+str(rule_id)

      try:
          if not rule_id in history_per_rule:
            if rule_status!="ACTIVE":
              logger.info("process_history_calc_final_value_of_rule_or_route(): "+debug_str+" case notexisting inactive")
              #history_per_rule[rule_id] = [counter]
            else:
              logger.info("process_history_calc_final_value_of_rule_or_route(): "+debug_str+" case notexisting active")
              if counter_is_null:
                history_per_rule[rule_id] = [counter_zero]
              else:
                history_per_rule[rule_id] = [counter, counter_zero]
          else:
            rec = history_per_rule[rule_id]
            if rule_status!="ACTIVE":
              logger.info("process_history_calc_final_value_of_rule_or_route(): "+debug_str+" case existing inactive")
              rec.insert(0, counter)
            else:
              last_value = rec[0]
              null_measurement=counter_null['value']
              last_is_null = last_value==None or last_value['value'] == null_measurement
              if last_value==None:
                rule_newer_than_last = true
              else:
                last_ts = helper_stats_store_parse_ts(last_value['ts'])
                rule_newer_than_last = last_ts==None or rule_last_updated > last_ts
              logger.info("process_history_calc_final_value_of_rule_or_route(): "+debug_str+" last_updated="+str(rule_last_updated)+", last_value="+str(last_value))
              if last_is_null and rule_newer_than_last:
                logger.info("process_history_calc_final_value_of_rule_or_route(): "+debug_str+" case existing active 11")
                if counter_is_null:
                  rec.insert(0, counter_zero)
                else:
                  rec.insert(0, counter_zero)
                  rec.insert(0, counter)
              elif last_is_null and not rule_newer_than_last:
                logger.info("process_history_calc_final_value_of_rule_or_route(): "+debug_str+" case existing active 10")
                rec.insert(0, counter_zero)
                rec.insert(0, counter)
              elif not last_is_null and rule_newer_than_last:
                logger.info("process_history_calc_final_value_of_rule_or_route(): "+debug_str+" case existing active 01")
                if counter_is_null:
                  rec.insert(0, counter_null)
                  rec.insert(0, counter_zero)
                else:
                  rec.insert(0, counter_null)
                  rec.insert(0, counter_zero)
                  rec.insert(0, counter)
              elif not last_is_null and not rule_newer_than_last:
                  logger.info("process_history_calc_final_value_of_rule_or_route(): "+debug_str+" case existing active 00")
                  rec.insert(0, counter)

            history_per_rule[rule_id] = rec[:samplecount]
      except Exception as e:
          logger.info("process_history_calc_final_value_of_rule_or_route(): "+debug_str+" got exception: "+str(e), exc_info=True)


def process_history_new_data_per_rule(nowstr, samplecount, newdata, history_per_route, history_per_rule, null_measurement, null_measurement_missing, zero_measurement):
    #queryset = Route.objects.all()
    queryset = Rule.objects.all()
    for ruleobj in queryset:
      rule_id = str(ruleobj.id)
      rule_status = str(ruleobj.status)
      #logger.info("snmpstats: ruleobj="+str(ruleobj))
      #logger.info("snmpstats: ruleobj.type="+str(type(ruleobj)))
      #logger.info("snmpstats: ruleobj.id="+str(rule_id))
      #logger.info("snmpstats: ruleobj.status="+rule_status)

      rule_last_updated = helper_rule_ts_parse(str(ruleobj.last_updated))
      counter_null = {"ts": rule_last_updated.isoformat(), "value": null_measurement }
      counter_zero = {"ts": rule_last_updated.isoformat(), "value": zero_measurement }

      new_data_value_per_route__hash = {}
      if rule_status=="ACTIVE":
        try:
          (new_data_value, new_data_value_per_route__hash) = process_history_get_new_value_of_rule(ruleobj, newdata, zero_measurement)
          logger.info("process_history_new_data_per_rule(): rule_id="+str(rule_id)+" => new_data_value="+str(new_data_value))
          #logger.info("process_history_new_data_per_rule(): rule_id="+str(rule_id)+" => new_data_value_per_route__hash="+str(new_data_value_per_route__hash))

          counter = {"ts": nowstr, "value": new_data_value}
          counter_is_null = False
        except Exception as e:
          logger.info("process_history_new_data_per_rule(): exception: rule_id="+str(rule_id)+" : "+str(e), exc_info=True)
          counter = {"ts": nowstr, "value": null_measurement_missing }
          counter_is_null = True
      else:
        counter = {"ts": nowstr, "value": null_measurement }
        counter_is_null = True

      process_history_calc_final_value_of_rule_or_route(True, history_per_rule, rule_id, rule_status, rule_last_updated, counter, counter_is_null, counter_null, counter_zero, samplecount)

      for route_id in new_data_value_per_route__hash:
        #logger.info("debug iter new_data_value_per_route__hash "+str(route_id)+", val="+str(new_data_value_per_route__hash[route_id]))
        if not counter_is_null:
          counter = {"ts": nowstr, "value": new_data_value_per_route__hash[route_id]}
          process_history_calc_final_value_of_rule_or_route(False, history_per_route, route_id, rule_status, rule_last_updated, counter, counter_is_null, counter_null, counter_zero, samplecount)

def poll_snmp_statistics():
    logger.info("poll_snmp_statistics(): Polling SNMP statistics.")

    # first, determine current ts, before calling get_snmp_stats
    now = datetime.now()
    nowstr = now.isoformat()

    # get new data
    try:
      logger.info("poll_snmp_statistics(): snmpstats: nowstr="+str(nowstr))
      newdata = get_snmp_stats()
    except Exception as e:
      logger.info("poll_snmp_statistics(): get_snmp_stats failed: "+str(e))
      return False
    
    logger.info("poll_snmp_statistics(): proper Polling SNMP statistics done, now updating history.")

    ###

    # lock history file access
    success = lock_history_file(1)
    if not success: 
      logger.error("poll_snmp_statistics(): locking history file failed, aborting");
      return False

    # load history
    history = load_history()
    
    now2 = datetime.now()
    msrm_delay_time = now2 - now

    zero_measurement = { "bytes" : 0, "packets" : 0 }
    null_measurement = 0 
    null_measurement_missing = 1

    try:
      last_poll_no_time = history['_last_poll_no_time']
    except Exception as e:
      logger.info("poll_snmp_statistics(): got exception while trying to access history[_last_poll_time]: "+str(e))
      last_poll_no_time=None

    logger.info("poll_snmp_statistics(): snmpstats: msrm_delay_time="+str(msrm_delay_time))
    logger.info("poll_snmp_statistics(): snmpstats: last_poll_no_time="+str(last_poll_no_time))
    history['_last_poll_no_time']=nowstr
    history['_last_msrm_delay_time']=str(msrm_delay_time)
          
    samplecount = settings.SNMP_MAX_SAMPLECOUNT

    # do actual updating of history data
    try:
        logger.info("poll_snmp_statistics(): before updating history: nowstr="+str(nowstr)+", last_poll_no_time="+str(last_poll_no_time))
        #newdata = get_snmp_stats()

        process_new_snmp_measurements__low_level(nowstr, samplecount, newdata, history)
        postprocess_history__remove_old_rules(now, history, settings.SNMP_REMOVE_RULES_AFTER)

        if settings.STATISTICS_PER_MATCHACTION_ADD_FINAL_ZERO == True:
          postprocess_history_final_zero__low_level(nowstr, samplecount, last_poll_no_time, history, null_measurement)

        if settings.STATISTICS_PER_RULE == True:
          try:
            history_per_route = history['_per_route']
          except Exception as e:
            history_per_route = {}
          try:
            history_per_rule = history['_per_rule']
          except Exception as e:
            history_per_rule = {}

          process_history_new_data_per_rule(nowstr, samplecount, newdata, history_per_route, history_per_rule, null_measurement, null_measurement_missing, zero_measurement)
          #postprocess_history__remove_old_rules(now, history_per_route, settings.SNMP_REMOVE_RULES_AFTER)
          #postprocess_history__remove_old_rules(now, history_per_rule, settings.SNMP_REMOVE_RULES_AFTER)

          history['_per_route'] = history_per_route
          history['_per_rule'] = history_per_rule 

        # store updated history
        save_history(history, nowstr)
        logger.info("poll_snmp_statistics(): Updating finished.")

    except Exception as e:
        logger.error("poll_snmp_statistics(): Updating failed. exception: "+str(e), exc_info=True)
        
    unlock_history_file()
    logger.info("poll_snmp_statistics(): Polling and Updating end: last_poll_no_time="+str(last_poll_no_time))

def add_initial_zero_value(rule_id, zero_or_null=True):
    logger.info("add_initial_zero_value(): rule_id="+str(rule_id))

    # get new data
    now = datetime.now()
    nowstr = now.isoformat()

    # lock history file access
    success = lock_history_file(1)
    if not success: 
      logger.error("add_initial_zero_value(): locking history file failed, aborting");
      return False

    # load history
    history = load_history()

    try:
      history_per_rule = history['_per_rule']
    except Exception as e:
      history_per_rule = {}


    if zero_or_null:
      zero_measurement = { "bytes" : 0, "packets" : 0 }
    else:
      zero_measurement = 0
    
    counter = {"ts": nowstr, "value": zero_measurement }
        
    samplecount = settings.SNMP_MAX_SAMPLECOUNT

    try:
        if rule_id in history_per_rule:
              rec = history_per_rule[rule_id]
              last_rec = rec[0]
              if last_rec==None or (zero_or_null and last_rec['value']==0) or ((not zero_or_null) and last_rec['value']!=0):
                rec.insert(0, counter)
                history_per_rule[rule_id] = rec[:samplecount]
        else:
              if zero_or_null:
                history_per_rule[rule_id] = [counter]

        history['_per_rule'] = history_per_rule

        # store updated history
        save_history(history, nowstr)

    except Exception as e:
        logger.info("add_initial_zero_value(): failure: exception: "+str(e), exc_info=True)

    unlock_history_file()

