# -*- coding: utf-8 -*- vim:fileencoding=utf-8:
# vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab

# Copyright (C) 2010-2014 GRNET S.A.
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

import nxpy as np
from ncclient import manager
from ncclient.transport.errors import AuthenticationError, SSHError
from lxml import etree as ET
from django.conf import settings
import logging
from django.core.cache import cache
import os
from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
from portrange import parse_portrange

from ncclient.operations.rpc import RPCError

cwd = os.getcwd()


LOG_FILENAME = os.path.join(settings.LOG_FILE_LOCATION, 'celery_jobs.log')

# FORMAT = '%(asctime)s %(levelname)s: %(message)s'
# logging.basicConfig(format=FORMAT)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(LOG_FILENAME)
handler.setFormatter(formatter)
logger.addHandler(handler)


def fod_unknown_host_cb(host, fingerprint):
    return True


class Retriever(object):
    def __init__(self, device=settings.NETCONF_DEVICE, username=settings.NETCONF_USER, password=settings.NETCONF_PASS, filter=settings.ROUTES_FILTER, port=settings.NETCONF_PORT, route_name=None, xml=None):
        self.device = device
        self.username = username
        self.password = password
        self.port = port
        self.filter = filter
        self.xml = xml
        if route_name:
            self.filter = settings.ROUTE_FILTER%route_name

    def fetch_xml(self):
        with manager.connect(host=self.device, port=self.port, username=self.username, password=self.password, hostkey_verify=False) as m:
            xmlconfig = m.get_config(source='running', filter=('subtree',self.filter)).data_xml
        return xmlconfig

    def proccess_xml(self):
        if self.xml:
            xmlconfig = self.xml
        else:
            xmlconfig = self.fetch_xml()
            logger.info("proxy::retriever(): fetched xmlconfig"+str(xmlconfig))
        parser = np.Parser()
        parser.confile = xmlconfig
        device = parser.export()
        return device

    def fetch_device(self):
        device = cache.get("device")
        logger.info("[CACHE] hit! got device")
        if device:
            return device
        else:
            device = self.proccess_xml()
            if device.routing_options:
                cache.set("device", device, 3600)
                logger.info("[CACHE] miss, setting device")
                return device
            else:
                return False


class Applier(object):
    def __init__(self, route_objects=[], rule_object=None, device=settings.NETCONF_DEVICE, username=settings.NETCONF_USER, password=settings.NETCONF_PASS, port=settings.NETCONF_PORT):
        self.rule_object = rule_object
        self.route_objects = route_objects
        self.device = device
        self.username = username
        self.password = password
        self.port = port

    def to_xml(self, operation=None):
        logger.info("proxy::to_xml(): Operation: %s"%operation)
        if self.rule_object:
            try:
                settings.PORTRANGE_LIMIT
            except:
                settings.PORTRANGE_LIMIT = 100

            if len(self.route_objects)==0:
              logger.info("proxy::to_xml(): route_objects is empty, returning False");
              return False

            logger.info("proxy::to_xml(): Generating XML config")
            rule_obj = self.rule_object
            device = np.Device()
            flow = np.Flow()
            #route = np.Route()
            #flow.routes.append(route)
            device.routing_options.append(flow)
            #route.name = rule_obj.name
            if operation == "delete":
                logger.info("proxy::to_xml(): Requesting a delete operation")
                logger.info("proxy::to_xml(): route_objects="+str(self.route_objects))
              
                for route_obj in self.route_objects:
                  route = np.Route()
                  #route.name = rule_obj.name
                  route.name = route_obj.name
                  flow.routes.append(route)
                  route.operation = operation

                logger.info("proxy::to_xml(): delete: routing_options="+str(device.routing_options))
                logger.info("proxy::to_xml(): delete: routing_options.export()="+str(device.routing_options[0].export()))
                device = device.export(netconf_config=True)
                result = ET.tostring(device)
                logger.info("proxy::to_xml(): (delete) result="+str(result))
                #return ET.tostring(device)
                return result
            # TODO convert to multiple Routes
            # rule.routes is a list of Routes

            count1=0
            for route_obj in self.route_objects:
              count1=count1+1

              route = np.Route()
              #route.name = rule_obj.name
              route.name = route_obj.name
              flow.routes.append(route)

              if route_obj.source:
                  route.match['source'].append(route_obj.source)
              if route_obj.destination:
                  route.match['destination'].append(route_obj.destination)
              try:
                  if route_obj.protocol:
                      for protocol in route_obj.protocol.all():
                          route.match['protocol'].append(protocol.protocol)
              except:
                  pass
              try:
                  ports = []
                  if route_obj.port:
                      portrange = str(route_obj.port)
                      for port in portrange.split(","):
                          route.match['port'].append(port)
              except:
                  pass
              try:
                  ports = []
                  if route_obj.destinationport:
                      portrange = str(route_obj.destinationport)
                      for port in portrange.split(","):
                          route.match['destination-port'].append(port)
              except:
                  pass
              try:
                  if route_obj.sourceport:
                      portrange = str(route_obj.sourceport)
                      for port in portrange.split(","):
                          route.match['source-port'].append(port)
              except:
                  pass
              if route_obj.icmpcode:
                  route.match['icmp-code'].append(route_obj.icmpcode)
              if route_obj.icmptype:
                  route.match['icmp-type'].append(route_obj.icmptype)
              if route_obj.tcpflag:
                  route.match['tcp-flags'].append(route_obj.tcpflag)
              try:
                  if route_obj.dscp:
                      for dscp in route_obj.dscp.all():
                          route.match['dscp'].append(dscp.dscp)
              except:
                  pass

              try:
                  if route_obj.fragmenttype:
                      for frag in route_obj.fragmenttype.all():
                          route.match['fragment'].append(frag.fragmenttype)
              except:
                  pass

              for thenaction in rule_obj.then.all():
                  if thenaction.action_value:
                      route.then[thenaction.action] = thenaction.action_value
                  else:
                      route.then[thenaction.action] = True

              if operation == "replace":
                  logger.info("proxy::to_xml(): Requesting a replace operation")
                  route.operation = operation

            #if count1==0: # TODO
              #route.match['None'] = ['']
              #route.match = ''

            device = device.export(netconf_config=True)
            result = ET.tostring(device)
            logger.info("proxy::to_xml(): result="+str(result))
            return result
        else:
            logger.info("proxy::to_xml(): returning False")
            return False

#####

    def get_delete_routes_config_by_names(self, name_list):
        if name_list != None:
            logger.info("proxy::get_delete_routes_config_by_names(): Generating XML config")
            device = np.Device()
            flow = np.Flow()
            for name in name_list:
                route = np.Route()
                flow.routes.append(route)
                route.name = name
                route.operation = 'delete'
            device.routing_options.append(flow)
            device = device.export(netconf_config=True)
            #return ET.tostring(device)
            config = ET.tostring(device)
            logger.info("proxy::get_delete_routes_config_by_names(): return config="+str(config))
            return config
        else:
            logger.info("proxy::get_delete_routes_config_by_names(): return False")
            return False

    def delete_routes(self):
        if self.route_objects:
            logger.info("proxy::delete_routes(): Generating XML config")
            name_list = [route.name for route in self.route_objects]
            config = self.get_delete_routes_config_by_names(name_list)
            return config
        else:
            logger.info("proxy::delete_routes(): return False")
            return False

    def delete_routes_by_names__immediately(self, name_list):
        config = self.get_delete_routes_config_by_names(name_list)
        if config:
            logger.info("proxy::delete_routes_by_names(): return config="+str(config))
            commit, response = self.apply(configuration=config)
            return True
        else:
            logger.info("proxy::delete_routes_by_names(): return False")
            return False
    
####

    def get_existing_config_xml(self):
        retriever0 = Retriever(xml=None)
        config_xml_running = retriever0.fetch_xml()
        logger.info("proxy::get_existing_config(): config_xml_running="+str(config_xml_running))
        return config_xml_running

    def get_existing_config(self):
        retriever0 = Retriever(xml=None)
        config_parsed = retriever0.proccess_xml()
        logger.info("proxy::get_existing_config(): config_parsed="+str(config_parsed))
        return config_parsed

    def get_existing_routes(self):
        config_parsed = self.get_existing_config()
        if config_parsed.routing_options and config_parsed.routing_options.__len__()>0:
          flow = config_parsed.routing_options[0]
          logger.info("proxy::get_existing_routes(): config_parsed.flow="+str(flow))
          routes_existing = flow.routes
          logger.info("proxy::get_existing_routes(): config_parsed.flow.routes="+str(routes_existing))
          return routes_existing
        else:
          logger.info("proxy::get_existing_routes(): no routing_options or is empty")
          return []

    def get_existing_route_names(self):
      routes_existing = self.get_existing_routes()
      route_ids_existing = [route.name for route in routes_existing]
      logger.info("proxy::get_existing_route_names(): config_parsed.flow.routes.ids="+str(route_ids_existing))
      return route_ids_existing

####

    def apply(self, configuration = None, operation=None):
        reason = None
        if not configuration:
            configuration = self.to_xml(operation=operation)
            logger.info("proxy::apply(): configuration="+str(configuration))

        #self.get_existing_route_names()

        edit_is_successful = False
        commit_confirmed_is_successful = False
        commit_is_successful = False
        if configuration:
            with manager.connect(host=self.device, port=self.port, username=self.username, password=self.password, hostkey_verify=False) as m:
                assert(":candidate" in m.server_capabilities)
                with m.locked(target='candidate'):
                    m.discard_changes()
#                    try:
#                      config = m.get_config(source='candidate', filter=None)
#                      logger.info("proxy::apply(): get_config="+str(config))
#                    except Exception as e:
#                        logger.error("proxy::apply(): get_config: Caught edit exception1: ", exc_info=True)                        
#                        #cause = "Caught edit exception: %s %s (e.class=)" % (e, reason)
#                        cause = "proxy::apply(): get_config: Caught edit exception: %s %s (e.class=%s)" % (e, "", str(type(e)))
#                        cause = cause.replace('\n', '')
#                        logger.error("proxy::apply(): get_config: "+str(cause))

                    try:
                        edit_response = m.edit_config(target='candidate', config=configuration, test_option='test-then-set')
                        edit_is_successful, reason = is_successful(edit_response)
                        logger.info("Successfully edited @ %s" % self.device)
                        if not edit_is_successful:
                            raise Exception()
                    except SoftTimeLimitExceeded:
                        cause="Task timeout"
                        logger.error(cause)
                        return False, cause
                    except TimeLimitExceeded:
                        cause="Task timeout"
                        logger.error(cause)
                        return False, cause
                    #except ncclient.operations.rpc.RPCError as e:
                    except RPCError as e:
                        logger.error("proxy::apply(): RPCError")
                        #cause = "Caught edit RPCError: %s reason=%s (e.class=)" % (e, reason)
                        #logger.error(cause)
                        #cause = "Caught edit RPCError: %s reason=%s (dir=%s)" % (e, reason, str(dir(e)))
                        #logger.error(cause)
                        cause = "Caught edit RPCError: %s reason=%s message=%s" % (e, reason, str(e.message))
                        #logger.error(cause)
                        #cause = "Caught edit RPCError: %s reason=%s (dir=%s, info=%s)" % (e, reason, str(dir(e)), str(e.info)) # 
                        #logger.error(cause)
                        #cause = "Caught edit RPCError: %s reason=%s (dir=%s, tag=%s)" % (e, reason, str(dir(e)), str(e.tag)) # 
                        #logger.error(cause)
                        #cause = "Caught edit RPCError: %s reason=%s (dir=%s, severity=%s)" % (e, reason, str(dir(e)), str(e.severity)) # 
                        cause = cause.replace('\n', '')
                        logger.error("proxy::apply(): "+str(cause))
                        if "statement not found: route " in str(e.message):
                          cause = "Ignoring: "+cause
                          logger.error("proxy::apply(): not calling discard_changes")
                          edit_is_successful = True
                          #return True, cause
                        else:
                          logger.error("proxy::apply(): calling discard_changes, to revert changes")
                          m.discard_changes()
                          return False, cause
                    except Exception as e:
                        #cause = "Caught edit exception: %s %s (e.class=)" % (e, reason)
                        cause = "Caught edit exception: %s %s (e.class=%s)" % (e, reason, str(type(e)))
                        cause = cause.replace('\n', '')
                        logger.error("proxy::apply(): "+str(cause))
                        m.discard_changes()
                        return False, cause
                    if edit_is_successful:
                        try:
                            commit_confirmed_response = m.commit(confirmed=True, timeout=settings.COMMIT_CONFIRMED_TIMEOUT)
                            commit_confirmed_is_successful, reason = is_successful(commit_confirmed_response)

                            if not commit_confirmed_is_successful:
                                raise Exception()
                            else:
                                logger.info("proxy::apply(): Successfully confirmed committed @ %s" % self.device)
                                if not settings.COMMIT:
                                    return True, "Successfully confirmed committed"
                        except SoftTimeLimitExceeded:
                            cause="Task timeout"
                            logger.error("proxy::apply(): "+str(cause))
                            return False, cause
                        except TimeLimitExceeded:
                            cause="Task timeout"
                            logger.error("proxy::apply(): "+str(cause))
                            return False, cause
                        except Exception as e:
                            cause="Caught commit confirmed exception: %s %s" %(e,reason)
                            cause=cause.replace('\n', '')
                            logger.error("proxy::apply(): "+str(cause))
                            return False, cause

                        if settings.COMMIT:
                            if edit_is_successful and commit_confirmed_is_successful:
                                try:
                                    commit_response = m.commit(confirmed=False)
                                    commit_is_successful, reason = is_successful(commit_response)
                                    logger.info("Successfully committed @ %s" % self.device)
                                    newconfig = m.get_config(source='running', filter=('subtree',settings.ROUTES_FILTER)).data_xml
                                    retrieve = Retriever(xml=newconfig)
                                    logger.info("[CACHE] caching device configuration")
                                    cache.set("device", retrieve.proccess_xml(), 3600)

                                    if not commit_is_successful:
                                        raise Exception()
                                    else:
                                        logger.info("Successfully cached device configuration")
                                        return True, "Successfully committed"
                                except SoftTimeLimitExceeded:
                                    cause="Task timeout"
                                    logger.error(cause)
                                    return False, cause
                                except TimeLimitExceeded:
                                    cause="Task timeout"
                                    logger.error(cause)
                                    return False, cause
                                except Exception as e:
                                    cause="Caught commit exception: %s %s" %(e,reason)
                                    cause=cause.replace('\n', '')
                                    logger.error(cause)
                                    return False, cause
        else:
            return False, "No configuration was supplied"


def is_successful(response):
    logger.info("is_successful(): response="+str(response))
    from StringIO import StringIO
    doc = parsexml_(StringIO(response))
    rootNode = doc.getroot()
    success_list = rootNode.xpath("//*[local-name()='ok']")
    if len(success_list) > 0:
        logger.info("is_successful(): return True")
        return True, None
    else:
        reason_return = ''
        reason_list = rootNode.xpath("//*[local-name()='error-message']")
        for reason in reason_list:
            reason_return = '%s %s' % (reason_return, reason.text)
        logger.info("is_successful(): return False return="+str(reason_return))
        return False, reason_return


def parsexml_(*args, **kwargs):
    if 'parser' not in kwargs:
        kwargs['parser'] = ET.ETCompatXMLParser()
    doc = ET.parse(*args, **kwargs)
    return doc
