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

from utils import proxy as PR
from celery.task import task
from celery.task.sets import subtask
import logging
import json
from celery.task.http import *
import beanstalkc
from django.conf import settings
import datetime
from django.core.mail import send_mail
from django.template.loader import render_to_string
import os
from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
from ipaddr import *
from os import fork,_exit
from sys import exit
import time

LOG_FILENAME = os.path.join(settings.LOG_FILE_LOCATION, 'celery_jobs.log')


# FORMAT = '%(asctime)s %(levelname)s: %(message)s'
# logging.basicConfig(format=FORMAT)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(LOG_FILENAME)
handler.setFormatter(formatter)
logger.addHandler(handler)


@task(ignore_result=True)
def add(route, callback=None):
    try:
        applier = PR.Applier(route_object=route)
        commit, response = applier.apply()
        if commit:
            status = "ACTIVE"
        else:
            status = "ERROR"
        route.status = status
        route.response = response
        route.save()
        announce("[%s] Rule add: %s - Result: %s" % (route.applier, route.name, response), route.applier, route)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        announce("[%s] Rule add: %s - Result: %s" % (route.applier, route.name, route.response), route.applier, route)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        announce("[%s] Rule add: %s - Result: %s" % (route.applier, route.name, route.response), route.applier, route)
    except Exception:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        announce("[%s] Rule add: %s - Result: %s" % (route.applier, route.name, route.response), route.applier, route)


@task(ignore_result=True)
def edit(route, callback=None):
    try:
        applier = PR.Applier(route_object=route)
        commit, response = applier.apply(operation="replace")
        if commit:
            status = "ACTIVE"
            #try:
            #  snmp_add_initial_zero_value.delay(str(route.id), True)
            #except Exception as e:
            #  logger.error("edit(): route="+str(route)+", ACTIVE, add_initial_zero_value failed: "+str(e))
        else:
            status = "ERROR"
        route.status = status
        route.response = response
        route.save()
        announce("[%s] Rule edit: %s - Result: %s" % (route.applier, route.name, response), route.applier, route)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        announce("[%s] Rule edit: %s - Result: %s" % (route.applier, route.name, route.response), route.applier, route)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        announce("[%s] Rule edit: %s - Result: %s" % (route.applier, route.name, route.response), route.applier, route)
    except Exception:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        announce("[%s] Rule edit: %s - Result: %s" % (route.applier, route.name, route.response), route.applier, route)


@task(ignore_result=True)
def delete(route, **kwargs):
    try:
        applier = PR.Applier(route_object=route)
        commit, response = applier.apply(operation="delete")
        reason_text = ''
        if commit:
            status = "INACTIVE"
            if "reason" in kwargs and kwargs['reason'] == 'EXPIRED':
                status = 'EXPIRED'
                reason_text = " Reason: %s " % status
            #try:
            #  snmp_add_initial_zero_value.delay(str(route.id), False)
            #except Exception as e:
            #  logger.error("edit(): route="+str(route)+", INACTIVE, add_null_value failed: "+str(e))
        else:
            status = "ERROR"
        route.status = status
        route.response = response
        route.save()
        announce("[%s] Suspending rule : %s%s- Result %s" % (route.applier, route.name, reason_text, response), route.applier, route)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        announce("[%s] Suspending rule : %s - Result: %s" % (route.applier, route.name, route.response), route.applier, route)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        announce("[%s] Suspending rule : %s - Result: %s" % (route.applier, route.name, route.response), route.applier, route)
    except Exception:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        announce("[%s] Suspending rule : %s - Result: %s" % (route.applier, route.name, route.response), route.applier, route)


# May not work in the first place... proxy is not aware of Route models
@task
def batch_delete(routes, **kwargs):
    if routes:
        for route in routes:
            route.status = 'PENDING';route.save()
        applier = PR.Applier(route_objects=routes)
        conf = applier.delete_routes()
        commit, response = applier.apply(configuration=conf)
        reason_text = ''
        if commit:
            status = "INACTIVE"
            if "reason" in kwargs and kwargs['reason'] == 'EXPIRED':
                status = 'EXPIRED'
                reason_text = " Reason: %s " % status
            elif "reason" in kwargs and kwargs['reason'] != 'EXPIRED':
                status = kwargs['reason']
                reason_text = " Reason: %s " % status
        else:
            status = "ERROR"
        for route in routes:
            route.status = status
            route.response = response
            route.expires = datetime.date.today()
            route.save()
            announce("[%s] Rule removal: %s%s- Result %s" % (route.applier, route.name, reason_text, response), route.applier, route)
    else:
        return False


#@task(ignore_result=True)
def announce(messg, user, route):
    peers = user.get_profile().peers.all()
    username = None
    for peer in peers:
        if username:
            break
        for network in peer.networks.all():
            net = IPNetwork(network)
            if IPNetwork(route.destination) in net:
                username = peer.peer_tag
                break
    messg = str(messg)
    b = beanstalkc.Connection()
    b.use(settings.POLLS_TUBE)
    tube_message = json.dumps({'message': messg, 'username': username})
    b.put(tube_message)
    b.close()


@task
def check_sync(route_name=None, selected_routes=[]):
    from flowspec.models import Route, MatchPort, MatchDscp, ThenAction
    if not selected_routes:
        routes = Route.objects.all()
    else:
        routes = selected_routes
    if route_name:
        routes = routes.filter(name=route_name)
    for route in routes:
        if route.has_expired() and (route.status != 'EXPIRED' and route.status != 'ADMININACTIVE' and route.status != 'INACTIVE'):
            if route.status != 'ERROR':
                logger.info('Expiring %s route %s' %(route.status, route.name))
                subtask(delete).delay(route, reason="EXPIRED")
        else:
            if route.status != 'EXPIRED':
                route.check_sync()


@task(ignore_result=True)
def notify_expired():
    from flowspec.models import *
    from django.contrib.sites.models import Site
    logger.info('Initializing expiration notification')
    routes = Route.objects.all()
    for route in routes:
        if route.status not in ['EXPIRED', 'ADMININACTIVE', 'INACTIVE', 'ERROR']:
            expiration_days = (route.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                try:
                    fqdn = Site.objects.get_current().domain
                    admin_url = "https://%s%s" % \
                    (fqdn,
                     "/edit/%s"%route.name)
                    mail_body = render_to_string("rule_action.txt",
                                             {"route": route, 'expiration_days':expiration_days, 'action':'expires', 'url':admin_url})
                    days_num = ' days'
                    expiration_days_text = "%s %s" %('in',expiration_days)
                    if expiration_days == 0:
                        days_num = ' today'
                        expiration_days_text = ''
                    if expiration_days == 1:
                        days_num = ' day'
                    logger.info('Route %s expires %s%s. Notifying %s (%s)' %(route.name, expiration_days_text, days_num, route.applier.username, route.applier.email))
                    send_mail(settings.EMAIL_SUBJECT_PREFIX + "Rule %s expires %s%s" %
                              (route.name,expiration_days_text, days_num),
                              mail_body, settings.SERVER_EMAIL,
                              [route.applier.email])
                except Exception as e:
                    logger.info("Exception: %s"%e)
                    pass
    logger.info('Expiration notification process finished')

##############################################################################
##############################################################################
# snmp task handling (including helper functions)

import os
import signal

def handleSIGCHLD(signal, frame):
  logger.info("handleSIGCHLD(): reaping childs")
  os.waitpid(-1, os.WNOHANG)

def snmp_lock_create(wait=0):
    first=1
    success=0
    while first or wait:
      first=0
      try:
          os.mkdir(settings.SNMP_POLL_LOCK)
          logger.error("snmp_lock_create(): creating lock dir succeeded")
          success=1
          return success
      except OSError, e:
          logger.error("snmp_lock_create(): creating lock dir failed: OSError: "+str(e))
          success=0
      except Exception as e:
          logger.error("snmp_lock_create(): Lock already exists")
          logger.error("snmp_lock_create(): creating lock dir failed: "+str(e))
          success=0
      if not success and wait:
        time.sleep(1)
    return success;

def snmp_lock_remove():
    try:
      os.rmdir(settings.SNMP_POLL_LOCK)
    except Exception as e:
      logger.info("snmp_lock_remove(): failed "+str(e))

def exit_process():
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+")")
      exit()
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+"), after exit")
      sys.exit()
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+"), after sys.exit")
      os._exit()
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+"), after os._exit")

#@task(ignore_result=True, time_limit=580, soft_time_limit=550)
@task(ignore_result=True, max_retries=0)
def poll_snmp_statistics():
    from flowspec import snmpstats

    if not snmp_lock_create(0):
      return

    signal.signal(signal.SIGCHLD, handleSIGCHLD)

    pid = os.getpid()
    logger.info("poll_snmp_statistics(): before fork (pid="+str(pid)+")")
    npid = os.fork()
    if npid == -1:
      pass
    elif npid > 0:
      logger.info("poll_snmp_statistics(): returning in parent process (pid="+str(pid)+", npid="+str(npid)+")")
    else:
      logger.info("poll_snmp_statistics(): in child process (pid="+str(pid)+", npid="+str(npid)+")")
      try:
        snmpstats.poll_snmp_statistics()        
      except e:
        logger.error("poll_snmp_statistics(): exception occured in snmp poll (pid="+str(pid)+", npid="+str(npid)+"): "+str(e))
      snmp_lock_remove()
      #exit_process()
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+")")
      exit()
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+"), after exit")
      sys.exit()
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+"), after sys.exit")
      os._exit()
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+"), after os._exit")

@task(ignore_result=True, max_retries=0)
def snmp_add_initial_zero_value(rule_id, zero_or_null=True):
    from flowspec import snmpstats

    signal.signal(signal.SIGCHLD, handleSIGCHLD)

    pid = os.getpid()
    logger.info("snmp_add_initial_zero_value(): before fork (pid="+str(pid)+")")
    npid = os.fork()
    if npid == -1:
      pass
    elif npid > 0:
      logger.info("snmp_add_initial_zero_value(): returning in parent process (pid="+str(pid)+", npid="+str(npid)+")")
    else:
      logger.info("snmp_add_initial_zero_value(): in child process (pid="+str(pid)+", npid="+str(npid)+")")

      if snmp_lock_create(1):
        try:
          snmpstats.add_initial_zero_value(rule_id, zero_or_null)
          logger.info("snmp_add_initial_zero_value(): rule_id="+str(rule_id)+" sucesss")
        except Exception as e:
          logger.error("snmp_add_initial_zero_value(): rule_id="+str(rule_id)+" failed: "+str(e))
        snmp_lock_remove()

      #exit_process()
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+")")
      exit()
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+"), after exit")
      sys.exit()
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+"), after sys.exit")
      os._exit()
      logger.info("exit_process(): before exit in child process (pid="+str(pid)+", npid="+str(npid)+"), after os._exit")


