from __future__ import absolute_import, unicode_literals
import os
#from celery import Celery
from flowspy import settings
import sys

##

print("loading flowspy.celery_preactions", file=sys.stderr)

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'flowspy.settings')

##

print("performing flowspy.celery_preactions", file=sys.stderr)

if hasattr(settings, 'SNMP_POLL_LOCK'):
    SNMP_POLL_LOCK=settings.SNMP_POLL_LOCK
    #print("SNMP_POLL_LOCK="+str(SNMP_POLL_LOCK), file=sys.stderr)
    if SNMP_POLL_LOCK!='' and os.path.exists(SNMP_POLL_LOCK):
      print("trying to remove "+str(SNMP_POLL_LOCK), file=sys.stderr)
      os.rmdir(SNMP_POLL_LOCK)

    SNMP_TEMP_FILE=settings.SNMP_TEMP_FILE
    #print("SNMP_TEMP_FILE="+str(SNMP_TEMP_FILE), file=sys.stderr)
    if SNMP_TEMP_FILE!='' and os.path.exists(SNMP_TEMP_FILE+'.lock'):
      print("trying to remove "+str(SNMP_TEMP_FILE+'.lock'), file=sys.stderr)
      os.rmdir(settings.SNMP_TEMP_FILE+'.lock')

