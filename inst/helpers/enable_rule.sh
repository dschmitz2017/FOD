#!/bin/bash

source_prefix="$1"
shift 1
[ -n "$source_prefix" ] || source_prefix="127.0.0.1/32"

destination_prefix="$1"
shift 1
[ -n "$destination_prefix" ] || destination_prefix="0.0.0.0/0"

#

IPprotocolId="$1" #arg
shift 1
[ -n "$IPprotocolId" ] || IPprotocolId="1"

#

enablex="$1"
shift 1
[ -n "$enablex" ] || enablex="1"

#

appliername="$1"
shift 1
[ -n "$appliername" ] || appliername="admin"

#

name_prefix="testrtr1"

#

echo "$0: args: $source_prefix $destination_prefix $IPprotocolId $enablex $appliername"

#

{ cat /dev/fd/5 | ./pythonenv ./manage.py shell; } 5<<EOF
from flowspec.models import *
from django.contrib.auth.models import User; 
applier1 = User.objects.get(username__exact='$appliername');

from django.db.models import Q
query = Q()
query |= Q(source='$source_prefix', destination='$destination_prefix', protocol__in=[$IPprotocolId])
matching_routes = Route.objects.filter(query)

from copy import copy

if len(matching_routes)!=0:
  print("test rule $name_prefix already exists")
  print("matching_routes="+str(matching_routes))
  a = matching_routes[0]
  a0=copy(a)
else:
  a = Route(name='$name_prefix', source='$source_prefix', destination='$destination_prefix', status='INACTIVE', applier=applier1)
  a.save();
  a.protocol.set([$IPprotocolId])
  a.save();
  a0=copy(a)

from flowspec.tasks import edit, deactivate_route
if $enablex:
  a.status="ACTIVE"
  a.save()
  edit(a.id, a0)
else:
  a.status="PENDING"
  a.save()
  deactivate_route(a.id)

EOF

#

echo "SELECT * from route;" | ./pythonenv ./manage.py dbshell | grep "$name_prefix.*$source_prefix.*$destination_prefix.*$IPprotocolId"

